#define _POSIX_C_SOURCE 200809L
#include "auth_status.h"
#include "auth_anomaly.h"
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define AUTH_MAX_SNAPSHOT_BYTES (1024 * 1024)
#define AUTH_FRESHNESS_SECONDS 120

static int bad(AuthStatusSummary *s) {
    s->invalid = 1;
    s->available = 0;
    s->fresh = 0;
    return -1;
}

int auth_status_read(const char *path, int64_t now_ms, AuthStatusSummary *out) {
    if (!path || !out || now_ms < 0) return -1;
    memset(out, 0, sizeof(*out));
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    if (!S_ISREG(st.st_mode) || st.st_size < 0 ||
        st.st_size > AUTH_MAX_SNAPSHOT_BYTES) return bad(out);

    FILE *fp = fopen(path, "r");
    if (!fp) return 0;
    out->snapshot_unix_seconds = (int64_t)st.st_mtime;
    AuthAnomalyTracker *tracker = calloc(1, sizeof(*tracker));
    if (!tracker) { fclose(fp); return bad(out); }
    auth_anomaly_init(tracker);

    char *line = NULL;
    size_t cap = 0;
    ssize_t got;
    size_t consumed = 0;
    int64_t last_ms = -1;
    int ok = 1;
    while ((got = getline(&line, &cap, fp)) != -1) {
        consumed += (size_t)got;
        if (got < 8 || got > 512 || consumed > AUTH_MAX_SNAPSHOT_BYTES ||
            line[got - 1] != '\n') { ok = 0; break; }
        line[got - 1] = '\0';
        if (got > 1 && line[got - 2] == '\r') line[got - 2] = '\0';
        char *save = NULL;
        char *p[4];
        p[0] = strtok_r(line, "\t", &save);
        for (int i = 1; i < 4; i++) p[i] = strtok_r(NULL, "\t", &save);
        if (!p[0] || !p[1] || !p[2] || !p[3] ||
            strtok_r(NULL, "\t", &save)) { ok = 0; break; }
        errno = 0;
        char *end = NULL;
        long long when = strtoll(p[0], &end, 10);
        if (errno || !end || *end || when < 0 || when < last_ms ||
            (strcmp(p[1], "0") && strcmp(p[1], "1"))) { ok = 0; break; }
        AuthAnomalyResult event;
        int rc = auth_anomaly_apply(tracker, (int64_t)when,
                                    p[1][0] - '0', p[2], p[3], &event);
        if (rc != AUTH_OK) { ok = 0; break; }
        last_ms = (int64_t)when;
        out->events++;
        out->failures += (unsigned long)(p[1][0] == '1');
        out->source_alerts += (unsigned long)event.source_alert;
        out->username_alerts += (unsigned long)event.username_alert;
    }
    if (ferror(fp)) ok = 0;
    free(line);
    fclose(fp);
    /* Evaluate expirations against current time, even if no new login occurred. */
    if (ok && (last_ms < 0 || last_ms <= now_ms)) {
        AuthExpiryResult expired;
        if (auth_anomaly_tick(tracker, now_ms, &expired) != AUTH_OK) ok = 0;
    } else if (ok) ok = 0; /* future timestamps: clock skew or corrupted input */
    if (ok) {
        for (int i = 0; i < AUTH_MAX_GROUPS; ++i) {
            out->source_active += (unsigned long)tracker->by_source[i].active;
            out->username_active += (unsigned long)tracker->by_username[i].active;
        }
        int64_t age = now_ms / 1000 - (int64_t)st.st_mtime;
        out->available = 1;
        out->fresh = age >= 0 && age <= AUTH_FRESHNESS_SECONDS;
    }
    free(tracker);
    if (!ok) return bad(out);
    return 0;
}

int auth_status_apply_poll_heartbeat(AuthStatusSummary *s,
    const char *heartbeat_path, int64_t now_ms) {
    if (!s || !heartbeat_path || now_ms < 0) return -1;
    s->fresh = 0; /* Fail closed; never label a missing heartbeat as healthy. */
    s->collection_unix_seconds = 0;
    if (!s->available || s->invalid) return 0;

    struct stat st;
    if (lstat(heartbeat_path, &st) != 0) return 0; /* Missing heartbeat. */
    if (!S_ISREG(st.st_mode) || st.st_size < 2 || st.st_size > 32)
        return bad(s);
    FILE *fp = fopen(heartbeat_path, "r");
    if (!fp) return 0; /* Cannot confirm collection freshness. */
    char line[40] = {0};
    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return bad(s);
    }
    int extra = fgetc(fp);
    int read_error = ferror(fp);
    fclose(fp);
    if (read_error || extra != EOF) return bad(s);
    /* Strict decimal event count followed by newline; no additional metadata. */
    size_t len = strlen(line);
    if (len < 2 || line[len-1] != '\n') return bad(s);
    line[len-1] = '\0';
    for (size_t i = 0; i < len-1; i++)
        if (line[i] < '0' || line[i] > '9') return bad(s);
    errno = 0;
    char *end = NULL;
    unsigned long expected_events = strtoul(line, &end, 10);
    if (errno || !end || *end || expected_events != s->events)
        return bad(s);

    int64_t poll_seconds = (int64_t)st.st_mtime;
    int64_t age = now_ms/1000 - poll_seconds;
    s->collection_unix_seconds = poll_seconds;
    s->fresh = poll_seconds >= s->snapshot_unix_seconds &&
               age >= 0 && age <= AUTH_FRESHNESS_SECONDS;
    return 0;
}

void auth_status_to_json(const AuthStatusSummary *s, char *buf, size_t len) {
    if (!buf || !len) return;
    if (!s) { snprintf(buf, len, "{\"state\":\"unavailable\"}"); return; }
    const char *state = s->invalid ? "invalid" : !s->available ? "unavailable" :
        !s->fresh ? "stale" :
        (s->source_active || s->username_active) ? "alert" : "no_alert";
    snprintf(buf, len,
        "{\"state\":\"%s\",\"events\":%lu,\"failures\":%lu,"
        "\"source_active\":%lu,\"username_active\":%lu,"
        "\"source_alerts_historical\":%lu,\"username_alerts_historical\":%lu,"
        "\"snapshot_unix_seconds\":%lld,\"collection_unix_seconds\":%lld,\"freshness_seconds\":%d}",
        state, s->events, s->failures, s->source_active, s->username_active,
        s->source_alerts, s->username_alerts,
        (long long)s->snapshot_unix_seconds,
        (long long)s->collection_unix_seconds, AUTH_FRESHNESS_SECONDS);
}
