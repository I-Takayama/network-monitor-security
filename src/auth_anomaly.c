#include "auth_anomaly.h"
#include <string.h>

static size_t bounded_len(const char *s, size_t max) {
    size_t n = 0;
    if (!s) return 0;
    while (n <= max && s[n]) n++;
    return n;
}

static int valid_key(const char *s, size_t max) {
    size_t n = bounded_len(s, max);
    if (n == 0 || n > max) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20 || c == 0x7f) return 0;
    }
    return 1;
}

static AuthFailureGroup *find_group(AuthFailureGroup groups[AUTH_MAX_GROUPS],
                                     const char *key) {
    for (int i = 0; i < AUTH_MAX_GROUPS; ++i) {
        if (groups[i].used && strcmp(groups[i].key, key) == 0)
            return &groups[i];
    }
    return NULL;
}

static AuthFailureGroup *empty_group(AuthFailureGroup groups[AUTH_MAX_GROUPS]) {
    for (int i = 0; i < AUTH_MAX_GROUPS; ++i) {
        if (!groups[i].used) return &groups[i];
    }
    return NULL;
}

static void initialize_group(AuthFailureGroup *group, const char *key) {
    memset(group, 0, sizeof(*group));
    memcpy(group->key, key, strlen(key) + 1);
    group->used = 1;
}

/* Five most recent failures suffice to decide whether 5 failures fall within
 * any trailing 60-second window, regardless of the request rate. */
static size_t expire_groups(AuthFailureGroup groups[AUTH_MAX_GROUPS],
                            int64_t now) {
    size_t recoveries = 0;
    for (int i = 0; i < AUTH_MAX_GROUPS; i++) {
        AuthFailureGroup *g = &groups[i];
        if (!g->used) continue;
        size_t stale = 0;
        while (stale < g->retained &&
               now - g->failures[stale] >= AUTH_WINDOW_MS) stale++;
        if (stale) {
            size_t remaining = g->retained - stale;
            memmove(g->failures, g->failures + stale,
                    remaining * sizeof(g->failures[0]));
            g->retained = remaining;
        }
        if (g->active && g->retained < AUTH_FAILURE_THRESHOLD) {
            g->active = 0;
            recoveries++;
        }
        if (!g->active && g->retained == 0) {
            memset(g, 0, sizeof(*g)); /* reclaim inactive group slot */
        }
    }
    return recoveries;
}

void auth_anomaly_init(AuthAnomalyTracker *tracker) {
    if (!tracker) return;
    memset(tracker, 0, sizeof(*tracker));
    tracker->last_time_ms = -1;
}

int auth_anomaly_tick(AuthAnomalyTracker *tracker, int64_t epoch_ms,
                      AuthExpiryResult *out) {
    if (!tracker || !out || epoch_ms < 0 ||
        (tracker->last_time_ms >= 0 && epoch_ms < tracker->last_time_ms))
        return AUTH_BAD_INPUT;
    *out = (AuthExpiryResult){0};
    out->source_recoveries = expire_groups(tracker->by_source, epoch_ms);
    out->username_recoveries = expire_groups(tracker->by_username, epoch_ms);
    tracker->last_time_ms = epoch_ms;
    return AUTH_OK;
}

static void push_failure(AuthFailureGroup *g, int64_t epoch_ms,
                         int *new_alert) {
    if (g->retained == AUTH_FAILURE_THRESHOLD) {
        memmove(g->failures, g->failures + 1,
                (AUTH_FAILURE_THRESHOLD - 1) * sizeof(g->failures[0]));
        g->retained--;
    }
    g->failures[g->retained++] = epoch_ms;
    if (!g->active && g->retained == AUTH_FAILURE_THRESHOLD) {
        g->active = 1;
        *new_alert = 1;
    }
}

int auth_anomaly_apply(AuthAnomalyTracker *tracker, int64_t epoch_ms,
                       int outcome, const char *source_ip, const char *username,
                       AuthAnomalyResult *out) {
    if (!tracker || !out || epoch_ms < 0 ||
        (outcome != AUTH_SUCCESS && outcome != AUTH_FAILURE) ||
        !valid_key(source_ip, 64) || !valid_key(username, AUTH_MAX_KEY_BYTES) ||
        (tracker->last_time_ms >= 0 && epoch_ms < tracker->last_time_ms))
        return AUTH_BAD_INPUT;

    /* Check group availability after expiring stale groups, before mutation. */
    AuthExpiryResult expiry = {0};
    if (auth_anomaly_tick(tracker, epoch_ms, &expiry) != AUTH_OK)
        return AUTH_BAD_INPUT;
    *out = (AuthAnomalyResult){0};
    out->source_recoveries = expiry.source_recoveries;
    out->username_recoveries = expiry.username_recoveries;

    if (outcome == AUTH_SUCCESS) return AUTH_OK;

    AuthFailureGroup *src = find_group(tracker->by_source, source_ip);
    AuthFailureGroup *usr = find_group(tracker->by_username, username);
    if ((!src && !empty_group(tracker->by_source)) ||
        (!usr && !empty_group(tracker->by_username)))
        return AUTH_CAPACITY_EXCEEDED;
    if (!src) {
        src = empty_group(tracker->by_source);
        initialize_group(src, source_ip);
    }
    if (!usr) {
        usr = empty_group(tracker->by_username);
        initialize_group(usr, username);
    }
    push_failure(src, epoch_ms, &out->source_alert);
    push_failure(usr, epoch_ms, &out->username_alert);
    out->source_active = src->active;
    out->username_active = usr->active;
    out->source_failures = src->retained;
    out->username_failures = usr->retained;
    return AUTH_OK;
}
