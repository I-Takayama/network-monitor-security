#define _POSIX_C_SOURCE 200809L
#include "auth_anomaly.h"
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MAX_INPUT_BYTES (1024 * 1024)
#define MAX_LINE_BYTES 512

static void utc_timestamp(int64_t ms, char out[32]) {
    time_t sec = (time_t)(ms / 1000);
    struct tm utc;
    if (!gmtime_r(&sec, &utc) || !strftime(out, 24, "%Y-%m-%dT%H:%M:%S", &utc)) {
        out[0] = '\0';
        return;
    }
    size_t n = strlen(out);
    snprintf(out + n, 32 - n, ".%03dZ", (int)(ms % 1000));
}

static int parse_line(char *line, int64_t *when, int *outcome,
                      const char **source, const char **username) {
    char *save = NULL;
    char *p[4];
    p[0] = strtok_r(line, "\t", &save);
    for (int i = 1; i < 4; ++i) p[i] = strtok_r(NULL, "\t", &save);
    if (!p[0] || !p[1] || !p[2] || !p[3] || strtok_r(NULL, "\t", &save)) return -1;
    errno = 0;
    char *end = NULL;
    intmax_t v = strtoimax(p[0], &end, 10);
    if (errno || !end || *end || v < 0 || v > INT64_MAX) return -1;
    if (strcmp(p[1], "0") && strcmp(p[1], "1")) return -1;
    *when = (int64_t)v;
    *outcome = p[1][0] - '0';
    *source = p[2];
    *username = p[3];
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fputs("usage: auth_alert_export normalized.tsv new-output.csv\n", stderr);
        return 2;
    }
    struct stat meta;
    if (stat(argv[1], &meta) || !S_ISREG(meta.st_mode) ||
        meta.st_size < 0 || meta.st_size > MAX_INPUT_BYTES) {
        fputs("AUTH_ALERT_EXPORT_ERROR=invalid_input_file\n", stderr);
        return 2;
    }
    FILE *in = fopen(argv[1], "r");
    if (!in) { perror("input"); return 2; }
    umask(077);
    FILE *out = fopen(argv[2], "wx");
    if (!out) { perror("new output"); fclose(in); return 2; }
    AuthAnomalyTracker *t = calloc(1, sizeof(*t));
    if (!t) { fclose(in); fclose(out); unlink(argv[2]); return 2; }
    auth_anomaly_init(t);
    int ok = fprintf(out, "observed_at_utc,transition,source_alerts,username_alerts,source_recoveries,username_recoveries\n") > 0;
    char *line = NULL;
    size_t cap = 0;
    ssize_t got;
    size_t input_bytes = 0, rows = 0, transitions = 0;
    unsigned long source_alerts = 0, user_alerts = 0, source_recoveries = 0, user_recoveries = 0;
    int64_t last = -1;
    while (ok && (got = getline(&line, &cap, in)) != -1) {
        rows++;
        input_bytes += (size_t)got;
        if (got < 8 || got > MAX_LINE_BYTES || input_bytes > MAX_INPUT_BYTES || line[got-1] != '\n') {
            ok = 0; break;
        }
        line[got-1] = '\0';
        if (got > 1 && line[got-2] == '\r') line[got-2] = '\0';
        int64_t when;
        int outcome;
        const char *ip, *user;
        if (parse_line(line, &when, &outcome, &ip, &user) || (last >= 0 && when < last)) {
            ok = 0; break;
        }
        AuthAnomalyResult a;
        if (auth_anomaly_apply(t, when, outcome, ip, user, &a) != AUTH_OK) {
            ok = 0; break;
        }
        last = when;
        source_alerts += (unsigned long)a.source_alert;
        user_alerts += (unsigned long)a.username_alert;
        source_recoveries += (unsigned long)a.source_recoveries;
        user_recoveries += (unsigned long)a.username_recoveries;
        if (a.source_alert || a.username_alert || a.source_recoveries || a.username_recoveries) {
            char stamp[32];
            utc_timestamp(when, stamp);
            if (!stamp[0]) { ok = 0; break; }
            const char *type = (a.source_alert || a.username_alert) &&
                                (a.source_recoveries || a.username_recoveries) ? "mixed" :
                               (a.source_alert || a.username_alert) ? "alert" : "recovery";
            if (fprintf(out, "%s,%s,%d,%d,%zu,%zu\n", stamp, type,
                        a.source_alert, a.username_alert,
                        a.source_recoveries, a.username_recoveries) < 0) {
                ok = 0; break;
            }
            transitions++;
        }
    }
    if (ferror(in) || fflush(out) != 0) ok = 0;
    if (fclose(out) != 0) ok = 0;
    fclose(in);
    free(t);
    free(line);
    if (!ok) {
        unlink(argv[2]);
        fprintf(stderr, "AUTH_ALERT_EXPORT_ERROR=invalid_or_unwritable_row_%zu\n", rows);
        return 1;
    }
    printf("AUTH_INPUT_ROWS=%zu\nAUTH_CSV_TRANSITIONS=%zu\n"
           "AUTH_SOURCE_ALERTS=%lu\nAUTH_USERNAME_ALERTS=%lu\n"
           "AUTH_SOURCE_RECOVERIES=%lu\nAUTH_USERNAME_RECOVERIES=%lu\nAUTH_ALERT_EXPORT=PASS\n",
           rows, transitions, source_alerts, user_alerts, source_recoveries, user_recoveries);
    return 0;
}
