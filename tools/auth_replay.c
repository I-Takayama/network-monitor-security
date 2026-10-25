#define _POSIX_C_SOURCE 200809L
#include "auth_anomaly.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

static int fail(size_t line_no, const char *reason) {
    fprintf(stderr, "AUTH_REPLAY_ERROR=line_%zu_%s\n", line_no, reason);
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fputs("Usage: auth_replay normalized.tsv\n", stderr);
        return 2;
    }

    FILE *fp = fopen(argv[1], "r");
    if (!fp) {
        perror("auth_replay fopen");
        return 2;
    }

    AuthAnomalyTracker *tracker = calloc(1, sizeof(*tracker));
    if (!tracker) {
        fclose(fp);
        return 2;
    }
    auth_anomaly_init(tracker);

    char *line = NULL;
    size_t allocated = 0;
    size_t rows = 0, failures = 0;
    size_t ip_alerts = 0, user_alerts = 0;
    size_t ip_recoveries = 0, user_recoveries = 0;
    int result = 0;
    ssize_t n;

    while ((n = getline(&line, &allocated, fp)) >= 0) {
        rows++;

        if (n == 0 || n > 512) {
            result = fail(rows, "bad_length");
            break;
        }

        line[strcspn(line, "\r\n")] = '\0';

        char *save = NULL;
        char *parts[4];

        parts[0] = strtok_r(line, "\t", &save);
        for (int i = 1; i < 4; ++i) {
            parts[i] = strtok_r(NULL, "\t", &save);
        }

        if (!parts[0] || !parts[1] || !parts[2] || !parts[3] ||
            strtok_r(NULL, "\t", &save)) {
            result = fail(rows, "invalid_columns");
            break;
        }

        errno = 0;
        char *end = NULL;
        long long parsed = strtoll(parts[0], &end, 10);

        if (errno || *end || parsed < 0 || parsed > INT64_MAX) {
            result = fail(rows, "invalid_timestamp");
            break;
        }

        if (strcmp(parts[1], "0") != 0 &&
            strcmp(parts[1], "1") != 0) {
            result = fail(rows, "invalid_outcome");
            break;
        }

        int outcome = parts[1][0] - '0';
        AuthAnomalyResult alert;

        int rc = auth_anomaly_apply(
            tracker,
            (int64_t)parsed,
            outcome,
            parts[2],
            parts[3],
            &alert
        );

        if (rc != AUTH_OK) {
            result = fail(
                rows,
                rc == AUTH_CAPACITY_EXCEEDED
                    ? "capacity_exceeded"
                    : "invalid_event"
            );
            break;
        }

        if (outcome == AUTH_FAILURE) failures++;

        ip_alerts += (size_t)alert.source_alert;
        user_alerts += (size_t)alert.username_alert;
        ip_recoveries += alert.source_recoveries;
        user_recoveries += alert.username_recoveries;
    }

    if (ferror(fp)) {
        perror("auth_replay getline");
        result = 2;
    }

    if (!result) {
        printf(
            "AUTH_ROWS=%zu\n"
            "AUTH_FAILURES=%zu\n"
            "AUTH_SOURCE_ALERTS=%zu\n"
            "AUTH_USER_ALERTS=%zu\n"
            "AUTH_SOURCE_RECOVERIES=%zu\n"
            "AUTH_USER_RECOVERIES=%zu\n",
            rows, failures, ip_alerts, user_alerts,
            ip_recoveries, user_recoveries
        );
        puts("AUTH_REPLAY=PASS");
    }

    free(line);
    free(tracker);
    fclose(fp);
    return result;
}