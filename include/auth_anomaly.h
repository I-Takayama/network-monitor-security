#ifndef AUTH_ANOMALY_H
#define AUTH_ANOMALY_H

/* Phase 2: authentication-failure burst detector, independent of TCP/HTTP Health.
 * Input events must be timestamp-ordered (UTC epoch milliseconds). Passwords are
 * neither accepted nor stored. A missing/unreadable log is NOT a healthy state;
 * log retrieval and JSONL validation belong to the ingestion layer (Stage 4).
 */

#include <stddef.h>
#include <stdint.h>

#define AUTH_WINDOW_MS INT64_C(60000)
#define AUTH_FAILURE_THRESHOLD 5
#define AUTH_MAX_GROUPS 64
#define AUTH_MAX_KEY_BYTES 80

#define AUTH_SUCCESS 0
#define AUTH_FAILURE 1
#define AUTH_OK 0
#define AUTH_BAD_INPUT (-1)
#define AUTH_CAPACITY_EXCEEDED (-2)

typedef struct {
    char key[AUTH_MAX_KEY_BYTES + 1];
    int used;
    int active;
    size_t retained;
    int64_t failures[AUTH_FAILURE_THRESHOLD];
} AuthFailureGroup;

typedef struct {
    AuthFailureGroup by_source[AUTH_MAX_GROUPS];
    AuthFailureGroup by_username[AUTH_MAX_GROUPS];
    int64_t last_time_ms;
} AuthAnomalyTracker;

typedef struct {
    int source_alert;          /* 0 -> 1 threshold transition */
    int username_alert;
    int source_active;         /* current, including ongoing alert */
    int username_active;
    size_t source_failures;    /* capped at threshold */
    size_t username_failures;
    size_t source_recoveries;  /* may include OTHER keys that expired */
    size_t username_recoveries;
} AuthAnomalyResult;

typedef struct {
    size_t source_recoveries;
    size_t username_recoveries;
} AuthExpiryResult;

void auth_anomaly_init(AuthAnomalyTracker *tracker);

/* Advance time even without login events. A group is recovered after fewer than
 * five failures remain in the trailing 60 seconds. Does not synthesize logins.
 */
int auth_anomaly_tick(AuthAnomalyTracker *tracker, int64_t epoch_ms,
                      AuthExpiryResult *out);

/* outcome is AUTH_SUCCESS or AUTH_FAILURE. The key fields must be non-empty,
 * bounded, NUL-terminated ASCII/UTF-8 strings. No truncation or silent evictions.
 * On an input error or group-capacity overflow, no login is consumed.
 */
int auth_anomaly_apply(AuthAnomalyTracker *tracker, int64_t epoch_ms,
                       int outcome, const char *source_ip, const char *username,
                       AuthAnomalyResult *out);

#endif
