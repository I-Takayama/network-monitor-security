#ifndef AUTH_STATUS_H
#define AUTH_STATUS_H
#include <stdint.h>
#include <stddef.h>

typedef struct {
    int available;
    int fresh;
    int invalid;
    unsigned long events;
    unsigned long failures;
    unsigned long source_active;
    unsigned long username_active;
    unsigned long source_alerts;
    unsigned long username_alerts;
    int64_t snapshot_unix_seconds;
    int64_t collection_unix_seconds;
} AuthStatusSummary;

/* Reads only local, normalized data. No IP, username or credential is exported. */
int auth_status_read(const char *path, int64_t now_ms, AuthStatusSummary *out);
/* Collection health is independent of event arrival. A successful poll creates
 * an event-count-only heartbeat file, never containing PII. The caller is
 * responsible for verifying the remote snapshot and committing its checkpoint.
 * Returns -1 for inconsistent/corrupt heartbeat, 0 otherwise.
 */
int auth_status_apply_poll_heartbeat(AuthStatusSummary *s,
    const char *heartbeat_path, int64_t now_ms);
void auth_status_to_json(const AuthStatusSummary *s, char *buf, size_t len);
#endif
