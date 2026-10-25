#include "http_anomaly.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

void init_http_anomaly_history(HttpAnomalyHistory *history) {
    if (history != NULL) memset(history, 0, sizeof(*history));
}

void detect_http_anomaly(int enabled, int expected_status,
                         const HttpProbeResult *probe,
                         HttpAnomalyHistory *history,
                         HttpAnomalyResult *out) {
    if (history == NULL || out == NULL) return;

    memset(out, 0, sizeof(*out));
    (void)snprintf(out->message, sizeof(out->message), "normal");

    if (!enabled) {
        history->consecutive_abnormal = 0;
        (void)snprintf(out->message, sizeof(out->message), "disabled");
        return;
    }

    int health = evaluate_http_health(enabled, expected_status, probe);
    int bad_transport = (health == HTTP_HEALTH_TRANSPORT_ERROR);
    int bad_status = (health == HTTP_HEALTH_MISMATCH);
    int bad_latency = (!bad_transport && !bad_status && probe != NULL &&
                       probe->response_ms > HTTP_SLOW_THRESHOLD_MS);
    int missing_latency = (!bad_transport && !bad_status && probe != NULL &&
                           probe->response_ms < 0);
    int abnormal = bad_transport || bad_status || bad_latency || missing_latency;

    if (!abnormal) {
        int old_count = history->consecutive_abnormal;
        history->consecutive_abnormal = 0;
        if (old_count > 0) {
            out->anomaly_type = HTTP_ANOMALY_RECOVERED;
            (void)snprintf(out->message, sizeof(out->message),
                           "http recovered after %d abnormal sample(s)", old_count);
        }
        return;
    }

    if (history->consecutive_abnormal < INT_MAX)
        history->consecutive_abnormal++;
    out->consecutive_abnormal = history->consecutive_abnormal;

    if (out->consecutive_abnormal >= HTTP_CONSECUTIVE_THRESHOLD) {
        out->anomaly_type = HTTP_ANOMALY_CONSECUTIVE;
        (void)snprintf(out->message, sizeof(out->message),
                       "http consecutive anomalies: %d", out->consecutive_abnormal);
    } else if (bad_transport || missing_latency) {
        out->anomaly_type = HTTP_ANOMALY_TRANSPORT_ERROR;
        (void)snprintf(out->message, sizeof(out->message),
                       "http response unavailable: error=%d",
                       probe != NULL ? probe->error_code : 0);
    } else if (bad_status) {
        out->anomaly_type = HTTP_ANOMALY_STATUS_MISMATCH;
        (void)snprintf(out->message, sizeof(out->message),
                       "http status mismatch: expected=%d actual=%d",
                       expected_status, probe->http_status);
    } else {
        out->anomaly_type = HTTP_ANOMALY_SLOW_RESPONSE;
        (void)snprintf(out->message, sizeof(out->message),
                       "http slow response: %ld ms (threshold %ld ms)",
                       probe->response_ms, HTTP_SLOW_THRESHOLD_MS);
    }
}
