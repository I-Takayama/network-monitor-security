#ifndef HTTP_ANOMALY_H
#define HTTP_ANOMALY_H

#include "http_health.h"

#define HTTP_ANOMALY_NONE 0
#define HTTP_ANOMALY_STATUS_MISMATCH 1
#define HTTP_ANOMALY_TRANSPORT_ERROR 2
#define HTTP_ANOMALY_SLOW_RESPONSE 3
#define HTTP_ANOMALY_CONSECUTIVE 4
#define HTTP_ANOMALY_RECOVERED 5

#define HTTP_SLOW_THRESHOLD_MS 1000L
#define HTTP_CONSECUTIVE_THRESHOLD 3

/* HTTP history is independent of the existing TCP PortHistory. */
typedef struct {
    int consecutive_abnormal;
} HttpAnomalyHistory;

typedef struct {
    int anomaly_type;
    int consecutive_abnormal;
    char message[160];
} HttpAnomalyResult;

void init_http_anomaly_history(HttpAnomalyHistory *history);

/* One call per HTTP monitoring cycle, in order for each monitored endpoint.
   Priority: 3+ consecutive abnormalities > mismatch/transport > latency.
   Recovery is an event emitted on the first fully normal sample after a fault.
   HTTP_HEALTH_OK describes HTTP status matching; slow responses may still
   have an anomaly, independently of HTTP Health. */
void detect_http_anomaly(int enabled, int expected_status,
                         const HttpProbeResult *probe,
                         HttpAnomalyHistory *history,
                         HttpAnomalyResult *out);

#endif
