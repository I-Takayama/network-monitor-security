#include "http_health.h"

int evaluate_http_health(int enabled, int expected_status,
                         const HttpProbeResult* probe) {
    if (!enabled) return HTTP_HEALTH_DISABLED;
    if (probe == 0 || probe->http_status < 100 ||
        probe->http_status > 599) return HTTP_HEALTH_TRANSPORT_ERROR;
    if (expected_status < 100 || expected_status > 599)
        return HTTP_HEALTH_TRANSPORT_ERROR;
    return probe->http_status == expected_status
        ? HTTP_HEALTH_OK : HTTP_HEALTH_MISMATCH;
}
