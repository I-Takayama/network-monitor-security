#ifndef HTTP_HEALTH_H
#define HTTP_HEALTH_H

#include "http_probe.h"

#define HTTP_HEALTH_DISABLED 0
#define HTTP_HEALTH_OK 1
#define HTTP_HEALTH_MISMATCH 2
#define HTTP_HEALTH_TRANSPORT_ERROR 3

/* Compare actual HTTP response with the configured expected HTTP status.
   This is separate from TCP Health and does not diagnose root cause. */
int evaluate_http_health(int enabled, int expected_status,
                         const HttpProbeResult* probe);

#endif
