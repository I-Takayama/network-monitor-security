#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "http_anomaly.h"

static int total = 0;
static int failed = 0;

static HttpProbeResult probe(int status, long elapsed, int code) {
    HttpProbeResult r = {0};
    r.http_status = status;
    r.response_ms = elapsed;
    r.error_code = code;
    r.error_stage = code ? "receive" : "none";
    return r;
}

static void verify(const char *name, int enabled, int expected,
                   const HttpProbeResult *current, HttpAnomalyHistory *history,
                   int want_type, int want_count, const char *message_fragment) {
    HttpAnomalyResult result;
    detect_http_anomaly(enabled, expected, current, history, &result);
    int ok = result.anomaly_type == want_type &&
             result.consecutive_abnormal == want_count &&
             (message_fragment == NULL ||
              strstr(result.message, message_fragment) != NULL);
    total++;
    if (!ok) {
        failed++;
        printf("FAIL %02d %s: type=%d count=%d message=%s\n",
               total, name, result.anomaly_type,
               result.consecutive_abnormal, result.message);
    } else {
        printf("PASS %02d %s\n", total, name);
    }
}

int main(void) {
    HttpAnomalyHistory h;
    init_http_anomaly_history(&h);
    HttpProbeResult ok = probe(200, 10, 0);
    HttpProbeResult at_threshold = probe(200, 1000, 0);
    HttpProbeResult slow = probe(200, 1001, 0);
    HttpProbeResult mismatch_404 = probe(404, 30, 0);
    HttpProbeResult mismatch_500 = probe(500, 40, 0);
    HttpProbeResult transport = probe(0, 50, ECONNREFUSED);
    HttpProbeResult missing_time = probe(200, -1, 0);

    verify("initial normal", 1, 200, &ok, &h, HTTP_ANOMALY_NONE, 0, "normal");
    verify("stable normal", 1, 200, &ok, &h, HTTP_ANOMALY_NONE, 0, "normal");
    verify("exact 1000ms normal", 1, 200, &at_threshold, &h, HTTP_ANOMALY_NONE, 0, "normal");
    verify("1001ms slow", 1, 200, &slow, &h, HTTP_ANOMALY_SLOW_RESPONSE, 1, "1001 ms");
    verify("recovered from slow", 1, 200, &ok, &h, HTTP_ANOMALY_RECOVERED, 0, "recovered");
    verify("stable after recovery", 1, 200, &ok, &h, HTTP_ANOMALY_NONE, 0, "normal");
    verify("first mismatch 404", 1, 200, &mismatch_404, &h, HTTP_ANOMALY_STATUS_MISMATCH, 1, "expected=200 actual=404");
    verify("second mismatch 500", 1, 200, &mismatch_500, &h, HTTP_ANOMALY_STATUS_MISMATCH, 2, "expected=200 actual=500");
    verify("third abnormal", 1, 200, &mismatch_404, &h, HTTP_ANOMALY_CONSECUTIVE, 3, "consecutive");
    verify("fourth abnormal", 1, 200, &mismatch_500, &h, HTTP_ANOMALY_CONSECUTIVE, 4, "consecutive");
    verify("recovered from mismatch", 1, 200, &ok, &h, HTTP_ANOMALY_RECOVERED, 0, "after 4");
    verify("first transport failure", 1, 200, &transport, &h, HTTP_ANOMALY_TRANSPORT_ERROR, 1, "error=");
    verify("mixed anomaly second", 1, 200, &mismatch_404, &h, HTTP_ANOMALY_STATUS_MISMATCH, 2, "mismatch");
    verify("mixed anomaly third", 1, 200, &transport, &h, HTTP_ANOMALY_CONSECUTIVE, 3, "consecutive");
    verify("recovered after transport", 1, 200, &ok, &h, HTTP_ANOMALY_RECOVERED, 0, "recovered");
    verify("expected 404 actual 404", 1, 404, &mismatch_404, &h, HTTP_ANOMALY_NONE, 0, "normal");
    verify("404 expected 200 abnormal", 1, 200, &mismatch_404, &h, HTTP_ANOMALY_STATUS_MISMATCH, 1, "mismatch");
    verify("disabled resets history", 0, 200, &transport, &h, HTTP_ANOMALY_NONE, 0, "disabled");
    verify("reenable does not recover", 1, 200, &ok, &h, HTTP_ANOMALY_NONE, 0, "normal");
    verify("missing response time", 1, 200, &missing_time, &h, HTTP_ANOMALY_TRANSPORT_ERROR, 1, "unavailable");
    verify("recover from missing time", 1, 200, &ok, &h, HTTP_ANOMALY_RECOVERED, 0, "recovered");
    verify("null probe", 1, 200, NULL, &h, HTTP_ANOMALY_TRANSPORT_ERROR, 1, "unavailable");
    verify("invalid expected status", 1, 99, &ok, &h, HTTP_ANOMALY_TRANSPORT_ERROR, 2, "unavailable");
    verify("third after invalid config", 1, 99, &ok, &h, HTTP_ANOMALY_CONSECUTIVE, 3, "consecutive");
    verify("recovered after invalid config", 1, 200, &ok, &h, HTTP_ANOMALY_RECOVERED, 0, "recovered");
    HttpAnomalyResult ignored;
    detect_http_anomaly(1, 200, &ok, NULL, &ignored);
    detect_http_anomaly(1, 200, &ok, &h, NULL);
    total++;
    printf("PASS %02d null result/history safety\n", total);

    printf("HTTP_ANOMALY_TEST_RESULT: %d passed, %d failed, %d total\n",
           total - failed, failed, total);
    return failed == 0 ? 0 : 1;
}
