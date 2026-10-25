#include <stdio.h>
#include <errno.h>
#include "anomaly.h"

static int total = 0;
static int failed = 0;

static void check(const char *name, PortHistory *h,
                  int state, int stage, int code,
                  int expected_type, int expected_count) {
    ScanResult scan = {0};
    AnomalyResult result = {0};

    scan.result = state;
    scan.error_stage = stage;
    scan.error_code = code;
    scan.response_ms = 1;

    detect_anomaly(&scan, h, &result);
    total++;

    if (result.anomaly_type == expected_type &&
        h->failure_count == expected_count) {
        printf("PASS %02d %s\n", total, name);
    } else {
        failed++;
        printf("FAIL %02d %s type=%d count=%d message=%s\n",
               total, name, result.anomaly_type,
               h->failure_count, result.message);
    }
}

int main(void) {
    PortHistory h;
    init_port_history(&h);
    h.expected_state = EXPECT_CLOSED;

    check("CLOSED refused 1", &h, STATUS_CLOSED,
          ERROR_STAGE_CONNECT, ECONNREFUSED, ANOMALY_NONE, 1);
    check("CLOSED refused 2", &h, STATUS_CLOSED,
          ERROR_STAGE_CONNECT, ECONNREFUSED, ANOMALY_NONE, 2);
    check("CLOSED refused 3", &h, STATUS_CLOSED,
          ERROR_STAGE_CONNECT, ECONNREFUSED, ANOMALY_NONE, 3);
    check("unexpected OPEN", &h, STATUS_OPEN,
          ERROR_STAGE_NONE, 0, ANOMALY_UNEXPECTED_OPEN, 0);
    check("return to CLOSED", &h, STATUS_CLOSED,
          ERROR_STAGE_CONNECT, ECONNREFUSED, ANOMALY_NONE, 1);
    check("timeout is not verified CLOSED", &h, STATUS_CLOSED,
          ERROR_STAGE_CONNECT, ETIMEDOUT, ANOMALY_UNVERIFIED_CLOSED, 2);
    check("scan ERROR first", &h, STATUS_ERROR,
          ERROR_STAGE_SOCKET, 24, ANOMALY_SCAN_ERROR, 1);
    check("scan ERROR second different cause", &h, STATUS_ERROR,
          ERROR_STAGE_IP_CONVERSION, 0, ANOMALY_SCAN_ERROR, 2);
    check("scan ERROR third different cause", &h, STATUS_ERROR,
          ERROR_STAGE_SOCKET, 12, ANOMALY_CONSECUTIVE_FAILURE, 3);

    init_port_history(&h);
    h.expected_state = OBSERVE_ONLY;

    check("observe OPEN", &h, STATUS_OPEN,
          ERROR_STAGE_NONE, 0, ANOMALY_NONE, 0);
    check("observe CLOSED", &h, STATUS_CLOSED,
          ERROR_STAGE_CONNECT, ECONNREFUSED, ANOMALY_NONE, 1);
    check("observe scan ERROR", &h, STATUS_ERROR,
          ERROR_STAGE_SOCKET, 24, ANOMALY_SCAN_ERROR, 1);

    printf("POLICY_TEST_RESULT: %d passed, %d failed, %d total\n",
           total - failed, failed, total);
    return failed == 0 ? 0 : 1;
}
