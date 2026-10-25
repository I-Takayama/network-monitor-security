#include <stdio.h>
#include <string.h>
#include "anomaly.h"

static int total = 0;
static int failures = 0;

static void expect_step(const char *label, PortHistory *history,
                        int status, long response_ms, int stage, int code,
                        int expected_type, const char *expected_message,
                        int expected_count) {
    ScanResult scan = {0};
    AnomalyResult anomaly = {0};

    scan.result = status;
    scan.response_ms = response_ms;
    scan.error_stage = stage;
    scan.error_code = code;

    detect_anomaly(&scan, history, &anomaly);
    total++;

    if (anomaly.anomaly_type == expected_type &&
        strcmp(anomaly.message, expected_message) == 0 &&
        history->failure_count == expected_count &&
        history->previous_result == status) {
        printf("PASS %02d %s\n", total, label);
    } else {
        failures++;
        printf("FAIL %02d %s\n", total, label);
        printf("  got: type=%d count=%d prev=%d message=%s\n",
               anomaly.anomaly_type, history->failure_count,
               history->previous_result, anomaly.message);
        printf("  expected: type=%d count=%d prev=%d message=%s\n",
               expected_type, expected_count, status, expected_message);
    }
}

int main(void) {
    PortHistory h;
    init_port_history(&h);

    expect_step("initial OPEN", &h, STATUS_OPEN, 1, ERROR_STAGE_NONE, 0,
                ANOMALY_NONE, "normal", 0);

    expect_step("stable OPEN", &h, STATUS_OPEN, 1, ERROR_STAGE_NONE, 0,
                ANOMALY_NONE, "normal", 0);

    expect_step("OPEN latency > threshold", &h, STATUS_OPEN, 1001, ERROR_STAGE_NONE, 0,
                ANOMALY_SLOW_RESPONSE, "slow response: 1001 ms", 0);

    expect_step("OPEN latency equals threshold", &h, STATUS_OPEN, 1000, ERROR_STAGE_NONE, 0,
                ANOMALY_NONE, "normal", 0);

    expect_step("OPEN to CLOSED", &h, STATUS_CLOSED, 0, ERROR_STAGE_CONNECT, 111,
                ANOMALY_STATUS_CHANGED, "status changed: previous=1 current=0", 1);

    expect_step("CLOSED twice", &h, STATUS_CLOSED, 0, ERROR_STAGE_CONNECT, 111,
                ANOMALY_NONE, "normal", 2);

    expect_step("CLOSED three times", &h, STATUS_CLOSED, 0, ERROR_STAGE_CONNECT, 111,
                ANOMALY_CONSECUTIVE_FAILURE, "consecutive connection failures: 3", 3);

    expect_step("CLOSED four times", &h, STATUS_CLOSED, 0, ERROR_STAGE_CONNECT, 111,
                ANOMALY_CONSECUTIVE_FAILURE, "consecutive connection failures: 4", 4);

    expect_step("CLOSED to ERROR resets counter", &h,
                STATUS_ERROR, -1, ERROR_STAGE_SOCKET, 24,
                ANOMALY_STATUS_CHANGED, "status changed: previous=0 current=-1", 1);

    expect_step("ERROR with a different cause counts", &h,
                STATUS_ERROR, -1, ERROR_STAGE_IP_CONVERSION, 0,
                ANOMALY_NONE, "normal", 2);

    expect_step("ERROR third time with another cause", &h,
                STATUS_ERROR, -1, ERROR_STAGE_SOCKET, 12,
                ANOMALY_CONSECUTIVE_FAILURE, "consecutive scan errors: 3", 3);

    expect_step("ERROR to CLOSED resets counter", &h,
                STATUS_CLOSED, 0, ERROR_STAGE_CONNECT, 111,
                ANOMALY_STATUS_CHANGED, "status changed: previous=-1 current=0", 1);

    expect_step("CLOSED second time after ERROR", &h,
                STATUS_CLOSED, 0, ERROR_STAGE_CONNECT, 111,
                ANOMALY_NONE, "normal", 2);

    expect_step("CLOSED to OPEN resets failures", &h,
                STATUS_OPEN, 1, ERROR_STAGE_NONE, 0,
                ANOMALY_STATUS_CHANGED, "status changed: previous=0 current=1", 0);

    expect_step("OPEN stable after recovery", &h,
                STATUS_OPEN, 1, ERROR_STAGE_NONE, 0,
                ANOMALY_NONE, "normal", 0);

    expect_step("OPEN to ERROR", &h,
                STATUS_ERROR, -1, ERROR_STAGE_SOCKET, 24,
                ANOMALY_STATUS_CHANGED, "status changed: previous=1 current=-1", 1);

    expect_step("ERROR to OPEN resets failures", &h,
                STATUS_OPEN, 1, ERROR_STAGE_NONE, 0,
                ANOMALY_STATUS_CHANGED, "status changed: previous=-1 current=1", 0);

    init_port_history(&h);

    expect_step("initial CLOSED is not a state change", &h,
                STATUS_CLOSED, 1400, ERROR_STAGE_CONNECT, 110,
                ANOMALY_NONE, "normal", 1);

    expect_step("CLOSED latency is not OPEN slowdown", &h,
                STATUS_CLOSED, 1400, ERROR_STAGE_CONNECT, 110,
                ANOMALY_NONE, "normal", 2);

    expect_step("CLOSED three times despite large latency", &h,
                STATUS_CLOSED, 1400, ERROR_STAGE_CONNECT, 110,
                ANOMALY_CONSECUTIVE_FAILURE, "consecutive connection failures: 3", 3);

    printf("TEST_RESULT: %d passed, %d failed, %d total\n",
           total - failures, failures, total);

    return failures == 0 ? 0 : 1;
}
