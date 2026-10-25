#include <stdio.h>
#include <errno.h>
#include "health.h"

static int total = 0;
static int failed = 0;

static void check(const char* label,
                  int expected_state,
                  int observed_state,
                  long response_ms,
                  int failure_count,
                  int error_stage,
                  int error_code,
                  int expected_health) {
    ScanResult scan = {0};
    PortHistory history = {0};

    scan.result = observed_state;
    scan.response_ms = response_ms;
    scan.error_stage = error_stage;
    scan.error_code = error_code;
    history.failure_count = failure_count;

    int actual = evaluate_health(
        &scan, &history, expected_state
    );

    total++;

    if (actual == expected_health) {
        printf("PASS %02d %s\n", total, label);
    } else {
        failed++;
        printf("FAIL %02d %s expected=%d actual=%d\n",
               total, label, expected_health, actual);
    }
}

int main(void) {
    check("OPEN normal",
          EXPECT_OPEN, STATUS_OPEN, 1, 0,
          ERROR_STAGE_NONE, 0, HEALTH_OK);

    check("OPEN at 1000ms",
          EXPECT_OPEN, STATUS_OPEN, 1000, 0,
          ERROR_STAGE_NONE, 0, HEALTH_OK);

    check("OPEN at 1001ms",
          EXPECT_OPEN, STATUS_OPEN, 1001, 0,
          ERROR_STAGE_NONE, 0, HEALTH_WARNING);

    check("OPEN at 1500ms",
          EXPECT_OPEN, STATUS_OPEN, 1500, 0,
          ERROR_STAGE_NONE, 0, HEALTH_WARNING);

    check("CLOSED first failure",
          EXPECT_OPEN, STATUS_CLOSED, 0, 1,
          ERROR_STAGE_CONNECT, ECONNREFUSED, HEALTH_WARNING);

    check("CLOSED second failure",
          EXPECT_OPEN, STATUS_CLOSED, 0, 2,
          ERROR_STAGE_CONNECT, ECONNREFUSED, HEALTH_WARNING);

    check("CLOSED third failure",
          EXPECT_OPEN, STATUS_CLOSED, 0, 3,
          ERROR_STAGE_CONNECT, ECONNREFUSED, HEALTH_ALERT);

    check("ERROR first failure",
          EXPECT_OPEN, STATUS_ERROR, -1, 1,
          ERROR_STAGE_SOCKET, 24, HEALTH_UNKNOWN);

    check("ERROR third failure",
          EXPECT_OPEN, STATUS_ERROR, -1, 3,
          ERROR_STAGE_SOCKET, 24, HEALTH_ALERT);

    check("Expected CLOSED refused",
          EXPECT_CLOSED, STATUS_CLOSED, 0, 3,
          ERROR_STAGE_CONNECT, ECONNREFUSED, HEALTH_OK);

    check("Expected CLOSED timeout",
          EXPECT_CLOSED, STATUS_CLOSED, 1500, 3,
          ERROR_STAGE_CONNECT, ETIMEDOUT, HEALTH_UNKNOWN);

    check("Expected CLOSED unreachable",
          EXPECT_CLOSED, STATUS_CLOSED, 1, 3,
          ERROR_STAGE_CONNECT, ENETUNREACH, HEALTH_UNKNOWN);

    check("Unexpected OPEN",
          EXPECT_CLOSED, STATUS_OPEN, 1, 0,
          ERROR_STAGE_NONE, 0, HEALTH_ALERT);

    check("Expected CLOSED scan ERROR",
          EXPECT_CLOSED, STATUS_ERROR, -1, 1,
          ERROR_STAGE_SOCKET, 24, HEALTH_UNKNOWN);

    check("Expected CLOSED repeated ERROR",
          EXPECT_CLOSED, STATUS_ERROR, -1, 3,
          ERROR_STAGE_SOCKET, 24, HEALTH_ALERT);

    check("Observe OPEN",
          OBSERVE_ONLY, STATUS_OPEN, 1, 0,
          ERROR_STAGE_NONE, 0, HEALTH_OBSERVE);

    check("Observe CLOSED",
          OBSERVE_ONLY, STATUS_CLOSED, 0, 1,
          ERROR_STAGE_CONNECT, ECONNREFUSED, HEALTH_OBSERVE);

    check("Observe timeout",
          OBSERVE_ONLY, STATUS_CLOSED, 1500, 1,
          ERROR_STAGE_CONNECT, ETIMEDOUT, HEALTH_OBSERVE);

    check("Observe scan ERROR",
          OBSERVE_ONLY, STATUS_ERROR, -1, 1,
          ERROR_STAGE_SOCKET, 24, HEALTH_UNKNOWN);

    check("Observe repeated ERROR",
          OBSERVE_ONLY, STATUS_ERROR, -1, 3,
          ERROR_STAGE_SOCKET, 24, HEALTH_ALERT);

    check("Invalid observed state",
          EXPECT_OPEN, 99, 0, 0,
          ERROR_STAGE_NONE, 0, HEALTH_UNKNOWN);

    check("Invalid expected state",
          99, STATUS_OPEN, 1, 0,
          ERROR_STAGE_NONE, 0, HEALTH_UNKNOWN);

    printf("HEALTH_TEST_RESULT: %d passed, %d failed, %d total\n",
           total - failed, failed, total);

    return failed == 0 ? 0 : 1;
}
