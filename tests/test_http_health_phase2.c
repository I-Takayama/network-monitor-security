#include <stdio.h>
#include "http_health.h"

static int cases = 0, failed = 0;
static void check(const char* title, int enabled, int expected,
                  int actual_status, int outcome) {
    HttpProbeResult r = {0};
    r.http_status = actual_status;
    int got = evaluate_http_health(enabled, expected, &r);
    cases++;
    if (got != outcome) {
        failed++;
        printf("FAIL %02d %s expected=%d got=%d\n", cases, title, outcome, got);
    } else {
        printf("PASS %02d %s\n", cases, title);
    }
}
int main(void) {
    check("disabled", 0, 200, 200, HTTP_HEALTH_DISABLED);
    check("200 equals 200", 1, 200, 200, HTTP_HEALTH_OK);
    check("404 differs from 200", 1, 200, 404, HTTP_HEALTH_MISMATCH);
    check("404 equals 404", 1, 404, 404, HTTP_HEALTH_OK);
    check("500 differs from 200", 1, 200, 500, HTTP_HEALTH_MISMATCH);
    check("301 differs from 200", 1, 200, 301, HTTP_HEALTH_MISMATCH);
    check("no HTTP reply", 1, 200, 0, HTTP_HEALTH_TRANSPORT_ERROR);
    check("invalid status", 1, 200, 700, HTTP_HEALTH_TRANSPORT_ERROR);
    check("invalid expectation", 1, 99, 200, HTTP_HEALTH_TRANSPORT_ERROR);
    cases++;
    if (evaluate_http_health(1, 200, NULL) == HTTP_HEALTH_TRANSPORT_ERROR) {
        printf("PASS %02d null probe\n", cases);
    } else { failed++; printf("FAIL %02d null probe\n", cases); }
    printf("HTTP_HEALTH_TEST_RESULT: %d passed, %d failed, %d total\n",
           cases - failed, failed, cases);
    return failed == 0 ? 0 : 1;
}
