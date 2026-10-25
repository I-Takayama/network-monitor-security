#include <stdio.h>
#include <string.h>
#include "http_probe.h"

static int check(const char *label,
                 const char *path, int expected) {
    HttpProbeResult r;

    int rc = http_probe_get(
        "127.0.0.1", 18000, path, 3000, &r
    );

    int ok = (
        rc == 0 &&
        r.http_status == expected &&
        r.response_ms >= 0 &&
        strcmp(r.error_stage, "none") == 0
    );

    printf("%s %s HTTP=%d time=%ldms\n",
           ok ? "PASS" : "FAIL",
           label, r.http_status, r.response_ms);

    return ok;
}

int main(void) {
    int passed = 0;

    passed += check(
        "GET /health", "/health", 200
    );

    passed += check(
        "GET /balance", "/balance", 200
    );

    passed += check(
        "GET unknown endpoint",
        "/missing-http-probe", 404
    );

    HttpProbeResult r;
    int rc = http_probe_get(
        "127.0.0.1", 18001, "/health", 3000, &r
    );

    int transport_ok = (
        rc != 0 &&
        r.http_status == 0 &&
        r.error_code != 0 &&
        strcmp(r.error_stage, "connect") == 0
    );

    printf("%s TCP connection failure stage=%s errno=%d\n",
           transport_ok ? "PASS" : "FAIL",
           r.error_stage, r.error_code);

    passed += transport_ok;

    printf("HTTP_PROBE_RESULT: %d passed, %d failed, 4 total\n",
           passed, 4 - passed);

    return passed == 4 ? 0 : 1;
}
