#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "config.h"

static int cases = 0, failed = 0;
static void check(const char* name, const char* content,
                  int valid, int expected) {
    char path[] = "/tmp/nm-http-health-config-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) { perror("mkstemp"); exit(2); }
    FILE* fp = fdopen(fd, "w");
    if (!fp) { perror("fdopen"); close(fd); unlink(path); exit(2); }
    if (fputs(content, fp) == EOF || fclose(fp) != 0) {
        perror("write config"); unlink(path); exit(2);
    }
    Config config;
    int rc = load_config(path, &config);
    unlink(path);
    int ok = valid ? (rc == 0 && config.http_expected_status == expected) : rc != 0;
    cases++;
    printf("%s %02d %s\n", ok ? "PASS" : "FAIL", cases, name);
    if (!ok) failed++;
}
int main(void) {
    check("default expected 200", "", 1, 200);
    check("expected 204", "http_expected_status=204\n", 1, 204);
    check("expected 404", "http_expected_status=404\n", 1, 404);
    check("reject 99", "http_expected_status=99\n", 0, 0);
    check("reject 600", "http_expected_status=600\n", 0, 0);
    check("reject text", "http_expected_status=abc\n", 0, 0);
    printf("HTTP_HEALTH_CONFIG_TEST_RESULT: %d passed, %d failed, %d total\n",
           cases - failed, failed, cases);
    return failed == 0 ? 0 : 1;
}
