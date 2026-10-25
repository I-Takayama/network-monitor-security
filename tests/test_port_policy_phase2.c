#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "config.h"

static int total = 0;
static int failed = 0;

static void test_case(const char* label,
                      const char* content,
                      int should_succeed,
                      int expected_18000,
                      int expected_18001) {
    char path[] = "/tmp/nm-policy-XXXXXX";
    int fd = mkstemp(path);

    if (fd < 0) {
        perror("mkstemp");
        exit(2);
    }

    FILE* fp = fdopen(fd, "w");
    if (!fp) {
        perror("fdopen");
        close(fd);
        unlink(path);
        exit(2);
    }

    if (fputs(content, fp) == EOF || fclose(fp) != 0) {
        perror("write test config");
        unlink(path);
        exit(2);
    }

    Config config;
    int rc = load_config(path, &config);
    unlink(path);

    int ok = should_succeed ? (rc == 0) : (rc != 0);

    if (ok && should_succeed) {
        ok =
            get_expected_state_for_port(&config, 18000) ==
                expected_18000 &&
            get_expected_state_for_port(&config, 18001) ==
                expected_18001;
    }

    total++;

    if (ok) {
        printf("PASS %02d %s\n", total, label);
    } else {
        failed++;
        printf("FAIL %02d %s\n", total, label);
    }
}

int main(void) {
    test_case("default OPEN", "",
              1, EXPECT_OPEN, EXPECT_OPEN);

    test_case("global CLOSED",
              "expected_state=CLOSED\n",
              1, EXPECT_CLOSED, EXPECT_CLOSED);

    test_case("global OBSERVE_ONLY",
              "expected_state=OBSERVE_ONLY\n",
              1, OBSERVE_ONLY, OBSERVE_ONLY);

    test_case("override port 18001",
              "expected_state=OPEN\n"
              "expected_state_18001=CLOSED\n",
              1, EXPECT_OPEN, EXPECT_CLOSED);

    test_case("override port 18000",
              "expected_state=CLOSED\n"
              "expected_state_18000=OPEN\n",
              1, EXPECT_OPEN, EXPECT_CLOSED);

    test_case("override before default",
              "expected_state_18001=CLOSED\n"
              "expected_state=OBSERVE_ONLY\n",
              1, OBSERVE_ONLY, EXPECT_CLOSED);

    test_case("two different overrides",
              "expected_state_18000=OPEN\n"
              "expected_state_18001=OBSERVE_ONLY\n",
              1, EXPECT_OPEN, OBSERVE_ONLY);

    test_case("reject port zero",
              "expected_state_0=CLOSED\n",
              0, 0, 0);

    test_case("reject port 65536",
              "expected_state_65536=CLOSED\n",
              0, 0, 0);

    test_case("reject malformed port",
              "expected_state_abc=CLOSED\n",
              0, 0, 0);

    test_case("reject malformed port suffix",
              "expected_state_18001abc=CLOSED\n",
              0, 0, 0);

    test_case("reject invalid policy",
              "expected_state_18001=UNKNOWN\n",
              0, 0, 0);

    test_case("reject duplicate port policy",
              "expected_state_18001=CLOSED\n"
              "expected_state_18001=OPEN\n",
              0, 0, 0);

    printf("PORT_POLICY_TEST_RESULT: %d passed, %d failed, %d total\n",
           total - failed, failed, total);

    return failed == 0 ? 0 : 1;
}
