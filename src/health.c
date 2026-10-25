#include <errno.h>
#include "health.h"

int evaluate_health(const ScanResult* scan,
                    const PortHistory* history,
                    int expected_state) {

    // 監視処理のエラーは期待状態に関係なく評価する
    if (scan->result == STATUS_ERROR) {
        return history->failure_count >= 3
            ? HEALTH_ALERT : HEALTH_UNKNOWN;
    }

    // 観測専用モードではOPEN/CLOSEDの良否を決めない
    if (expected_state == OBSERVE_ONLY) {
        return HEALTH_OBSERVE;
    }

    // 通常CLOSEDであるべきポート
    if (expected_state == EXPECT_CLOSED) {
        if (scan->result == STATUS_OPEN) {
            return HEALTH_ALERT;
        }

        if (scan->result == STATUS_CLOSED &&
            scan->error_stage == ERROR_STAGE_CONNECT &&
            scan->error_code == ECONNREFUSED) {
            return HEALTH_OK;
        }

        return HEALTH_UNKNOWN;
    }

    // 通常OPENであるべきポート
    if (expected_state == EXPECT_OPEN) {
        if (scan->result == STATUS_OPEN) {
            if (scan->response_ms > SLOW_RESPONSE_THRESHOLD_MS) {
                return HEALTH_WARNING;
            }
            return HEALTH_OK;
        }

        if (scan->result == STATUS_CLOSED) {
            return history->failure_count >= 3
                ? HEALTH_ALERT : HEALTH_WARNING;
        }
    }

    return HEALTH_UNKNOWN;
}
