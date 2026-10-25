#ifndef HEALTH_H
#define HEALTH_H

#include "status.h"

/*
 * TCP監視条件に対するヘルスステータスを評価する。
 * 戻り値：HEALTH_* 定数
 */
int evaluate_health(const ScanResult* scan,
                    const PortHistory* history,
                    int expected_state);

#endif
