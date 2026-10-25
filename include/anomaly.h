#ifndef ANOMALY_H
#define ANOMALY_H

#include "scanner.h"
#include "config.h"

/*
 * 異常の種類を表す定数
 */
#define ANOMALY_NONE 0                  // 異常なし
#define ANOMALY_STATUS_CHANGED 1        // ポート状態の変化（OPEN⇄CLOSED）
#define ANOMALY_SLOW_RESPONSE 2         // 応答時間の遅延
#define ANOMALY_CONSECUTIVE_FAILURE 3   // 連続失敗
#define ANOMALY_UNEXPECTED_OPEN 4
#define ANOMALY_UNVERIFIED_CLOSED 5
#define ANOMALY_SCAN_ERROR 6

// TCP接続試行時間の遅延閾値（ミリ秒）
#define SLOW_RESPONSE_THRESHOLD_MS 1000L

/*
 * ポートごとの過去状態を保持する構造体
 *
 * 【目的】
 * - 前回の状態と比較することで異常検知を行う
 * - 連続失敗や応答時間の変化を追跡する
 */
typedef struct {
    int previous_result;            // 前回のポート状態（OPEN/CLOSED）
    int current_result;             // 現在のポート状態
    int failure_count;              // 連続失敗回数
    int expected_state;             // 期待状態
    double previous_response_ms;    // 前回の応答時間（ms）
} PortHistory;

/*
 * 異常検知結果を保持する構造体
 *
 * 【目的】
 * - 検知した異常の種類と内容をまとめる
 * - ログ出力やWeb表示で利用する
 */
typedef struct {
    int anomaly_type;   // 異常の種類（上記ANOMALY_*）
    char message[256];  // 異常内容の説明メッセージ
} AnomalyResult;

/*
 * PortHistoryを初期化する関数
 *
 * @param history 初期化対象の履歴構造体
 */
void init_port_history(PortHistory* history);

/*
 * 異常検知を行う関数
 *
 * 【処理内容】
 * - 現在のスキャン結果と過去の状態を比較
 * - 状態変化・応答遅延・連続失敗を検知
 * - 結果をAnomalyResultに格納
 *
 * @param current 現在のスキャン結果
 * @param history 過去状態（更新される）
 * @param anomaly 検知結果の出力先
 */
void detect_anomaly(const ScanResult* current, PortHistory* history, AnomalyResult* anomaly);

#endif