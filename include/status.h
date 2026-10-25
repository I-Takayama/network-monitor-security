#ifndef STATUS_H
#define STATUS_H

#include <pthread.h>
#include "scanner.h"
#include "anomaly.h"
#include "http_probe.h"
#include "http_anomaly.h"

#define HEALTH_UNKNOWN 0
#define HEALTH_OK 1
#define HEALTH_WARNING 2
#define HEALTH_ALERT 3
#define HEALTH_OBSERVE 4

/*
 * 1回の監視結果をまとめて保持する構造体
 *
 * 【目的】
 * - スキャン結果と異常検知結果を1つにまとめて扱う
 * - ログ出力、共有状態更新、Web表示で共通利用する
 */
typedef struct {
    ScanResult scan;        // ポートスキャン結果
    AnomalyResult anomaly;  // 異常検知結果
    int expected_state;     // 期待状態
    int health_status;      // ヘルスステータス
    int http_enabled;
    char http_path[128];
    HttpProbeResult http;
    int http_expected_status;
    int http_health_status;
    HttpAnomalyResult http_anomaly;
} MonitorResult;

/*
 * スレッド間で共有する監視状態を保持する構造体
 *
 * 【目的】
 * - 各ポートの最新監視結果を保持する
 * - Webサーバや他スレッドから安全に参照・更新できるようにする
 *
 * 【設計意図】
 * - 共有データを1か所に集約することで管理を簡潔にする
 * - mutexにより同時アクセス時の競合状態を防ぐ
 */
typedef struct {
    MonitorResult* results; // 各ポートの最新監視結果を格納する配列
    int count;              // 監視対象ポート数
    pthread_mutex_t mutex;  // 共有データ保護用のmutex
} SharedStatus;

/*
 * SharedStatusを初期化する関数
 *
 * 【処理内容】
 * - 監視結果配列を確保する
 * - mutexを初期化する
 *
 * @param status 初期化対象の共有状態
 * @param count  監視対象ポート数
 */
void init_shared_status(SharedStatus* status, int count);

/*
 * 共有状態を更新する関数
 *
 * 【処理内容】
 * - 指定インデックスの監視結果を更新する
 * - mutexによる排他制御を行い、競合状態を防ぐ
 *
 * @param status 更新対象の共有状態
 * @param index  更新する配列位置
 * @param result 書き込む監視結果
 */
void update_shared_status(SharedStatus* status, int index, const MonitorResult* result);

/*
 * SharedStatusの後処理を行う関数
 *
 * 【処理内容】
 * - 確保した監視結果配列を解放する
 * - mutexを破棄する
 *
 * @param status 後処理対象の共有状態
 */
void destroy_shared_status(SharedStatus* status);

#endif
