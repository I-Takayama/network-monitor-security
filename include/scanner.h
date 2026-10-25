#ifndef SCANNER_H
#define SCANNER_H

/*
 * ポートスキャン結果を表す定数
 */
#define STATUS_OPEN 1       // 接続成功
#define STATUS_CLOSED 0     // 接続失敗
#define STATUS_ERROR -1     // ソケット生成やIP変換などの処理エラー
#define ERROR_STAGE_NONE 0
#define ERROR_STAGE_SOCKET 1
#define ERROR_STAGE_IP_CONVERSION 2
#define ERROR_STAGE_CONNECT 3

/*
 * スキャン対象を表す構造体
 *
 * 【目的】
 * - 監視対象IPアドレスとポート範囲をまとめて管理する
 * - main処理で監視条件を一元的に扱いやすくする
 */
typedef struct {
    char ip[64];    // 監視対象のIPアドレス
    int start_port; // 監視開始ポート
    int end_port;   // 監視終了ポート
} ScanTarget;

/*
 * 1回のポートスキャン結果を保持する構造体
 *
 * 【目的】
 * - スキャン結果をログ出力、異常検知、Web表示で共通利用する
 * - 時刻・接続結果・応答時間をまとめて保持する
 */
typedef struct {
    char time_str[64];  // 計測時刻
    char ip[64];        // 対象IPアドレス
    int port;           // 対象ポート番号
    int result;         // STATUS_OPEN / STATUS_CLOSED / STATUS_ERROR
    long response_ms;   // 接続試行にかかった時間（ミリ秒）
    int error_stage;  // エラー発生箇所
    int error_code;   // エラー詳細コード
} ScanResult;

/*
 * 指定したIPアドレス・ポートにTCP接続を試み、
 * ポートの開閉状態と応答時間を取得する関数
 *
 * @param ip          対象IPアドレス
 * @param port        対象ポート番号
 * @param scan_result スキャン結果の格納先
 * @return 成功時 STATUS_OPEN または STATUS_CLOSED、失敗時 STATUS_ERROR
 */
int scan_port(const char* ip, int port, ScanResult* scan_result);

/*
 * スキャン結果をターミナルに表示する関数
 *
 * @param scan_result 表示対象のスキャン結果
 */
void print_result(const ScanResult* scan_result);

#endif