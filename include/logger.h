#ifndef LOGGER_H
#define LOGGER_H

#include "status.h"

/*
 * 監視結果をログとして記録するモジュール
 *
 * 【目的】
 * - スキャン結果を時系列で保存し、後から分析可能にする
 * - 異常発生時の履歴を残し、トラブルシュートに活用する
 *
 * 【設計意図】
 * - ログ出力処理を他の処理から分離し、責務を明確化する
 * - ファイル出力形式（CSVなど）をこのモジュールで一元管理する
 */

/*
 * 監視結果をログファイルに出力する関数
 *
 * 【処理内容】
 * - MonitorResult の内容をCSV形式でファイルに書き込む
 * - 時刻、IP、ポート、結果、応答時間、異常情報などを記録
 *
 * @param result ログ出力する監視結果
 */
void log_result(const MonitorResult* result);
void log_http_result(const MonitorResult* result);

#endif