#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>

/*
 * 現在時刻を文字列として取得する関数
 *
 * 【目的】
 * - スキャン結果にタイムスタンプを付与する
 * - ログ出力や画面表示で利用するための統一フォーマットを提供する
 *
 * 【仕様】
 * - 指定されたバッファに現在時刻を文字列として格納する
 * - フォーマット例: "YYYY-MM-DD HH:MM:SS"
 *
 * @param buffer 時刻文字列を書き込むバッファ
 * @param size   バッファサイズ（オーバーフロー防止用）
 */
void get_current_time_str(char* buffer, size_t size);

#endif