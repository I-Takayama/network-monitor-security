#include <time.h>
#include "utils.h"

/*
 * 現在時刻を文字列として取得する
 * ログ出力や画面表示で統一フォーマットの時刻を扱うために使用する
 *
 * フォーマット: YYYY-MM-DD HH:MM:SS
 */
void get_current_time_str(char* buffer, size_t size){
    // 現在時刻（UNIX時間）を取得
    time_t now = time(NULL);

    // ローカルタイム（日本時間など）へ変換
    struct tm *local = localtime(&now);

    // 指定フォーマットで文字列に変換してbufferへ格納
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", local);
}