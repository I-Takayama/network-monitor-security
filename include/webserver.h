#ifndef WEBSERVER_H
#define WEBSERVER_H

#include "status.h"

/*
 * Webサーバ用スレッドの引数構造体
 *
 * 【目的】
 * - Webサーバの起動に必要な情報をまとめる
 * - スレッド関数に複数のパラメータを安全に渡す
 */
typedef struct {
    int port;                       // Webサーバの待ち受けポート番号
    SharedStatus* shared_status;    // 監視結果（共有データ）
} WebServerArg;

/*
 * Webサーバを起動するスレッド関数
 *
 * 【処理内容】
 * - 指定ポートで待ち受けを行う
 * - HTTPリクエストを受信し、内容に応じてレスポンスを返す
 *   - "/"            → HTMLページを返す
 *   - "/api/status" → JSON形式で監視結果を返す
 *
 * 【設計意図】
 * - 監視処理とWeb表示処理を分離し、非同期に動作させる
 * - SharedStatusを参照することでリアルタイムな情報提供を実現
 *
 * @param arg WebServerArg構造体へのポインタ
 * @return スレッド関数の戻り値（未使用）
 */
void* start_web_server(void* arg);
#endif