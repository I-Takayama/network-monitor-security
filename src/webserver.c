#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "webserver.h"
#include "auth_status.h"
#include <time.h>
#include <stdint.h>

#define BUFFER_SIZE 4096
#define JSON_BUFFER_SIZE 65536

// クライアントへ404レスポンスを返す
static void send_404(int client_sock);
static void send_auth_json(int client_sock);

// index.html を読み込み、トップページとして返す
static void send_index_html(int client_sock);

// 共有監視状態をJSON形式に変換して返す
static void send_status_json(int client_sock, SharedStatus* shared_status);

// 受信したHTTPリクエストに応じて応答を切り替える
static void handle_client(int client_sock, SharedStatus* shared_status);

/*
 * 簡易Webサーバを起動する
 * ブラウザからのHTTPリクエストを受け付け、
 * HTML画面またはJSON形式の監視結果を返す
 */
void* start_web_server(void* arg) {
    WebServerArg* server_arg = (WebServerArg*)arg;
    int server_port = server_arg->port;
    SharedStatus* shared_status = server_arg->shared_status;

    int server_sock;
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    // TCPサーバ用ソケットを生成する
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("socket");
        return NULL;
    }

    // サーバ再起動時にポートを再利用しやすくする
    int opt = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(server_sock);
        return NULL;
    }

    // サーバの待受アドレス情報を初期化する
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    server_addr.sin_port = htons(server_port);

    // IPv4ループバックアドレスで待ち受ける
    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(server_sock);
        return NULL;
    }

    // 接続待ち状態に移行する
    if (listen(server_sock, 10) < 0) {
        perror("listen");
        close(server_sock);
        return NULL;
    }

    printf("Web server started: http://localhost:%d/\n", server_port);

    // クライアントからの接続を繰り返し受け付ける
    while (1) {
        int client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_len);
        if (client_sock < 0) {
            perror("accept");
            continue;
        }

        // 受信したリクエストの内容に応じて応答を返す
        handle_client(client_sock, shared_status);
        close(client_sock);
    }

    close(server_sock);
    return NULL;
}

/*
 * クライアントから受信したHTTPリクエストを解析し、
 * パスに応じてHTML / JSON / 404を返す
 */
static void handle_client(int client_sock, SharedStatus* shared_status) {
    char buffer[BUFFER_SIZE];
    int received;

    // 受信用バッファを初期化してリクエストを受信する
    memset(buffer, 0, sizeof(buffer));
    received = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
    if (received <= 0) {
        return;
    }

    // トップページ要求なら index.html を返す
    if (strncmp(buffer, "GET / ", 6) == 0 || strncmp(buffer, "GET /HTTP", 9) == 0) {
        send_index_html(client_sock);
    }
    // API要求なら監視結果をJSONで返す
    else if (strncmp(buffer, "GET /api/status ", 16) == 0) {
        send_status_json(client_sock, shared_status);
    }
    else if (strncmp(buffer, "GET /api/auth-status ", 21) == 0) {
        send_auth_json(client_sock);
    }
    // 定義していないパスには404を返す
    else {
        send_404(client_sock);
    }
}

/*
 * ブラウザ表示用の index.html を返す
 * ファイルが存在しない場合は 500 Internal Server Error を返す
 */
static void send_index_html(int client_sock) {
    FILE* fp = fopen("web/index.html", "r");
    if (fp == NULL) {
        const char* body = "<html><body><h1>index.html not found</h1></body></html>";

        dprintf(client_sock,
                "HTTP/1.1 500 Internal Server Error\r\n"
                "Content-Type: text/html\r\n"
                "Content-Length: %zu\r\n"
                "Connection: close\r\n"
                "\r\n"
                "%s",
                strlen(body), body);
        return;
    }

    // HTMLファイル全体を読み込むためサイズを取得する
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    rewind(fp);

    char* body = malloc(file_size + 1);
    if (body == NULL) {
        fclose(fp);
        return;
    }

    // ファイル内容を格納するバッファを動的確保する
    fread(body, 1, file_size, fp);
    body[file_size] = '\0';
    fclose(fp);

    // HTTPレスポンスとしてHTMLを返す
    dprintf(client_sock,
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html; charset=UTF-8\r\n"
            "Content-Length: %ld\r\n"
            "Connection: close\r\n"
            "\r\n"
            "%s",
            file_size, body);

    free(body);
}

/*
 * 共有監視状態をJSON形式で返す
 * 外部ライブラリは使わず、snprintfで手動生成している
 */
static void send_status_json(int client_sock, SharedStatus* shared_status) {
    char body[JSON_BUFFER_SIZE];
    int offset = 0;

    // 共有データを安全に参照するため、JSON生成中はロックする
    pthread_mutex_lock(&shared_status->mutex);

    // JSON配列の開始
    offset += snprintf(body + offset, sizeof(body) - offset, "[");

    for (int i = 0; i < shared_status->count; i++) {
        MonitorResult* r = &shared_status->results[i];

        // 各ポートの監視結果をJSONオブジェクトとして連結する
        offset += snprintf(
            body + offset,
            sizeof(body) - offset,
            "%s"
            "{"
            "\"time_str\":\"%s\","
            "\"ip\":\"%s\","
            "\"port\":%d,"
            "\"result\":%d,"
            "\"response_ms\":%ld,"
            "\"anomaly_type\":%d,"
            "\"anomaly_message\":\"%s\","
             "\"expected_state\":%d,"
             "\"health_status\":%d,"
             "\"http_enabled\":%d,"
             "\"http_path\":\"%s\","
             "\"http_status\":%d,"
             "\"http_expected_status\":%d,"
             "\"http_health_status\":%d,"
             "\"http_response_ms\":%ld,"
             "\"http_error_stage\":\"%s\","
             "\"http_error_code\":%d,"
             "\"http_anomaly_type\":%d,"
             "\"http_consecutive_abnormal\":%d,"
             "\"http_anomaly_message\":\"%s\""
            "}",
            (i == 0 ? "" : ","),
            r->scan.time_str,
            r->scan.ip,
            r->scan.port,
            r->scan.result,
            r->scan.response_ms,
            r->anomaly.anomaly_type,
            r->anomaly.message,
            r->expected_state,
            r->health_status,
            r->http_enabled,
            r->http_path,
            r->http.http_status,
            r->http_expected_status,
            r->http_health_status,
            r->http.response_ms,
            r->http.error_stage ? r->http.error_stage : "unknown",
            r->http.error_code,
            r->http_anomaly.anomaly_type,
            r->http_anomaly.consecutive_abnormal,
            r->http_anomaly.message
        );

        // バッファあふれを防ぐため、残量が少なくなったら生成を打ち切る
        if (offset >= (int)sizeof(body) - 512) {
            break;
        }
    }

    // JSON配列の終了
    offset += snprintf(body + offset, sizeof(body) - offset, "]");

    // JSON生成が終わったので共有データのロックを解除する
    pthread_mutex_unlock(&shared_status->mutex);

    // application/json としてクライアントへ返す
    dprintf(client_sock,
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json; charset=UTF-8\r\n"
            "Content-Length: %d\r\n"
            "Connection: close\r\n"
            "\r\n"
            "%s",
            offset, body);
}

/* Independent auth feed: /api/status remains a legacy JSON array. */
static void send_auth_json(int client_sock) {
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0) return;
    const int64_t now_ms = (int64_t)now.tv_sec * INT64_C(1000) +
                           now.tv_nsec / 1000000;
    AuthStatusSummary status;
    (void)auth_status_read(
        ((getenv("NM_AUTH_TSV") && getenv("NM_AUTH_TSV")[0]) ? getenv("NM_AUTH_TSV") : "data/auth-normalized.tsv"),
        now_ms, &status);
    (void)auth_status_apply_poll_heartbeat(
        &status,
        ((getenv("NM_AUTH_HEARTBEAT") && getenv("NM_AUTH_HEARTBEAT")[0]) ? getenv("NM_AUTH_HEARTBEAT") : "data/poll-heartbeat.txt"),
        now_ms);
    char body[512];
    auth_status_to_json(&status, body, sizeof(body));
    dprintf(client_sock,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json; charset=UTF-8\r\n"
        "Cache-Control: no-store\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n%s",
        strlen(body), body);
}

/*
 * 未定義のパスに対して 404 Not Found を返す
 */
static void send_404(int client_sock) {
    const char* body = "<html><body><h1>404 Not Found</h1></body></html>";

    dprintf(client_sock,
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n"
            "\r\n"
            "%s",
            strlen(body), body);
}
