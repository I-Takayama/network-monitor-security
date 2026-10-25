#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "scanner.h"
#include "utils.h"

/*
 * 指定したIPアドレス・ポートにTCP接続を試み、
 * ポートの開閉状態と応答時間を取得する
 *
 * 戻り値:
 *   1  : OPEN
 *   0  : CLOSED
 *  -1  : ERROR
 */
int scan_port(const char* ip, int port, ScanResult* scan_result){
    int sockfd;
    struct sockaddr_in server;
    struct timeval start, end;

    // 結果構造体に対象情報を保存しておく
    strncpy(scan_result->ip, ip, sizeof(scan_result->ip) - 1);
    scan_result->ip[sizeof(scan_result->ip) - 1] = '\0';
    scan_result->port = port;
    scan_result->error_stage = ERROR_STAGE_NONE;
    scan_result->error_code = 0;
    get_current_time_str(scan_result->time_str, sizeof(scan_result->time_str));

    // 接続開始時刻を取得し、応答時間計測に使用する
    gettimeofday(&start, NULL);

    // TCPソケットを生成する
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0){
        scan_result->error_stage = ERROR_STAGE_SOCKET;
        scan_result->error_code = errno;
        perror("socket");
        scan_result->result = -1;
        scan_result->response_ms = -1;
        return -1;
    }

    // 接続先アドレス情報を初期化する
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    // 文字列のIPアドレスをバイナリ形式へ変換する
    int conversion_result = inet_pton(AF_INET, ip, &server.sin_addr);
    if (conversion_result <= 0) {
        scan_result->error_stage = ERROR_STAGE_IP_CONVERSION;
        scan_result->error_code = (conversion_result == 0) ? 0 : errno;
        if (conversion_result == 0) {
            fprintf(stderr, "inet_pton: invalid IPv4 address\n");
        } else {
            perror("inet_pton");
        }
        close(sockfd);
        scan_result->result = -1;
        scan_result->response_ms = -1;
        return -1;
    }

    // TCP接続を試み、失敗した場合は CLOSED と判定する
    if (connect(sockfd, (struct sockaddr *)&server, sizeof(server)) < 0) {
        scan_result->error_stage = ERROR_STAGE_CONNECT;
        scan_result->error_code = errno;
        gettimeofday(&end, NULL);

        // 接続試行にかかった時間をミリ秒単位で計算する
        scan_result->response_ms = (end.tv_sec - start.tv_sec) * 1000L
                                 + (end.tv_usec - start.tv_usec) / 1000L;
        close(sockfd);
        scan_result->result = 0;
        return 0;
    }

    // 接続成功時も応答時間をミリ秒単位で計算する
    gettimeofday(&end, NULL);
    scan_result->response_ms = (end.tv_sec - start.tv_sec) * 1000L
                             + (end.tv_usec - start.tv_usec) / 1000L;

    close(sockfd);
    scan_result->result = 1;
    return 1;
}

/*
 * スキャン結果をターミナルに表示する
 * result の値に応じて OPEN / CLOSED / ERROR を切り替える
 */
void print_result(const ScanResult* scan_result){
    if(scan_result->result == 0){
        printf("[%s] %s:%d -> CLOSED (%ld ms)\n",
               scan_result->time_str,
               scan_result->ip,
               scan_result->port,
               scan_result->response_ms);
    }else if(scan_result->result == 1){
        printf("[%s] %s:%d -> OPEN (%ld ms)\n",
               scan_result->time_str,
               scan_result->ip,
               scan_result->port,
               scan_result->response_ms);
    }else{
        printf("[%s] %s:%d -> ERROR (%ld ms)\n",
               scan_result->time_str,
               scan_result->ip,
               scan_result->port,
               scan_result->response_ms);
    }
}