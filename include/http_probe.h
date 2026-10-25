#ifndef HTTP_PROBE_H
#define HTTP_PROBE_H

typedef struct {
    int http_status;
    long response_ms;
    int error_code;
    const char *error_stage;
} HttpProbeResult;

/*
 * IPv4 HTTP GETの監視。
 * response_msはTCP接続開始からHTTPヘッダー受信完了まで。
 * 戻り値：正常なHTTP応答を受信した場合0、通信失敗時-1。
 * HTTP 404や500もHTTP応答としては受信成功(戻り値0)。
 */
int http_probe_get(const char *ipv4, int port, const char *path,
                   int timeout_ms, HttpProbeResult *out);

#endif
