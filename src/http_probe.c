#define _POSIX_C_SOURCE 200809L
#include "http_probe.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* 単調増加クロックで経過時間を測定 */
static long long mono_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) return -1;
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static int fail(HttpProbeResult *out, const char *stage, int code,
                long long started) {
    out->error_stage = stage;
    out->error_code = code;
    long long now = mono_ms();
    if (started >= 0 && now >= started)
        out->response_ms = (long)(now - started);
    return -1;
}

/* 指定期限までソケットの通信準備を待つ */
static int wait_for(int fd, short events, long long deadline) {
    for (;;) {
        long long remaining = deadline - mono_ms();
        if (remaining <= 0) {
            errno = ETIMEDOUT;
            return -1;
        }

        struct pollfd pfd = {
            .fd = fd, .events = events, .revents = 0
        };

        int n = poll(&pfd, 1, (int)remaining);
        if (n > 0) return 0;
        if (n == 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        if (errno != EINTR) return -1;
    }
}

int http_probe_get(const char *ipv4, int port, const char *path,
                   int timeout_ms, HttpProbeResult *out) {
    if (!out) return -1;

    *out = (HttpProbeResult){
        .http_status = 0,
        .response_ms = -1,
        .error_code = 0,
        .error_stage = "none"
    };

    if (!ipv4 || !path || path[0] != '/' ||
        strpbrk(path, "\r\n \t") ||
        port < 1 || port > 65535 ||
        timeout_ms < 1 || timeout_ms > 60000) {
        return fail(out, "input", EINVAL, -1);
    }

    long long started = mono_ms();
    if (started < 0)
        return fail(out, "clock", errno, -1);

    long long deadline = started + timeout_ms;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        return fail(out, "socket", errno, started);

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);

    if (inet_pton(AF_INET, ipv4, &addr.sin_addr) != 1) {
        close(sock);
        return fail(out, "input", EINVAL, started);
    }

    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0 ||
        fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        int e = errno;
        close(sock);
        return fail(out, "socket", e, started);
    }

    /* タイムアウト付きTCP接続 */
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        if (errno != EINPROGRESS) {
            int e = errno;
            close(sock);
            return fail(out, "connect", e, started);
        }

        if (wait_for(sock, POLLOUT, deadline) < 0) {
            int e = errno;
            close(sock);
            return fail(out, "connect", e, started);
        }

        int so_error = 0;
        socklen_t sl = sizeof(so_error);

        if (getsockopt(sock, SOL_SOCKET, SO_ERROR,
                       &so_error, &sl) < 0 || so_error) {
            int e = so_error ? so_error : errno;
            close(sock);
            return fail(out, "connect", e, started);
        }
    }

    /* GETリクエストを生成 */
    char request[512];
    int req_len = snprintf(
        request, sizeof(request),
        "GET %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Connection: close\r\n\r\n",
        path, ipv4, port
    );

    if (req_len < 0 || (size_t)req_len >= sizeof(request)) {
        close(sock);
        return fail(out, "input", EMSGSIZE, started);
    }

    /* 部分送信にも対応 */
    size_t sent = 0;

    while (sent < (size_t)req_len) {
        if (wait_for(sock, POLLOUT, deadline) < 0) {
            int e = errno;
            close(sock);
            return fail(out, "send", e, started);
        }

        ssize_t n = send(
            sock, request + sent,
            (size_t)req_len - sent, MSG_NOSIGNAL
        );

        if (n < 0 && (errno == EAGAIN || errno == EINTR))
            continue;

        if (n <= 0) {
            int e = n == 0 ? EPIPE : errno;
            close(sock);
            return fail(out, "send", e, started);
        }

        sent += (size_t)n;
    }

    /* HTTPレスポンスヘッダーを受信 */
    char header[8192];
    size_t used = 0;

    for (;;) {
        if (used == sizeof(header) - 1) {
            close(sock);
            return fail(out, "parse", EMSGSIZE, started);
        }

        if (wait_for(sock, POLLIN, deadline) < 0) {
            int e = errno;
            close(sock);
            return fail(out, "receive", e, started);
        }

        ssize_t n = recv(
            sock, header + used,
            sizeof(header) - 1 - used, 0
        );

        if (n < 0 && (errno == EAGAIN || errno == EINTR))
            continue;

        if (n <= 0) {
            int e = n == 0 ? EPROTO : errno;
            close(sock);
            return fail(out, "receive", e, started);
        }

        used += (size_t)n;
        header[used] = '\0';

        if (strstr(header, "\r\n\r\n"))
            break;
    }

    close(sock);

    /* HTTPステータスコードを解析 */
    int major, minor, status;

    if (sscanf(header, "HTTP/%d.%d %d",
               &major, &minor, &status) != 3 ||
        major != 1 ||
        (minor != 0 && minor != 1) ||
        status < 100 || status > 599) {
        return fail(out, "parse", EPROTO, started);
    }

    out->http_status = status;
    out->response_ms = (long)(mono_ms() - started);

    return 0;
}
