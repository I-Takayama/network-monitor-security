#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "config.h"

/*
 * 設定ファイルを読み込み、Config構造体に値を格納する関数
 *
 * 【仕様】
 * - "key=value" 形式のテキストを1行ずつ解析
 * - 対応するキーに応じてConfig構造体に値をセット
 *
 * 【設計意図】
 * - 設定をコードから分離し、再ビルドなしで変更可能にする
 * - シンプルなフォーマットにすることで可読性と保守性を確保
 */
int load_config(const char* filename, Config* config) {

    // ファイルポインタ
    if (config == NULL) {
        return -1;
    }

    memset(config, 0, sizeof(*config));
    config->expected_state = EXPECT_OPEN;
    config->http_port = 0;
    config->http_expected_status = 200;
    strcpy(config->http_path, "/health");

    FILE* fp = fopen(filename, "r");

    // 1行読み込み用バッファ
    char line[256];

    // ファイルオープン失敗時
    if (fp == NULL) {
        perror("fopen");
        return -1;
    }

    // ファイルを1行ずつ読み込む
    while (fgets(line, sizeof(line), fp)) {

        // キーと値を格納するバッファ
        char key[128];
        char value[128];

        /*
         * "key=value" の形式を解析
         * %[^=]  : '=' までをキーとして取得
         * %s     : 値を取得
         */
        if (sscanf(line, "%127[^=]=%127s", key, value) != 2) {
            // フォーマット不正な行は無視
            continue;
        }

        // 各キーに応じてConfig構造体へ値を設定

        if (strcmp(key, "ip") == 0) {

            // 文字列コピー（バッファオーバーフロー対策）
            strncpy(config->ip, value, sizeof(config->ip) - 1);
            config->ip[sizeof(config->ip) - 1] = '\0';

        } else if (strcmp(key, "start_port") == 0) {

            // 開始ポート番号
            config->start_port = atoi(value);

        } else if (strcmp(key, "end_port") == 0) {

            // 終了ポート番号
            config->end_port = atoi(value);

        } else if (strcmp(key, "interval") == 0) {

             // 監視間隔（秒）
            config->interval = atoi(value);

        } else if (strcmp(key, "web_port") == 0) {

            // Webサーバのポート番号
            config->web_port = atoi(value);

        } else if (strcmp(key, "http_port") == 0) {
            char* endptr = NULL;
            errno = 0;
            long value_port = strtol(value, &endptr, 10);
            if (*value == '\0' || *endptr != '\0' || errno != 0 ||
                value_port < 0 || value_port > 65535) {
                fprintf(stderr, "Invalid http_port: %s\n", value);
                fclose(fp);
                return -1;
            }
            config->http_port = (int)value_port;
        } else if (strcmp(key, "http_expected_status") == 0) {
            char* endptr = NULL;
            errno = 0;
            long expected = strtol(value, &endptr, 10);
            if (*value == '\0' || *endptr != '\0' || errno != 0 ||
                expected < 100 || expected > 599) {
                fprintf(stderr, "Invalid http_expected_status: %s\n", value);
                fclose(fp);
                return -1;
            }
            config->http_expected_status = (int)expected;
        } else if (strcmp(key, "http_path") == 0) {
            const char* allowed =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/_-.";
            if (value[0] != '/' ||
                strlen(value) >= sizeof(config->http_path) ||
                strspn(value, allowed) != strlen(value)) {
                fprintf(stderr, "Invalid http_path: %s\n", value);
                fclose(fp);
                return -1;
            }
            strcpy(config->http_path, value);
        } else if (strncmp(key, "expected_state_", 15) == 0) {
            const char* port_text = key + 15;
            char* endptr = NULL;

            errno = 0;
            long port_value = strtol(port_text, &endptr, 10);

            if (*port_text == '\0' || *endptr != '\0' ||
                errno != 0 || port_value < 1 || port_value > 65535) {
                fprintf(stderr, "Invalid port policy key: %s\n", key);
                fclose(fp);
                return -1;
            }

            int policy;

            if (strcmp(value, "OPEN") == 0) {
                policy = EXPECT_OPEN;
            } else if (strcmp(value, "CLOSED") == 0) {
                policy = EXPECT_CLOSED;
            } else if (strcmp(value, "OBSERVE_ONLY") == 0) {
                policy = OBSERVE_ONLY;
            } else {
                fprintf(stderr, "Invalid port policy: %s\n", value);
                fclose(fp);
                return -1;
            }

            for (int j = 0; j < config->port_policy_count; j++) {
                if (config->port_policies[j].port == (int)port_value) {
                    fprintf(stderr, "Duplicate port policy: %ld\n",
                            port_value);
                    fclose(fp);
                    return -1;
                }
            }

            if (config->port_policy_count >= MAX_PORT_EXPECTATIONS) {
                fprintf(stderr, "Too many port policies\n");
                fclose(fp);
                return -1;
            }

            int index = config->port_policy_count++;
            config->port_policies[index].port = (int)port_value;
            config->port_policies[index].expected_state = policy;
        } else if (strcmp(key, "expected_state") == 0) {
            if (strcmp(value, "OPEN") == 0) {
                config->expected_state = EXPECT_OPEN;
            } else if (strcmp(value, "CLOSED") == 0) {
                config->expected_state = EXPECT_CLOSED;
            } else if (strcmp(value, "OBSERVE_ONLY") == 0) {
                config->expected_state = OBSERVE_ONLY;
            } else {
                fprintf(stderr, "Invalid expected_state: %s\n", value);
                fclose(fp);
                return -1;
            }
        }
    }

    fclose(fp);
    return 0;
}
int get_expected_state_for_port(const Config* config, int port) {
    if (config == NULL) {
        return EXPECT_OPEN;
    }

    for (int i = 0; i < config->port_policy_count; i++) {
        if (config->port_policies[i].port == port) {
            return config->port_policies[i].expected_state;
        }
    }

    return config->expected_state;
}