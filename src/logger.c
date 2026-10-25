#include <stdio.h>
#include <string.h>
#include "scanner.h"
#include "logger.h"


/*
 * 監視結果をCSV形式でファイルに追記する
 * 時系列で記録することで、後から状態変化や異常の分析を可能にする
 */
void log_result(const MonitorResult* result) {
    // 追記モードでファイルを開く（過去ログを保持するため）
    FILE* fp = fopen("data/results.csv", "a");
    if (!fp) {
        perror("fopen");
        return;
    }

    /*
     * CSV形式で1行出力
     * [時刻, IP, ポート, 状態, 応答時間, 異常種別, 異常内容]
     */
    fprintf(fp, "%s,%s,%d,%d,%ld,%d,%s\n",
            result->scan.time_str,          // 計測時刻
            result->scan.ip,                // 対象IPアドレス
            result->scan.port,              // ポート番号
            result->scan.result,            // OPEN / CLOSED / ERROR
            result->scan.response_ms,       // 応答時間（ミリ秒）
            result->anomaly.anomaly_type,   // 異常種別
            result->anomaly.message);       // 異常内容

    // ファイルを閉じてリソースを解放する
    fclose(fp);

    FILE* detail_fp = fopen("data/results-detailed.csv", "a+");
    if (!detail_fp) {
        perror("fopen detailed log");
        return;
    }

    if (fseek(detail_fp, 0, SEEK_END) != 0) {
        perror("fseek detailed log");
        fclose(detail_fp);
        return;
    }

    long file_size = ftell(detail_fp);
    if (file_size < 0) {
        perror("ftell detailed log");
        fclose(detail_fp);
        return;
    }

    if (file_size == 0) {
        fprintf(detail_fp,
                "timestamp,ip,port,status,response_ms,anomaly_type,"
                "anomaly_message,error_stage,error_code,error_reason\n");
    }

    const char* stage = "none";

    switch (result->scan.error_stage) {
        case ERROR_STAGE_SOCKET:
            stage = "socket";
            break;
        case ERROR_STAGE_IP_CONVERSION:
            stage = "inet_pton";
            break;
        case ERROR_STAGE_CONNECT:
            stage = "connect";
            break;
        case ERROR_STAGE_NONE:
            stage = "none";
            break;
        default:
            stage = "unknown";
            break;
    }

    const char* reason = "none";

    if (result->scan.error_stage == ERROR_STAGE_IP_CONVERSION &&
        result->scan.error_code == 0) {
        reason = "invalid IPv4 address";
    } else if (result->scan.error_stage != ERROR_STAGE_NONE) {
        reason = strerror(result->scan.error_code);
    }

    fprintf(detail_fp, "%s,%s,%d,%d,%ld,%d,%s,%s,%d,%s\n",
            result->scan.time_str,
            result->scan.ip,
            result->scan.port,
            result->scan.result,
            result->scan.response_ms,
            result->anomaly.anomaly_type,
            result->anomaly.message,
            stage,
            result->scan.error_code,
            reason);

    fclose(detail_fp);
}
/* Separate HTTP log. Never write HTTP response bodies or credentials. */
void log_http_result(const MonitorResult* result) {
    if (!result->http_enabled) return;

    FILE* fp = fopen("data/results-http.csv", "a+");
    if (!fp) {
        perror("fopen HTTP log");
        return;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        perror("fseek HTTP log");
        fclose(fp);
        return;
    }
    long size = ftell(fp);
    if (size < 0) {
        perror("ftell HTTP log");
        fclose(fp);
        return;
    }
    if (size == 0) {
        fprintf(fp, "timestamp,ip,port,path,http_status,response_ms,"
                    "error_stage,error_code\n");
    }
    fprintf(fp, "%s,%s,%d,%s,%d,%ld,%s,%d\n",
            result->scan.time_str,
            result->scan.ip,
            result->scan.port,
            result->http_path,
            result->http.http_status,
            result->http.response_ms,
            result->http.error_stage ? result->http.error_stage : "unknown",
            result->http.error_code);
    fclose(fp);

    /* Separate verdict log; previous results-http.csv schema is unchanged. */
    FILE* health_fp = fopen("data/results-http-health.csv", "a+");
    if (!health_fp) {
        perror("fopen HTTP health log");
        return;
    }
    if (fseek(health_fp, 0, SEEK_END) != 0) {
        perror("fseek HTTP health log");
        fclose(health_fp);
        return;
    }
    long health_size = ftell(health_fp);
    if (health_size < 0) {
        perror("ftell HTTP health log");
        fclose(health_fp);
        return;
    }
    if (health_size == 0) {
        fprintf(health_fp, "timestamp,ip,port,path,expected_status,"
                           "http_status,http_health_status,response_ms\n");
    }
    fprintf(health_fp, "%s,%s,%d,%s,%d,%d,%d,%ld\n",
            result->scan.time_str, result->scan.ip, result->scan.port,
            result->http_path, result->http_expected_status,
            result->http.http_status, result->http_health_status,
            result->http.response_ms);
    fclose(health_fp);

    /* New anomaly log; existing HTTP and Health CSV schemas are unchanged. */
    FILE* anomaly_fp = fopen("data/results-http-anomaly.csv", "a+");
    if (!anomaly_fp) {
        perror("fopen HTTP anomaly log");
        return;
    }
    if (fseek(anomaly_fp, 0, SEEK_END) != 0) {
        perror("fseek HTTP anomaly log");
        fclose(anomaly_fp);
        return;
    }
    long anomaly_size = ftell(anomaly_fp);
    if (anomaly_size < 0) {
        perror("ftell HTTP anomaly log");
        fclose(anomaly_fp);
        return;
    }
    if (anomaly_size == 0) {
        fprintf(anomaly_fp,
                "timestamp,ip,port,path,http_status,http_health_status,"
                "http_anomaly_type,consecutive_abnormal,response_ms,message\n");
    }
    fprintf(anomaly_fp, "%s,%s,%d,%s,%d,%d,%d,%d,%ld,%s\n",
            result->scan.time_str, result->scan.ip, result->scan.port,
            result->http_path, result->http.http_status,
            result->http_health_status, result->http_anomaly.anomaly_type,
            result->http_anomaly.consecutive_abnormal,
            result->http.response_ms, result->http_anomaly.message);
    fclose(anomaly_fp);
}
