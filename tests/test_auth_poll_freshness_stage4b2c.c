#define _POSIX_C_SOURCE 200809L
#include "auth_status.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static void write_file(const char *path, const char *content) {
    FILE *f = fopen(path, "w");
    assert(f);
    assert(fputs(content, f) >= 0);
    assert(fclose(f) == 0);
}
static void file_time(const char *path, time_t seconds) {
    struct timespec ts[2];
    ts[0].tv_sec = ts[1].tv_sec = seconds;
    ts[0].tv_nsec = ts[1].tv_nsec = 0;
    assert(utimensat(AT_FDCWD, path, ts, 0) == 0);
}
int main(void) {
    char base[] = "/tmp/authpoll-test-XXXXXX";
    assert(mkdtemp(base));
    char log[200], heartbeat[200];
    snprintf(log, sizeof(log), "%s/log.tsv", base);
    snprintf(heartbeat, sizeof(heartbeat), "%s/poll-heartbeat.txt", base);
    time_t now = time(NULL);
    char body[256];
    snprintf(body, sizeof(body), "%lld\t1\t192.0.2.11\tuser\n",
             (long long)(now-40)*1000);
    write_file(log, body);
    file_time(log, now-30);
    AuthStatusSummary st;
    assert(auth_status_read(log, (long long)now*1000, &st) == 0);
    assert(auth_status_apply_poll_heartbeat(&st,heartbeat,(long long)now*1000)==0);
    assert(st.available && !st.fresh && !st.invalid);
    puts("PASS no polling evidence means stale");

    write_file(heartbeat, "1\n");
    file_time(heartbeat, now);
    assert(auth_status_read(log, (long long)now*1000, &st) == 0);
    assert(auth_status_apply_poll_heartbeat(&st,heartbeat,(long long)now*1000)==0);
    assert(st.available && st.fresh && st.events == 1);
    char json[512]; auth_status_to_json(&st,json,sizeof(json));
    assert(strstr(json, "\"state\":\"no_alert\""));
    assert(strstr(json, "\"collection_unix_seconds\":"));
    puts("PASS unchanged snapshot with verified poll is fresh");

    write_file(heartbeat, "2\n");
    file_time(heartbeat, now);
    assert(auth_status_read(log, (long long)now*1000, &st) == 0);
    assert(auth_status_apply_poll_heartbeat(&st,heartbeat,(long long)now*1000)<0);
    assert(st.invalid && !st.available);
    puts("PASS inconsistent poll event count is invalid");

    write_file(heartbeat, "1\n");
    file_time(heartbeat, now-130);
    assert(auth_status_read(log, (long long)now*1000, &st) == 0);
    assert(auth_status_apply_poll_heartbeat(&st,heartbeat,(long long)now*1000)==0);
    assert(!st.fresh && st.available);
    puts("PASS old heartbeat is stale");

    file_time(heartbeat, now-40); /* Older than last verified snapshot */
    assert(auth_status_read(log, (long long)now*1000, &st) == 0);
    assert(auth_status_apply_poll_heartbeat(&st,heartbeat,(long long)now*1000)==0);
    assert(!st.fresh);
    puts("PASS heartbeat predating snapshot is stale");

    unlink(log); unlink(heartbeat); rmdir(base);
    puts("AUTH_POLL_FRESHNESS_TESTS=5 PASS");
    return 0;
}
