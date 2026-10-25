#define _POSIX_C_SOURCE 200809L
#include "auth_status.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

static void write_events(const char *path, long long now, int count) {
    FILE *f = fopen(path, "w"); assert(f);
    for (int i=0;i<count;i++)
        fprintf(f,"%lld\t1\t192.0.2.1\ttest-user\n",now-4000+i*1000);
    fclose(f);
}
int main(void) {
    char temp[] = "/tmp/stage4b2-XXXXXX";
    int fd=mkstemp(temp); assert(fd>=0); close(fd);
    long long now=(long long)time(NULL)*1000;
    AuthStatusSummary st; char json[512];
    write_events(temp,now,4);
    assert(auth_status_read(temp,now,&st)==0);
    assert(st.available && st.fresh && !st.source_active && !st.username_active);
    puts("PASS four failures no alert");
    write_events(temp,now,5);
    assert(auth_status_read(temp,now,&st)==0);
    assert(st.available && st.fresh && st.source_active==1 && st.username_active==1);
    auth_status_to_json(&st,json,sizeof(json));
    assert(strstr(json,"\"state\":\"alert\""));
    assert(!strstr(json,"192.0.2.1") && !strstr(json,"test-user"));
    puts("PASS fifth failure alert without PII");
    assert(auth_status_read(temp,now+61000,&st)==0);
    assert(st.available && st.fresh && st.source_active==0 && st.username_active==0);
    puts("PASS time-based recovery");
    FILE *f=fopen(temp,"w"); assert(f); fputs("bad-line\n",f); fclose(f);
    assert(auth_status_read(temp,now,&st)!=0 && st.invalid);
    puts("PASS malformed input invalid");
    unlink(temp);
    assert(auth_status_read(temp,now,&st)==0 && !st.available);
    puts("PASS missing file unavailable");
    puts("AUTH_STATUS_STAGE4B2_TESTS=5 PASS");
    return 0;
}
