#include "auth_anomaly.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static int tests = 0;
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x); return 1; } } while (0)
#define RUN(fn) do { if(fn())return 1; tests++; printf("PASS %s\n",#fn); } while(0)

static int test_four_failures_no_alert(void) {
    AuthAnomalyTracker t; auth_anomaly_init(&t); AuthAnomalyResult r;
    for (int i = 0; i < 4; i++) {
        CHECK(auth_anomaly_apply(&t, i*1000, AUTH_FAILURE, "10.0.0.1", "alice", &r)==AUTH_OK);
        CHECK(!r.source_alert && !r.username_alert && !r.source_active);
    }
    return 0;
}
static int test_fifth_failure_alerts_once(void) {
    AuthAnomalyTracker t; auth_anomaly_init(&t); AuthAnomalyResult r;
    for(int i=0;i<6;i++){
        CHECK(auth_anomaly_apply(&t,i*1000,AUTH_FAILURE,"10.0.0.1","alice",&r)==AUTH_OK);
        CHECK(r.source_alert==(i==4)); CHECK(r.username_alert==(i==4));
    }
    CHECK(r.source_active && r.username_active && r.source_failures==5); return 0;
}
static int test_ip_group_diff_users(void) {
    AuthAnomalyTracker t; auth_anomaly_init(&t); AuthAnomalyResult r;
    char user[20];
    for(int i=0;i<5;i++){
        snprintf(user,sizeof user,"u%d",i);
        CHECK(auth_anomaly_apply(&t,i,AUTH_FAILURE,"10.0.0.1",user,&r)==AUTH_OK);
    }
    CHECK(r.source_alert && !r.username_alert); return 0;
}
static int test_user_group_diff_sources(void) {
    AuthAnomalyTracker t; auth_anomaly_init(&t); AuthAnomalyResult r;
    char ip[30];
    for(int i=0;i<5;i++){
        snprintf(ip,sizeof ip,"10.0.0.%d",i+1);
        CHECK(auth_anomaly_apply(&t,i,AUTH_FAILURE,ip,"alice",&r)==AUTH_OK);
    }
    CHECK(!r.source_alert && r.username_alert); return 0;
}
static int test_success_does_not_reset_failures(void) {
    AuthAnomalyTracker t; auth_anomaly_init(&t); AuthAnomalyResult r;
    for(int i=0;i<4;i++)CHECK(auth_anomaly_apply(&t,i*10,AUTH_FAILURE,"a","b",&r)==AUTH_OK);
    CHECK(auth_anomaly_apply(&t,50,AUTH_SUCCESS,"a","b",&r)==AUTH_OK);
    CHECK(!r.source_alert && !r.username_alert);
    CHECK(auth_anomaly_apply(&t,60,AUTH_FAILURE,"a","b",&r)==AUTH_OK);
    CHECK(r.source_alert && r.username_alert); return 0;
}
static int test_recovery_at_boundary(void) {
    AuthAnomalyTracker t; auth_anomaly_init(&t); AuthAnomalyResult r; AuthExpiryResult e;
    for(int i=0;i<5;i++)CHECK(auth_anomaly_apply(&t,i*1000,AUTH_FAILURE,"a","b",&r)==AUTH_OK);
    CHECK(auth_anomaly_tick(&t,59999,&e)==AUTH_OK);
    CHECK(e.source_recoveries==0 && e.username_recoveries==0);
    CHECK(auth_anomaly_tick(&t,60000,&e)==AUTH_OK);
    CHECK(e.source_recoveries==1 && e.username_recoveries==1);
    CHECK(auth_anomaly_tick(&t,60001,&e)==AUTH_OK);
    CHECK(e.source_recoveries==0 && e.username_recoveries==0); return 0;
}
static int test_retrigger_after_recovery(void) {
    AuthAnomalyTracker t; auth_anomaly_init(&t); AuthAnomalyResult r; AuthExpiryResult e;
    for(int i=0;i<5;i++)CHECK(auth_anomaly_apply(&t,i,AUTH_FAILURE,"a","b",&r)==AUTH_OK);
    CHECK(auth_anomaly_tick(&t,61000,&e)==AUTH_OK);
    CHECK(e.source_recoveries==1);
    for(int i=0;i<5;i++)CHECK(auth_anomaly_apply(&t,62000+i,AUTH_FAILURE,"a","b",&r)==AUTH_OK);
    CHECK(r.source_alert && r.username_alert); return 0;
}
static int test_boundary_exactly_60s_excluded(void) {
    AuthAnomalyTracker t; auth_anomaly_init(&t); AuthAnomalyResult r;
    for(int i=0;i<4;i++)CHECK(auth_anomaly_apply(&t,i,AUTH_FAILURE,"a","b",&r)==AUTH_OK);
    CHECK(auth_anomaly_apply(&t,60000,AUTH_FAILURE,"a","b",&r)==AUTH_OK);
    CHECK(!r.source_alert && !r.username_alert);
    CHECK(r.source_failures==4); return 0;
}
static int test_out_of_order_rejected(void) {
    AuthAnomalyTracker t; auth_anomaly_init(&t); AuthAnomalyResult r; AuthExpiryResult e;
    CHECK(auth_anomaly_apply(&t,100,AUTH_FAILURE,"a","b",&r)==AUTH_OK);
    CHECK(auth_anomaly_apply(&t,99,AUTH_FAILURE,"a","b",&r)==AUTH_BAD_INPUT);
    CHECK(auth_anomaly_tick(&t,99,&e)==AUTH_BAD_INPUT);
    CHECK(auth_anomaly_apply(&t,101,AUTH_FAILURE,"a","b",&r)==AUTH_OK);
    CHECK(r.source_failures==2); return 0;
}
static int test_bad_inputs(void) {
    AuthAnomalyTracker t; auth_anomaly_init(&t); AuthAnomalyResult r; char name[90];
    memset(name,'x',sizeof name);name[sizeof name-1]=0;
    CHECK(auth_anomaly_apply(&t,0,2,"a","b",&r)==AUTH_BAD_INPUT);
    CHECK(auth_anomaly_apply(&t,0,AUTH_FAILURE,"","b",&r)==AUTH_BAD_INPUT);
    CHECK(auth_anomaly_apply(&t,0,AUTH_FAILURE,"a\n","b",&r)==AUTH_BAD_INPUT);
    CHECK(auth_anomaly_apply(&t,0,AUTH_FAILURE,"a",name,&r)==AUTH_BAD_INPUT);
    CHECK(auth_anomaly_apply(&t,-1,AUTH_FAILURE,"a","b",&r)==AUTH_BAD_INPUT);
    CHECK(t.last_time_ms == -1); return 0;
}
static int test_capacity_explicit_failure(void) {
    AuthAnomalyTracker t; auth_anomaly_init(&t); AuthAnomalyResult r; char src[32],user[32];
    for(int i=0;i<AUTH_MAX_GROUPS;i++){
        snprintf(src,sizeof src,"192.0.2.%d",i);
        snprintf(user,sizeof user,"account%d",i);
        CHECK(auth_anomaly_apply(&t,i,AUTH_FAILURE,src,user,&r)==AUTH_OK);
    }
    CHECK(auth_anomaly_apply(&t,AUTH_MAX_GROUPS,AUTH_FAILURE,"newip","newuser",&r)==AUTH_CAPACITY_EXCEEDED);
    CHECK(auth_anomaly_apply(&t,AUTH_MAX_GROUPS+1,AUTH_FAILURE,"192.0.2.0","account0",&r)==AUTH_OK);
    CHECK(r.source_failures==2); return 0;
}
static int test_high_rate_bounded_and_recovers(void) {
    AuthAnomalyTracker t; auth_anomaly_init(&t); AuthAnomalyResult r; AuthExpiryResult e;
    int alerts=0;
    for(int i=0;i<300;i++){
        CHECK(auth_anomaly_apply(&t,i,AUTH_FAILURE,"a","b",&r)==AUTH_OK);
        alerts+=r.source_alert;
    }
    CHECK(alerts==1 && r.source_active);
    CHECK(auth_anomaly_tick(&t,60300,&e)==AUTH_OK);
    CHECK(e.source_recoveries==1 && e.username_recoveries==1); return 0;
}
static int test_capacity_reclaimed(void) {
    AuthAnomalyTracker t; auth_anomaly_init(&t); AuthAnomalyResult r; AuthExpiryResult e; char src[30],user[30];
    for(int i=0;i<AUTH_MAX_GROUPS;i++){
        snprintf(src,sizeof src,"ip%d",i);snprintf(user,sizeof user,"u%d",i);
        CHECK(auth_anomaly_apply(&t,i,AUTH_FAILURE,src,user,&r)==AUTH_OK);
    }
    CHECK(auth_anomaly_tick(&t,62000,&e)==AUTH_OK);
    CHECK(auth_anomaly_apply(&t,62001,AUTH_FAILURE,"new","new",&r)==AUTH_OK);
    return 0;
}
int main(void) {
    RUN(test_four_failures_no_alert);RUN(test_fifth_failure_alerts_once);
    RUN(test_ip_group_diff_users);RUN(test_user_group_diff_sources);
    RUN(test_success_does_not_reset_failures);RUN(test_recovery_at_boundary);
    RUN(test_retrigger_after_recovery);RUN(test_boundary_exactly_60s_excluded);
    RUN(test_out_of_order_rejected);RUN(test_bad_inputs);
    RUN(test_capacity_explicit_failure);RUN(test_high_rate_bounded_and_recovers);
    RUN(test_capacity_reclaimed);
    printf("AUTH_STAGE3_TESTS=%d PASS\n",tests);
    return 0;
}
