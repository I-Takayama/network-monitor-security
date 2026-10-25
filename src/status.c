#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "status.h"

/*
 * 共有監視状態（SharedStatus）を初期化する
 * 複数スレッドから参照・更新されるため、結果配列とmutexを用意する
 */
void init_shared_status(SharedStatus* status, int count) {
    // ポート数分の監視結果を保持する配列を確保する
    status->results = malloc(sizeof(MonitorResult) * count);
    if (status->results == NULL) {
        perror("malloc");
        exit(1);
    }
    status->count = count;

    // スレッド間で安全にデータ共有するためのmutexを初期化する
    pthread_mutex_init(&status->mutex, NULL);

    // 初期状態として全要素を0クリアする
    for (int i = 0; i < count; i++) {
        memset(&status->results[i], 0, sizeof(MonitorResult));
    }
}

/*
 * 監視結果を共有状態に反映する
 * 複数スレッドから同時にアクセスされるため、mutexで排他制御を行う
 */
void update_shared_status(SharedStatus* status, int index, const MonitorResult* result) {
    // 共有データ更新のためロック（競合状態防止）
    pthread_mutex_lock(&status->mutex);

    // 指定インデックスに監視結果をコピー
    status->results[index] = *result;

    // ロック解除（他スレッドのアクセスを許可）
    pthread_mutex_unlock(&status->mutex);
}

/*
 * 共有監視状態の後処理
 * 確保したメモリとmutexを解放する
 */
void destroy_shared_status(SharedStatus* status) {
    // 動的確保した結果配列を解放
    free(status->results);

    // mutexを破棄
    pthread_mutex_destroy(&status->mutex);
}