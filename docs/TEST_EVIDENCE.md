# 検証記録

記録日：2026-10-25

本書は開発時に確認した結果と、公開候補に対する検証を分けて記載する。

## 1. 公開候補 Release 0C：142件合格

| テスト群 | 件数 |
|---|---:|
| TCP異常判定 | 20 |
| ポート期待状態 | 12 |
| TCP Health | 22 |
| HTTP異常検知 | 26 |
| HTTP設定とHealth | 6 |
| HTTP Health | 10 |
| ポート別ポリシー | 13 |
| 認証失敗集中 | 13 |
| 認証ステータスAPI | 5 |
| heartbeat鮮度 | 5 |
| HTTP実通信プローブ | 4 |
| 認証アラートCSV | 6 |
| **合計** | **142** |

実行ログの確認済み結果：

```text
RELEASE_FULL_BUILD=PASS
TOTAL_REGRESSION_CHECKS=142_PASS
RELEASE_AUTH_ENV_OVERRIDE=PASS
RELEASE_WEB_ALERT=PASS
RELEASE_WEB_PII_SUPPRESSION=PASS
RELEASE_WEB_NO_ALERT_AFTER_EXPIRY=PASS
RELEASE_WEB_STALE=PASS
RELEASE_LEGACY_API=PASS
RELEASE_WEB_HTML=PASS
STAGE_RELEASE_0C_COMPLETE=YES
```

ここでの142件には単体・モジュール・HTTP実通信など異なる種類の検証を含む。142件すべてが独立した単体テストという意味ではない。

## 2. 実際のFastAPIと連携した認証検証

- 実際のHTTP 401応答を5回発生させ、認証ログ5件の追記を確認。
- 収集処理で5件を取り込み、C言語の判定器から認証失敗集中警告を生成。
- 送信元IP別とユーザー名別に各1件の警告を検知し、CSVに集約警告1行を記録。
- JSONLの既存部分のSHA-256、チェックポイント、イベント件数の整合性を検証。
- その後の新規1件取り込みと再取得時の重複防止を確認。
- 定期実行による追加1件の自動取得を確認し、合計8件の認証履歴まで検証。

認証CSVの警告発生時刻：

```text
2026-10-25T01:34:04.073Z
```

## 3. 自動収集の検証

WindowsタスクスケジューラとSSH鍵認証で無人取得を検証。

```text
SCHEDULED_NEW_EVENT_INGESTION=PASS
SCHEDULED_REPEAT_NO_DUPLICATE=PASS
SCHEDULED_EXECUTION_SPACING_SECONDS=58.8
ONE_MINUTE_CADENCE=PASS
STAGE4B5H_COMPLETE=YES
```

この結果は当該Windows・WSL・Ubuntu構成での実績であり、すべてのPCで常時動作することを保証するものではない。

## 4. Web表示の確認

隔離環境と実ブラウザで以下を確認。

- `alert` / `no_alert` / `stale` の状態応答
- `/api/status` の既存JSON配列互換性
- 認証APIでの個別IP・ユーザー名の非表示
- TCP監視のOPENと正常Health
- HTTP `/health` の200応答と正常Health
- TCP・HTTP・認証欄のブラウザ表示

実ブラウザでの一時的な測定例：TCP 2ms、HTTP 33ms。固定性能値やベンチマーク値ではない。

## 5. 開発で発生した問題と改善

| 問題 | 原因 | 対応 |
|---|---|---|
| 同じ履歴なのに再取得処理が停止 | CRLFとLFのバイト差 | 改行差と実際の内容差を区別 |
| TSV最終時刻を読めない | PowerShellとAWKの引数解釈 | 引数の影響を受けにくい取得処理へ変更 |
| 追加イベントの日時検証が失敗 | JSON日時の自動型変換 | 元のJSONから日時文字列を抽出 |
| 補助スクリプトを実行できない | WSL側にPythonがない | Bashによる追記処理へ変更 |
| タスク実行時に日本語パスが文字化け | Windows PowerShell 5.1の文字コード解釈 | UTF-8 BOM付き保存へ変更 |
| Webがstaleと表示 | 収集タスクを意図的に停止 | 収集停止を正常と誤判定しないことを確認 |

いずれも既存の認証履歴を保持して原因を切り分けた。問題を完全に起こさない保証ではなく、発生時の復旧と検証方法を得られたことが成果である。

## 6. 未検証・未完成

- 本公開候補からの模擬金融API環境の自動構築
- 本公開候補だけによるWindows自動収集の再現
- 大量ポート・長期間運用時の負荷測定
- 商用環境での検知精度・誤検知率評価
- 攻撃と内部障害を判別するモデルの精度評価
- 完全な原子的状態更新、ログローテーションへの一般対応

## 7. Webサーバの待受アドレス確認

2026年10月25日、公開候補の `src/webserver.c` を確認した。

Webサーバは `AF_INET` を使用し、待受アドレスに
`htonl(INADDR_LOOPBACK)` を指定している。
したがって、ソースコード上はIPv4ループバックアドレス
（127.0.0.1）へのバインドである。

Release 0Eの実行時監査では、WSL環境から待受ソケットの
アドレスを取得できず、`WEB_BIND_SCOPE=UNVERIFIED` となった。
これは全インターフェースでの待受が確認されたという意味ではない。

Windows側のポート転送やファイアウォールを含めた
到達範囲の網羅的な確認は行っていない。
