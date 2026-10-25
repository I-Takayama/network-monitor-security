# 運用手順・トラブルシューティング

## 1. このリポジトリだけで実行する場合

Linux環境で、GCC・makeが利用できることを確認する。

```bash
cp data/config.example.txt data/config.txt
make
```

`data/config.txt` の監視先・ポートを、実際に動作しているローカルの検証サービスに合わせる。

```bash
./monitor
```

起動はリポジトリのルートディレクトリから行う。停止する場合は、起動した端末で `Ctrl+C` を使用する。

画面例：

```text
http://127.0.0.1:8082/
```

このURLはサンプル設定を使用した場合。ポートを変更したらURLも変更する。

## 2. 模擬金融APIを使う開発環境での実行

模擬金融APIは本リポジトリに未同梱。別途FastAPIのプロジェクトを用意する。

Ubuntu側：

```bash
cd /path/to/financial-api
source .venv/bin/activate
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

WSL側でSSHトンネルを作成する例：

```bash
ssh -N -o ExitOnForwardFailure=yes \
    -L 127.0.0.1:18000:127.0.0.1:8000 \
    ubuntu-user@vm-address
```

別のWSL端末で接続確認する。

```bash
curl -i http://127.0.0.1:18000/health
```

HTTP 200を確認してからC監視ツールを起動する。トンネルを閉じると接続監視は失敗する。APIの停止・ネットワーク切断・監視サーバ停止はそれぞれ別の事象。

## 3. 認証監視の入力

公開候補は認証ログの取得器を同梱していない。外部収集器が次の2ファイルを用意する前提となる。

- 正規化TSV：各行は `epoch_ms`, `failure_flag`, `source_ip`, `username` の4列（TAB区切り）
- heartbeat：取り込み済みイベント件数1行。更新時刻は収集成功時刻として扱う

```bash
export NM_AUTH_TSV="/path/to/private/auth-normalized.tsv"
export NM_AUTH_HEARTBEAT="/path/to/private/poll-heartbeat.txt"
./monitor
```

両ファイルにはアクセス制限を設け、Git管理から除外する。

自動収集システムを再現したい場合は、SSH鍵・収集器・スケジューラを別途構築する必要がある。今回のGitHub候補だけで自動取得は開始されない。

## 4. 異常時の確認表

| 症状 | 確認すること |
|---|---|
| ダッシュボードに接続できない | C監視プロセスが稼働しているか、`web_port` が正しいか |
| TCPがCLOSED | サービス稼働、SSHトンネル、対象ポート、ファイアウォール |
| TCP正常・HTTP異常 | HTTPパス、期待コード、API処理、応答遅延 |
| HTTP欄が `—` | `http_port` が有効か、監視対象範囲内か |
| 認証 `unavailable` | TSVの存在・権限・環境変数 |
| 認証 `invalid` | TSVの書式、日時順、heartbeatの件数 |
| 認証 `stale` | 収集成功時刻、収集タスクの成否、TSVの更新状況 |
| 認証 `no_alert` | 収集がfreshで、現在有効な集中警告がない |

`no_alert` は、攻撃が存在しないことの証明ではない。

## 5. 開発環境での定期収集

2026年10月25日の実験では、Windowsタスクスケジューラによる1分間隔の収集を確認した。ただし、そのPowerShellスクリプトはこのリポジトリに含めていない。

手元の既存開発環境で収集を止める場合：

```powershell
Disable-ScheduledTask -TaskName 'NM-Auth-Poll-1min'
```

再開する場合：

```powershell
Enable-ScheduledTask -TaskName 'NM-Auth-Poll-1min'
```

これらは開発環境に同名タスクが登録済みの場合にのみ使用できる。

## 6. セキュリティ上の注意

- Webサーバをインターネットへ直接公開しない。
- 実際の利用者アカウントや実パスワードで攻撃シミュレーションを行わない。
- SSH秘密鍵、JSONL生ログ、正規化TSV、チェックポイント、収集レポートを公開しない。
- SSHトンネルを経由した接続では、ログに記録される送信元IPが元のクライアントIPを表すとは限らない。
- `stale` と通信障害は異なる。ログ収集の成功が確認できない場合は、監視データを現在の正常状態の根拠として扱わない。
