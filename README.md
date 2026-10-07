# awsec2config

EC2 の Windows Server 2025 と Ubuntu 22.04 / 24.04 LTS 向けのログ収集設定・導入監査／日次運用・設定復元の3点セットです。正管理者がいる環境で、副管理者が利用する前提です。

| 系統 | Ubuntu | Windows Server 2025 |
| --- | --- | --- |
| 導入 | `ec2_logging.py apply` | `Ec2Logging.ps1 -Mode Apply` |
| 導入監査／日次運用 | `audit` / `daily` | `-Mode Audit` / `-Mode Daily` |
| 復元 | `restore`（プレビュー）、`restore --execute` | `-Mode Restore`（プレビュー）、`-Mode Restore -Execute` |

ログ収集のベースラインであり、OS 全体の安全保証や侵害なしの証明ではありません。接続許可、アカウント、IAM、CloudTrail は自動変更しません。AWS リソースの作成・削除 API は呼びません。

## はじめに

1. [権限・正管理者への依頼](docs/permissions.md)を確認し、検証用 EC2 で試します。
2. [導入・監査・運用・復元手順](docs/runbook.md)を実施します。
3. 中央保存を使う場合は [CloudWatch 接続手順](docs/cloudwatch.md)を実施します。ローカル導入だけでは転送されません。

### Ubuntu

Python 3.10 以上、root、稼働中の journald / rsyslog / auditd、logrotate が必要です。パッケージは正管理者が事前に準備します。スクリプトはパッケージをインストールしません。

```bash
sudo python3 scripts/ubuntu/ec2_logging.py apply
sudo python3 scripts/ubuntu/ec2_logging.py audit --output /var/lib/awsec2config-reports/install-001
sudo python3 scripts/ubuntu/ec2_logging.py daily --hours 24 --output /var/lib/awsec2config-reports/daily-001
sudo python3 scripts/ubuntu/ec2_logging.py restore
sudo python3 scripts/ubuntu/ec2_logging.py restore --execute
```

永続 journal（最大1GiB、最大30日）、認証ログ専用ファイルとローテート（30世代）、アカウント／sudoers／SSH 設定ファイル変更の auditd ルールを追加します。保存期間は容量によって短くなります。復元しても保存ログは消しません。

### Windows Server 2025

管理者として Windows PowerShell 5.1 で実行します。実行ポリシーは組織の手順で署名／許可し、このキットは変更しません。

```powershell
.\scripts\windows\Ec2Logging.ps1 -Mode Apply
.\scripts\windows\Ec2Logging.ps1 -Mode Audit -OutputDirectory C:\SecurityReports\install-001
.\scripts\windows\Ec2Logging.ps1 -Mode Daily -Hours 24 -OutputDirectory C:\SecurityReports\daily-001
.\scripts\windows\Ec2Logging.ps1 -Mode Restore
.\scripts\windows\Ec2Logging.ps1 -Mode Restore -Execute
```

ログオン・特権ログオン・アカウント管理・監査ポリシー変更・システム整合性の監査を有効化します。Security / System / PowerShell Operational の容量を各256MiBにし、Firewall の許可／拒否ログと ScriptBlockLogging を有効にします。Firewall 自体の有効状態や接続ルールは変更しません。ScriptBlockLogging は新しいプロセスで検証します。PowerShell 7 の専用チャネルは対象外です。

### AWS 読み取り監査

AWS CLI v2 と副管理者の既存プロファイルを使用します。OS とは別に管理端末で実行できます。

```bash
python3 scripts/aws/audit.py --profile deputy --region ap-northeast-1 \
  --instance-id i-0123456789abcdef0 \
  --log-group /ec2/security/ubuntu/auth --log-stream i-0123456789abcdef0 \
  --output reports/aws-001
```

EC2、SG、EBS、CloudTrail、指定 CloudWatch ストリームを監査します。各グループ／ストリームで実行してください。AccessDenied でも他の取得を続け、該当項目は UNKNOWN にします。作成・削除権限をテストするためのリソース作成はしません。

## レポートと終了コード

report.html（一覧）、report.json（コマンド・取得結果）、sha256.json（ファイルハッシュ）を生成します。Windows は時間範囲の EVTX と Firewall ファイル、Ubuntu は認証 journal と認証／audit ログ末尾も保存します。Firewall と末尾ログは全期間の取得ではありません。ハッシュは生成後の改変検知用で、電子署名ではありません。

| 結果 | 意味 |
| --- | --- |
| PASS | 個別の設定・取得・確認成功 |
| FAIL | 設定不一致、停止、既知の問題 |
| UNKNOWN | 権限不足、証拠不足、手動確認が必要 |

終了コード: 0 は処理成功／確認項目成功、1 は処理エラー、2 は FAIL / UNKNOWN あり（レポート生成済み）。侵害判定の UNKNOWN は OS 監査の終了コードから除外します。AWS 監査は CloudTrail 範囲の手動確認があり、収集成功でも2があり得ます。

状態は Ubuntu: /var/lib/awsec2config、Windows: %ProgramData%\awsec2config に保存します。消すと復元できなくなるため保護します。管理者変更との競合は停止します。IAM を追加できても削除できない副管理者に、自動削除を要求しません。

## 検証

```bash
python3 -m unittest discover -s tests -v
```

一時ディレクトリと模擬コマンドで復元・競合・途中失敗・権限不足・SG 公開検出を検証します。実際の OS / AWS での動作と配送は [受け入れ確認](docs/runbook.md#受け入れ確認)が必要です。

PowerShell の構文と状態保存の回帰テスト:

```powershell
.\tests\check_windows.ps1
```

ローカルでは Linux 上の PowerShell 7.4 で構文・状態保存を確認しています。Windows PowerShell 5.1 の同じテストを CI に用意しました。これは Windows の OS 設定を変更する実機試験ではありません。CloudWatch 設定例は JSON 構文確認済みで、Agent 実機検証は別途必要です。
