# v0.2.0 中央運用の導入・監査・復旧

この版はリポジトリの実装です。実際の EC2 / AWS への導入と配送確認は別途行います。構成は商用 AWS の単一アカウント・リージョン向けです。監視対象は1スタック50台まで、月次対象は1〜8個のロググループです。

## 保存されるもの

| 保存先 | 内容・期間 |
| --- | --- |
| CloudWatch Logs | Windows Security / System / PowerShell Operational / Firewall、Ubuntu 認証専用ファイル / auditd、5分毎の heartbeat。各400日。Agent が転送したイベントが対象 |
| S3 `raw/` | Firehose が受信した CloudWatch subscription の gzip データ。日付プレフィックスは UTC。月次出力とは別経路 |
| S3 `monthly/` | 毎月1日18:00 **JST** に前月の JST 月初〜翌月初を export。4日18:00に再出力して遅延到着を補正。gzip、オブジェクト別 SHA-256 / バージョン / KMS / 保持期限、JSON manifest、HTMLレポート |
| S3 `evidence/` 等 | 検知の原本、通知、隔離前後の全 ENI と SG、復旧記録、配送失敗の原本、月次失敗情報 |
| DynamoDB | 月次チェックポイント、隔離前の構成、インシデント・確認状態。運用記録は450日、重複排除等は短期間 |

S3 はバージョニング、非公開、SSE-KMS、Object Lock **COMPLIANCE 400日**。90日後に Glacier、450日後に削除対象となります。保持中は正管理者でも削除できません。KMSキーの無効化・削除は復号を妨げるため別途保護します。ローカル OS ログは容量制限があり1年保持ではありません。中央配送が導入・稼働して初めて400日保存になります。Ubuntu journal 全文、アプリケーション独自ログ、CloudTrail 原本、VPC Flow Logs、GuardDuty の未検知イベントはこのテンプレートの収集対象外です。必要な追加ソースは正管理者と設定してください。

月次 COMPLETE は gzip 整合性等の検証成功を意味し、送信前のログ欠落がない証明ではありません。空期間や月途中作成は警告を記録し、heartbeat と raw データ、元ストリームの照合が必要です。4日より遅れて到着したログは手動で再出力します。月次処理はアカウントの export 同時実行制限を尊重し、48時間でタイムアウトします。大きすぎるファイルは検証を失敗させます。`ExportWindowHours` を24から12/6に変更して再実行してください。

## 通知と自動対応

| 優先度 | 条件と対応 |
| --- | --- |
| P1 | 承認済み重大 GuardDuty 検知、監査無効化・ログ消去・監査ポリシー変更、Windows アカウント／特権グループ変更、CloudTrail 停止・削除、KMS 無効化・削除予約、中央保存保護の変更、隔離失敗／構成逸脱。SNS通知と証拠保存 |
| P2 | 同一ホスト・送信元・ユーザーで5分固定窓10回以上の認証失敗、過去3窓の失敗後の成功、Ubuntu監査対象ファイル変更、heartbeat15分欠落、サービス停止、audit lost、空き容量10%未満10分継続、月次失敗／期限超過、権限不足 UNKNOWN。通知 |
| P3 | 月次処理の完了。警告と manifest を確認 |
| CloudWatch Alarm | Lambda失敗、Logs配送エラー、Firehose鮮度15分超、DLQ滞留。既存 SNS に通知 |

P1未確認は5分毎の巡回で15分後から再通知、30分後からエスカレーションします。SNSには識別情報と証拠参照を載せ、詳細ログはS3に保存します。SNS 配送成功は担当者が読んだ証明ではありません。正管理者・副管理者など複数の確認済み購読者を準備し、実際の通知配送を試験します。自動電話や SMS の構成は含みません。

**自動隔離するのは GuardDuty の承認済み種類・severity 7以上・更新30分以内の EC2 検知だけ**です。GuardDuty APIで原本を再確認します。対象タグ `SecurityResponse=auto-isolate` が必要で、`SecurityProtected=true`、ASG、管理対象 ENI は除外します。侵害認定は管理者が行います。OSの認証失敗や AWS 設定変更だけで自動遮断しません。

全 ENI の SG を正管理者が用意した同一 VPC の隔離 SG に置換します。隔離 SG は `SecurityIsolation=approved`、受信ルール無し、送信は承認済み private endpoint SG 宛の TCP443のみです。インターネット宛 CIDR・prefix list を許可しません。事前証拠を保存できなければ変更しません。元の SG は残します。停止・終了、共有 SG の変更は行いません。SG の追跡済み接続は変更後も残ることがあるため、即時完全遮断の保証ではありません。必要なら正管理者が別途 NACL 等の対応を判断します。

## 正管理者が準備するもの

* GuardDuty、組織の CloudTrail、既存 KMSキー、確認済み SNS topic、同一リージョンの配布用 S3 bucket。
* 既存 IAM role 8個。`scripts/aws/render_role_policies.py` が追加ポリシー・trust・KMS/SNS policy断片を生成します。**既存ポリシーを丸ごと置き換えず**、正管理者が最小権限で統合します。削除権限は要求しません。
* EC2 Agent 用既存 instance role の Logs 作成済みストリームへの送信権限。Agent のインストールと転送設定。
* 既存の private SSM / Logs endpoint と隔離 SG。検知種類、対象インスタンスタグ、対象 ENI ARN を明示して承認。ENI交換時は IAM 許可も更新。
* 副管理者の change set 作成／実行、既存ロールへの限定 `iam:PassRole`、コード／テンプレートの S3 Put、監査用読み取り権限。復旧・再開用 Lambda Invoke と確認／停止用 DynamoDB 操作は、実行者に個別付与。
* CloudTrail に復旧／再開 Lambda Invoke とインシデント確認 DynamoDB の data event を追加。JSONの `reported_approver` は実行者証明ではありません。

権限不足は UNKNOWN / 失敗として証拠に残します。IAM の作成可否から削除可否を推測しません。SCP、permission boundary、KMS policy、resource policy の制限も別途確認します。

## 導入

1. OSのベースラインを[既存手順](runbook.md)で適用・監査します。試験 EC2 から開始します。
2. release の Lambda ZIP と全ソース ZIP を取得し `SHA256SUMS.txt` を検証します。配布用既存 bucket の変更されない新しいキーに Lambda ZIP を配置します。
3. `config/deployment.example.json` を `config/deployment.local.json` にコピーし、全 placeholder を実値に変更します。使わない OS グループは `ActiveLogGroups` から除きます。`FindingTypes` は組織が承認した GuardDuty EC2 finding types をカンマ区切りで指定します。
4. `python3 scripts/aws/render_role_policies.py --config config/deployment.local.json --output .deployment/policies` を実行し、正管理者が既存 role / key / topic に統合します。人の復旧権限を自動応答 role に付与しないでください。
5. 既に `/ec2/security/*` グループが存在する場合は CloudFormation の **resource import** で取り込む構成を準備してください。新規作成との衝突は導入失敗になります。既存グループやログを削除して回避しないでください。subscription は各グループ2本を使用します。既存の2本使用済みの場合は先に構成を調整します。
6. `python3 -m pip install boto3` を管理端末の専用環境に導入します。
7. `python3 scripts/aws/deploy.py --config config/deployment.local.json` で変更セットだけ作成し、リソース・保持ロック・対象・権限を確認します。出力された変更セット ARN を AWS CLI `cloudformation execute-change-set` で実行します。`--execute` は作成した変更セットを明示実行するオプションです。
8. [CloudWatch設定](cloudwatch.md)を使用し、**全ストリーム名を instance ID に統一**します。Agentを起動し、Security等のWindowsイベントXML形式を実機確認してください。
9. Ubuntu: `sudo python3 scripts/ubuntu/schedule_heartbeat.py apply`。Windows: `ScheduleHeartbeat.ps1 -Mode Apply`。ファイルは管理者以外から書けない場所に配置します。OS Apply 済みの状態ディレクトリを利用します。
10. `python3 scripts/aws/audit_operations.py --config config/deployment.local.json --output reports/operations-install` で JSON / HTML / SHA-256 の導入証拠を収集します。読み取り不足は UNKNOWN、配送の実機確認は常に手動項目です。

## 日次と異常時

日次は OS `Daily` / `daily`、AWS 読み取り監査、中央運用監査を実行し、SNS未確認、heartbeat、raw到着、月次manifestを確認します。5分毎の巡回は専用 Scheduler によって自動実行されます。DLQ は14日なので巡回処理が原本をS3に退避します。巡回自体が止まった場合は滞留アラームを人が対応します。

以下の CLI 共通部分は `python3 scripts/aws/operations.py --profile deputy --region ap-northeast-1 --prefix awsec2config` です。

* `ack --incident-id ID`: 担当者の確認記録。
* `restore --instance-id i-... --incident-id ID`: 元構成への復旧プレビュー。証拠を確認し、`--execute` で実行。現在の構成が記録と異なる場合は停止します。
* `resume-isolation --instance-id i-... --incident-id ID`: 途中失敗した隔離の再開プレビュー。`--execute` でも GuardDuty、タグ、SG、元／隔離状態を再検証します。
* `restart-month --month 2026-09 --revision correction`: 過去月の補正処理。稼働中の処理に割り込まず、旧成果は保持します。
* `pause`: 停止内容のプレビュー。`pause --execute` は自動隔離の制御フラグを先に停止し、専用スケジュール3個と GuardDuty rule を無効化します。進行中の月次workflowやログ配送は継続します。

再開時は正管理者が停止理由を解消し、専用 scheduler と rule を再有効化してから `CONTROL#response.enabled=true` に戻します。進行中処理を止める必要がある場合は対象 execution ARN を確認して停止します。保存済みログや IAM を削除する操作は停止手順に含みません。

OS復元は既存の Restore 手順を使い、heartbeat は `schedule_heartbeat.py restore` / `ScheduleHeartbeat.ps1 -Mode Restore` でプレビュー後に明示実行します。元の監査ログと保存証拠は保持します。AWS側の復元は自動隔離の復旧と専用監視停止であり、ログ保持を解除する操作ではありません。

## 本番前の受け入れ

検証 EC2 で失敗ログ・成功ログ・heartbeatを生成し、CloudWatch、S3 raw、SNS実配送を確認します。隔離は本物の承認対象検知または組織の試験手順で行い、全 ENI の置換・証拠・SSM経路・既存接続の残存・人の復旧を確認します。副管理者の一部権限を外し、UNKNOWNと部分失敗が隠れないことも確認します。前月試験データのgzipと元ストリーム件数／時間範囲を照合します。自動テストは模擬API・SDK契約・構文の検証で、実AWSへの配送やOS設定変更の実機試験ではありません。
