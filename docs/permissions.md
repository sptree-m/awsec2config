# 権限と正管理者への依頼

AWS の副管理者権限と OS 管理権限は別物です。AWS 権限があっても root / ローカル管理者がなければ導入できません。SCP、Permissions Boundary、セッションポリシー、GPO が優先されます。

| 作業 | 必要な権限 | 不足時 |
| --- | --- | --- |
| Ubuntu 設定・ログ取得 | root、audit 操作権限 | 正管理者が実施／証拠提供 |
| Windows 設定・Security 取得 | ローカル管理者、監査ポリシー操作 | GPO 担当へ依頼 |
| 実行主体確認 | sts:GetCallerIdentity | 接続／認証確認（明示 Deny 下でも ID が返る場合あり） |
| EC2 読み取り | ec2:DescribeInstances, ec2:DescribeSecurityGroups, ec2:DescribeVolumes | UNKNOWN とし読み取り／代替証拠を依頼 |
| CloudTrail 読み取り | cloudtrail:DescribeTrails, cloudtrail:GetTrailStatus, cloudtrail:GetEventSelectors | HomeRegion を含め証拠提供を依頼 |
| CloudWatch 証拠 | logs:DescribeLogGroups, logs:GetLogEvents | 対象 ARN 限定の読み取りを依頼 |
| Agent 送信 | 既存 EC2 ロールの logs:DescribeLogStreams, logs:CreateLogStream, logs:PutLogEvents | 正管理者が既存ロールを準備・関連付け |
| Agent がグループを作る場合 | logs:CreateLogGroup | 本キットでは事前作成を推奨 |

Describe 系の一部は Resource * が必要です。送信／閲覧は対象 ARN に限定します。送信認証はインスタンスプロファイルを使い、長期アクセスキーを OS に保存しません。KMS は Logs のサービスプリンシパルと encryption context を含め正管理者が設計します。

## 正管理者が用意するもの

- 対象アカウント／リージョン／インスタンス、検証 EC2、復旧経路（SSM 等）。
- OS パッケージ、管理権限、GPO との整合。
- 設定例のロググループ、保存期間、KMS、既存送信ロール、NAT／対応 VPC endpoint。
- CloudTrail 管理イベント Read/Write、全対象リージョン、組織 trail／S3 配送、VPC Flow Logs、GuardDuty 等の採否。
- 不正ログオン、ログ消去、設定変更、配送途絶のアラーム、通知先と担当。
- 証拠のアクセス制御、保存期間、必要な改変耐性。

IAM の追加ができても削除できない場合は既存ロール・グループを使います。追加が必要なら作成前に所有者と廃止手順を決めます。本キットは IAM、ロググループ、trail、ロール関連付けを作成・削除しません。OS 復元でも中央ログを削除せず、AWS 側の廃止は正管理者の別作業です。
