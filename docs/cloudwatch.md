# CloudWatch 中央保存

ローカル設定と配送は別段階です。config/cloudwatch-*.json は Agent 設定例です。キットは Agent のインストール・設定上書きをしません。既存 Agent は設定と稼働状態を保存し、担当者が既存設定にマージします。全置換は既存監視を失う可能性があります。

## 事前準備

正管理者が公式 Agent、設定例のグループ、保存期間（400日。v0.2.0のCloudFormationで設定、OSスクリプトやAgentは変更しません）、暗号化、既存送信ロール、経路を用意します。IMDSv2 対応 Agent を使います。例には retention_in_days を含めず、Agent に保存期間変更権限を要求しません。

Ubuntu は root で auth / audit を読みます。Windows は Agent のサービスアカウントが Security と Firewall ファイルを読めることを確認します。変更済み Firewall パスは設定例も変更します。ログには機密・個人情報が含まれるので閲覧者を限定します。

## 新規 Agent の設定反映例

元の設定と稼働状態を保存し、承認された設定ファイルを指定します。

```bash
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
  -a fetch-config -m ec2 -s -c file:/absolute/path/cloudwatch-ubuntu.json
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a status
```

```powershell
& "$env:ProgramFiles\Amazon\AmazonCloudWatchAgent\amazon-cloudwatch-agent-ctl.ps1" `
  -a fetch-config -m ec2 -s -c file:C:\ApprovedConfig\cloudwatch-windows.json
& "$env:ProgramFiles\Amazon\AmazonCloudWatchAgent\amazon-cloudwatch-agent-ctl.ps1" -a status
```

Agent の検証ログ・実行ログも確認します。JSON 構文の正しさだけでは Agent スキーマ・配送成功を保証しません。

## 配信証明

Ubuntu で logger -p authpriv.notice に一意のマーカー、Windows の新しい PowerShell 5.1 で Write-Output に同じ用途のマーカーを指定します。ローカル auth／4104と CloudWatch の同じマーカー・日時を照合し、証拠を添付します。Security／auditd は検証環境でログオン・ファイル変更の試験も行います。

AWS 監査の受信時刻は補助証拠です。他のイベントの受信だけでは試験イベントの配送を証明できません。グループごとに対象 EC2 のストリームを指定します。

## 復元時

OS Restore は手動導入 Agent を戻しません。OS 復元前に担当者が元の Agent 設定と稼働状態へ戻します。以前停止していた新規 Agent は停止します。中央グループ・既存ロールは保持します。バックアップがなければ上書きせず正管理者へ相談します。

1年以上の保持、S3継続保管と毎月1日の出力、通知・自動隔離は [v0.2.0運用手順](security-operations.md) を参照してください。
