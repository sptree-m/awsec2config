#!/usr/bin/env python3
"""Read-only AWS evidence collection using AWS CLI v2 and an explicit profile/region."""
import argparse
import datetime as dt
import hashlib
import html
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def exposure(groups):
    exposed = []
    for group in groups:
        for rule in group.get('IpPermissions', []):
            world = any(x.get('CidrIp') == '0.0.0.0/0' for x in rule.get('IpRanges', [])) or any(
                x.get('CidrIpv6') == '::/0' for x in rule.get('Ipv6Ranges', []))
            if world and (rule.get('IpProtocol') == '-1' or
                          rule.get('IpProtocol') in ('tcp', '6') and any(
                              rule.get('FromPort', 65536) <= port <= rule.get('ToPort', -1) for port in (22, 3389))):
                exposed.append({'group_id': group['GroupId'], 'rule': rule})
    return exposed


def collect(args):
    args.output.mkdir(parents=True, mode=0o700, exist_ok=False)
    args.output.chmod(0o700)
    evidence, checks = {}, []
    def check(name, status, detail):
        checks.append({'name': name, 'status': status, 'detail': detail})
    def query(key, command, region=None):
        cmd = ['aws', '--profile', args.profile, '--region', region or args.region,
               '--output', 'json', '--no-cli-pager', *command]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=90,
                                    env={**os.environ, 'AWS_PAGER': ''})
            record = {'command': cmd, 'code': result.returncode, 'stderr': result.stderr}
            if result.returncode == 0:
                record['data'] = json.loads(result.stdout)
            else:
                check(key, 'UNKNOWN', result.stderr.strip() + ' / 正管理者に読み取り権限または代替証拠を依頼')
            evidence[key] = record
            return record.get('data')
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            evidence[key] = {'command': cmd, 'error': str(exc)}
            check(key, 'UNKNOWN', str(exc))
            return None
    identity = query('caller', ['sts', 'get-caller-identity'])
    if identity:
        check('実行主体', 'PASS', identity['Arn'])
    instances = query('instance', ['ec2', 'describe-instances', '--instance-ids', args.instance_id])
    instance = None
    if instances is not None:
        found = [i for r in instances.get('Reservations', []) for i in r.get('Instances', [])]
        if len(found) == 1:
            instance = found[0]
        else:
            check('インスタンス特定', 'UNKNOWN', '1台を特定できませんでした')
    if instance:
        metadata = instance.get('MetadataOptions', {})
        check('IMDSv2 必須', 'PASS' if metadata.get('HttpTokens') == 'required' and metadata.get('State') == 'applied' else 'FAIL', json.dumps(metadata))
        profile = instance.get('IamInstanceProfile')
        check('インスタンスプロファイル', 'PASS' if profile else 'FAIL',
              '関連付けあり。Agent の権限・配信成功は別途確認' if profile else 'CloudWatch 配信には正管理者が既存ロールを関連付け')
        sgids = [x['GroupId'] for x in instance.get('SecurityGroups', [])]
        if sgids:
            groups = query('security-groups', ['ec2', 'describe-security-groups', '--group-ids', *sgids])
            if groups is not None:
                open_rules = exposure(groups['SecurityGroups'])
                check('SSH / RDP 全世界公開', 'FAIL' if open_rules else 'PASS',
                      json.dumps(open_rules) if open_rules else '0.0.0.0/0 と ::/0 の SG ルール確認。経路・NACL は別途確認')
        else:
            check('セキュリティグループ', 'UNKNOWN', 'グループが特定できません')
        volumes = [b['Ebs']['VolumeId'] for b in instance.get('BlockDeviceMappings', []) if 'Ebs' in b]
        if volumes:
            data = query('volumes', ['ec2', 'describe-volumes', '--volume-ids', *volumes])
            if data is not None:
                check('EBS 暗号化', 'PASS' if len(data['Volumes']) == len(volumes) and all(v.get('Encrypted') for v in data['Volumes']) else 'FAIL',
                      json.dumps([{'id': v['VolumeId'], 'encrypted': v.get('Encrypted')} for v in data['Volumes']]))
    trails = query('cloudtrail', ['cloudtrail', 'describe-trails', '--include-shadow-trails'])
    if trails is not None:
        applicable = [t for t in trails.get('trailList', []) if t.get('IsMultiRegionTrail') or t.get('HomeRegion') == args.region]
        if not applicable:
            check('CloudTrail', 'FAIL', '対象リージョンの trail が見つかりません。CloudTrail Lake はこのスクリプトの対象外')
        for index, trail in enumerate(applicable):
            status = query(f'trail-status-{index}', ['cloudtrail', 'get-trail-status', '--name', trail['TrailARN']], trail['HomeRegion'])
            selectors = query(f'trail-selectors-{index}', ['cloudtrail', 'get-event-selectors', '--trail-name', trail['TrailARN']], trail['HomeRegion'])
            if status is not None:
                check(trail['Name'] + ' 稼働', 'PASS' if status.get('IsLogging') and not status.get('LatestDeliveryError') else 'FAIL', json.dumps(status))
            # Selectors are evidence only: advanced selectors require manual coverage assessment.
            check(trail['Name'] + ' 記録範囲', 'UNKNOWN', 'event selectors と配信日時から管理イベントの Read/Write、除外条件、配送先を正管理者が確認')
    if not args.log_group or not args.log_stream:
        check('CloudWatch 配信', 'UNKNOWN', '--log-group と --log-stream に対象インスタンスの実際の送信先を指定してください')
    else:
        data = query('log-groups', ['logs', 'describe-log-groups', '--log-group-name-prefix', args.log_group])
        if data is not None:
            exact = [x for x in data.get('logGroups', []) if x['logGroupName'] == args.log_group]
            check('CloudWatch 保存期間', 'PASS' if exact and exact[0].get('retentionInDays') else 'FAIL', json.dumps(exact))
        events = query('delivery', ['logs', 'get-log-events', '--log-group-name', args.log_group,
                                  '--log-stream-name', args.log_stream, '--limit', '1', '--no-start-from-head'])
        if events is not None:
            records = events.get('events', [])
            now = int(dt.datetime.now(dt.timezone.utc).timestamp() * 1000)
            recent = bool(records) and 0 <= now - records[-1]['ingestionTime'] <= args.hours * 3600000
            check('CloudWatch 直近の受信', 'PASS' if recent else 'UNKNOWN',
                  '受信時刻を確認。試験イベントとの照合が必要' if recent else '期間内の受信を確認できません。無イベントと配送障害を区別してください')
    check('IAM 権限・侵害判定', 'UNKNOWN', '読み取り成功から作成・削除権限は推定しません。侵害の有無は個別ログの調査が必要')
    report = {'schema_version': 1, 'time_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
              'instance_id': args.instance_id, 'region': args.region, 'checks': checks, 'evidence': evidence}
    path = args.output / 'report.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2)); path.chmod(0o600)
    rows = ''.join(f'<tr><td>{html.escape(c["name"])}</td><td>{c["status"]}</td><td>{html.escape(c["detail"])}</td></tr>' for c in checks)
    page = args.output / 'report.html'
    page.write_text('<!doctype html><meta charset="utf-8"><title>AWS evidence</title><h1>AWS 読み取り監査</h1>'
                    '<p>UNKNOWN は権限不足・証拠不足・要手動確認。PASS は個別確認です。</p><table border="1">' + rows + '</table>')
    page.chmod(0o600)
    manifest = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (path, page)}
    manifest_path = args.output / 'sha256.json'
    manifest_path.write_text(json.dumps(manifest, indent=2)); manifest_path.chmod(0o600)
    print(args.output)
    return 2 if any(c['status'] != 'PASS' for c in checks) else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', required=True)
    parser.add_argument('--region', required=True)
    parser.add_argument('--instance-id', required=True)
    parser.add_argument('--log-group')
    parser.add_argument('--log-stream')
    parser.add_argument('--hours', type=int, default=24)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'i-[0-9a-f]{8,17}', args.instance_id) or not 1 <= args.hours <= 168:
        parser.error('instance-id または hours が不正です')
    try:
        return collect(args)
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
