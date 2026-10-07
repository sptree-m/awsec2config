#!/usr/bin/env python3
"""Local Ubuntu logging lifecycle. No AWS mutation, package installation or SSH change."""
import argparse
import datetime as dt
import hashlib
import html
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import uuid

STATE = Path('/var/lib/awsec2config')
FILES = {
    '/etc/systemd/journald.conf.d/90-awsec2config.conf':
        '[Journal]\nStorage=persistent\nCompress=yes\nSystemMaxUse=1G\nMaxRetentionSec=30day\n',
    '/etc/rsyslog.d/90-awsec2config.conf':
        'auth,authpriv.* action(type="omfile" file="/var/log/awsec2config-auth.log" '
        'fileCreateMode="0640" fileOwner="syslog" fileGroup="adm")\n',
    '/etc/logrotate.d/awsec2config':
        '/var/log/awsec2config-auth.log {\n daily\n rotate 30\n missingok\n notifempty\n compress\n delaycompress\n create 0640 syslog adm\n sharedscripts\n postrotate\n  /usr/bin/systemctl kill -s HUP rsyslog.service\n endscript\n}\n',
    '/etc/audit/rules.d/90-awsec2config.rules':
        '-w /etc/passwd -p wa -k awsec2_identity\n'
        '-w /etc/group -p wa -k awsec2_identity\n'
        '-w /etc/shadow -p wa -k awsec2_identity\n'
        '-w /etc/sudoers -p wa -k awsec2_privilege\n'
        '-w /etc/ssh/sshd_config -p wa -k awsec2_remote\n',
}


def run(args):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=60)
        return {'command': args, 'code': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'command': args, 'code': -1, 'stdout': '', 'stderr': str(exc)}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def normalized_rule(line):
    parts = line.split()
    if '-p' in parts:
        index = parts.index('-p') + 1
        parts[index] = ''.join(sorted(parts[index]))
    return parts


def atomic_json(path, value):
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2))
    tmp.chmod(0o600)
    tmp.replace(path)


def root():
    if os.geteuid() != 0:
        raise RuntimeError('sudo / root が必要です')


def preflight():
    release = Path('/etc/os-release').read_text()
    if 'ID=ubuntu\n' not in release or not any(f'VERSION_ID="{v}"' in release for v in ('22.04', '24.04')):
        raise RuntimeError('Ubuntu 22.04 / 24.04 LTS のみ対応')
    for command in ('systemctl', 'rsyslogd', 'auditctl', 'augenrules', 'logrotate'):
        if not shutil.which(command):
            raise RuntimeError(f'{command} がありません。正管理者が rsyslog / auditd / logrotate を準備してください')
    for service in ('systemd-journald', 'rsyslog', 'auditd'):
        if run(['systemctl', 'is-active', service])['code'] != 0:
            raise RuntimeError(f'{service} が稼働していません')
    status = run(['auditctl', '-s'])
    if status['code'] != 0 or 'enabled 2' in status['stdout']:
        raise RuntimeError('auditd 状態を取得できないか immutable です。正管理者へ依頼してください')
    rules = run(['auditctl', '-l'])
    if rules['code'] or 'awsec2_' in rules['stdout']:
        raise RuntimeError('有効監査ルールを確認できないか専用キーが既に使われています')
    # augenrules must regenerate audit.rules without our watches on restore.
    existing = list(Path('/etc/audit/rules.d').glob('*.rules'))
    if not any(any(line.strip() and not line.lstrip().startswith('#') for line in p.read_text().splitlines()) for p in existing):
        raise RuntimeError('既存の audit ルールファイルがありません。正管理者が auditd ベースラインを準備してください')
    for filename in FILES:
        path = Path(filename)
        if path.exists() or path.is_symlink():
            raise RuntimeError(f'専用ファイルが既に存在します: {filename}')


def apply():
    root()
    if STATE.exists():
        raise RuntimeError('状態ディレクトリが存在します。audit / restore で確認してください')
    preflight()
    STATE.mkdir(mode=0o700)
    state = {'version': 1, 'phase': 'applying', 'files': {}, 'commands': [],
             'created_at': dt.datetime.now(dt.timezone.utc).isoformat()}
    # Dedicated files were absent. Record intent before each mutation, including interrupted runs.
    atomic_json(STATE / 'state.json', state)
    for name, content in FILES.items():
        data = content.encode()
        state['files'][name] = {'installed_sha256': digest(data), 'previous': None}
        atomic_json(STATE / 'state.json', state)
        path = Path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream:
            stream.write(data)
        path.chmod(0o644)
    commands = [
        ['rsyslogd', '-N1'], ['logrotate', '--debug', '/etc/logrotate.d/awsec2config'],
        ['systemctl', 'restart', 'systemd-journald'],
        ['journalctl', '--flush'], ['systemctl', 'restart', 'rsyslog'],
        ['augenrules', '--load'],
    ]
    for cmd in commands:
        result = run(cmd)
        state['commands'].append(result)
        atomic_json(STATE / 'state.json', state)
        if result['code']:
            raise RuntimeError(f'設定反映に失敗: {cmd}。状態を保存しました。audit / restore を実施してください')
    state['phase'] = 'applied'
    state['probe'] = 'awsec2config-probe-' + uuid.uuid4().hex
    atomic_json(STATE / 'state.json', state)
    result = run(['logger', '-p', 'authpriv.notice', state['probe']])
    state['commands'].append(result)
    atomic_json(STATE / 'state.json', state)
    if result['code']:
        raise RuntimeError('試験ログの生成に失敗。audit で確認してください')
    print('導入完了。audit で有効設定とログを検証してください')


def restore(execute):
    root()
    state = json.loads((STATE / 'state.json').read_text())
    if state['phase'] == 'restored':
        print('復元済みです')
        return
    for name, record in state['files'].items():
        path = Path(name)
        if path.is_symlink() or (path.exists() and digest(path.read_bytes()) != record['installed_sha256']):
            raise RuntimeError(f'導入後の変更を検出しました。上書きしません: {name}')
    print('復元対象: ' + ', '.join(state['files']))
    if not execute:
        print('実行には restore --execute を指定してください')
        return
    # Delete only our specific runtime watches. Never auditctl -D (all rules).
    rules_path = '/etc/audit/rules.d/90-awsec2config.rules'
    if rules_path in state['files']:
        active = run(['auditctl', '-l'])
        if active['code']:
            raise RuntimeError('有効監査ルールを確認できないため復元を停止しました')
        expected = [normalized_rule(x) for x in FILES[rules_path].splitlines()]
        for line in active['stdout'].splitlines():
            if 'awsec2_' in line and normalized_rule(line) not in expected:
                raise RuntimeError('専用監査ルールの変更を検出しました。正管理者へ手動確認を依頼してください')
        for line in FILES[rules_path].splitlines():
            # auditctl may normalize permissions; identify our watch by path and unique key.
            parts = line.split()
            if any(normalized_rule(line) == normalized_rule(x) for x in active['stdout'].splitlines()):
                result = run(['auditctl', '-W', *parts[1:]])
                if result['code']:
                    raise RuntimeError(f'監査ルール解除失敗: {result["stderr"]}')
    for name in state['files']:
        Path(name).unlink(missing_ok=True)
    for cmd in (['augenrules', '--load'], ['systemctl', 'restart', 'systemd-journald'],
                ['systemctl', 'restart', 'rsyslog']):
        result = run(cmd)
        state['commands'].append(result)
        atomic_json(STATE / 'state.json', state)
        if result['code']:
            raise RuntimeError(f'復元の反映に失敗: {cmd}。再実行してください')
    state['phase'] = 'restored'
    atomic_json(STATE / 'state.json', state)
    print('復元完了。保存ログと状態記録は保持しています')


def report(mode, output, hours):
    root()
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    output.chmod(0o700)
    checks = []
    evidence = {}
    def check(name, status, detail):
        checks.append({'name': name, 'status': status, 'detail': detail})
    state = None
    try:
        state = json.loads((STATE / 'state.json').read_text())
        check('導入状態', 'PASS' if state['phase'] == 'applied' else 'FAIL', state['phase'])
    except (OSError, ValueError) as exc:
        check('導入状態', 'UNKNOWN', str(exc))
    for name, content in FILES.items():
        path = Path(name)
        try:
            actual = path.read_bytes()
            check(name, 'PASS' if actual == content.encode() and not path.is_symlink() else 'FAIL', digest(actual))
        except OSError as exc:
            check(name, 'FAIL', str(exc))
    for service in ('systemd-journald', 'rsyslog', 'auditd'):
        result = run(['systemctl', 'is-active', service])
        evidence[service] = result
        check(service, 'PASS' if result['code'] == 0 else 'FAIL', result['stdout'].strip())
    commands = {
        'journal-effective': ['systemd-analyze', 'cat-config', 'systemd/journald.conf'],
        'journal-disk': ['journalctl', '--disk-usage'],
        'audit-status': ['auditctl', '-s'], 'audit-rules': ['auditctl', '-l'],
        'rsyslog-validation': ['rsyslogd', '-N1'],
        'logrotate-validation': ['logrotate', '--debug', '/etc/logrotate.d/awsec2config'],
        'disk': ['df', '-h', '/var/log'],
        'ssh-effective': ['sshd', '-T'],
        'authentication': ['journalctl', '--since', f'{hours} hours ago', '-o', 'json', '--no-pager',
                           'SYSLOG_FACILITY=4', 'SYSLOG_FACILITY=10'],
    }
    for key, cmd in commands.items():
        evidence[key] = run(cmd)
        check(key + ' 取得', 'PASS' if evidence[key]['code'] == 0 else 'UNKNOWN',
              '取得成功' if evidence[key]['code'] == 0 else evidence[key]['stderr'])
    if evidence['journal-effective']['code'] == 0:
        effective = {}
        section = ''
        for line in evidence['journal-effective']['stdout'].splitlines():
            line = line.strip()
            if line.startswith('['):
                section = line
            elif section == '[Journal]' and line and not line.startswith(('#', ';')) and '=' in line:
                key, value = line.split('=', 1)
                effective[key.strip()] = value.strip()
        for key, expected in {'Storage': 'persistent', 'SystemMaxUse': '1G', 'MaxRetentionSec': '30day'}.items():
            check('journal 有効設定 ' + key, 'PASS' if effective.get(key) == expected else 'FAIL', str(effective.get(key)))
    active = evidence['audit-rules']
    if active['code'] == 0:
        for line in FILES['/etc/audit/rules.d/90-awsec2config.rules'].splitlines():
            p = line.split()
            present = any(normalized_rule(line) == normalized_rule(x) for x in active['stdout'].splitlines())
            check('有効監査ルール ' + p[1], 'PASS' if present else 'FAIL', p[-1])
    status = evidence['audit-status']['stdout'].splitlines()
    lost = next((x.split()[-1] for x in status if x.startswith('lost ')), None)
    check('audit lost', 'PASS' if lost == '0' else 'UNKNOWN' if lost is None else 'FAIL', str(lost))
    enabled = next((x.split()[-1] for x in status if x.startswith('enabled ')), None)
    check('audit 有効状態', 'PASS' if enabled in ('1', '2') else 'UNKNOWN' if enabled is None else 'FAIL', str(enabled))
    persistent = Path('/var/log/journal').exists() and any(Path('/var/log/journal').rglob('*.journal'))
    check('永続 journal ファイル', 'PASS' if persistent else 'FAIL', '/var/log/journal')
    authfile = Path('/var/log/awsec2config-auth.log')
    check('認証ログファイル', 'PASS' if authfile.exists() else 'UNKNOWN',
          'ファイル存在は配信成功の証明ではありません。試験イベントも確認してください')
    if state and state.get('probe'):
        try:
            with authfile.open('rb') as stream:
                stream.seek(max(0, authfile.stat().st_size - 8 * 1024 * 1024))
                tail = stream.read()
            check('認証ログ試験イベント', 'PASS' if state['probe'].encode() in tail else 'UNKNOWN',
                  '導入時の logger マーカーを直近8MiBで照合。ローテート後は手動で試験イベントを再確認')
        except OSError as exc:
            check('認証ログ試験イベント', 'UNKNOWN', str(exc))
    for source in ('/var/log/audit/audit.log', '/var/log/awsec2config-auth.log'):
        try:
            path = Path(source)
            with path.open('rb') as stream:
                stream.seek(max(0, path.stat().st_size - 8 * 1024 * 1024))
                tail = stream.read()
            destination = output / (path.name + '.tail')
            destination.write_bytes(tail)
            destination.chmod(0o600)
            check(source + ' 保存', 'PASS', '現在のファイルの末尾8MiB以内。期間指定・全件取得ではありません')
        except OSError as exc:
            check(source + ' 保存', 'UNKNOWN', str(exc))
    # Raw records are retained; counts are signals, never a verdict of no intrusion.
    raw = evidence['authentication']['stdout'].lower()
    indicators = {term: raw.count(term) for term in ('failed password', 'invalid user', 'authentication failure', 'sudo')}
    check('侵害判定', 'UNKNOWN', '件数だけでは侵害の有無を判断できません。生ログを確認してください')
    value = {'schema_version': 1, 'mode': mode, 'time_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
             'host': platform.node(), 'hours': hours, 'checks': checks, 'indicators': indicators, 'evidence': evidence}
    atomic_json(output / 'report.json', value)
    rows = ''.join(f'<tr><td>{html.escape(c["name"])}</td><td>{c["status"]}</td><td>{html.escape(c["detail"])}</td></tr>' for c in checks)
    (output / 'report.html').write_text('<!doctype html><meta charset="utf-8"><title>EC2 logging evidence</title>'
        '<h1>Ubuntu ログ収集監査</h1><p>PASS は各項目の確認結果です。侵害なしの証明ではありません。</p>'
        '<table border="1"><tr><th>項目</th><th>結果</th><th>証拠・補足</th></tr>' + rows + '</table>'
        '<p>生の取得結果は report.json に保存しています。AWS 配信の監査は別途実施してください。</p>')
    (output / 'report.html').chmod(0o600)
    manifest = {p.name: digest(p.read_bytes()) for p in output.iterdir() if p.is_file()}
    atomic_json(output / 'sha256.json', manifest)
    print(output)
    return 2 if any(c['status'] in ('FAIL', 'UNKNOWN') and c['name'] != '侵害判定' for c in checks) else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['apply', 'audit', 'daily', 'restore'])
    parser.add_argument('--execute', action='store_true', help='復元を実行（省略時はプレビュー）')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--hours', type=int, default=24)
    args = parser.parse_args()
    if not 1 <= args.hours <= 168:
        parser.error('--hours は 1～168')
    if args.mode == 'apply':
        apply()
    elif args.mode == 'restore':
        restore(args.execute)
    else:
        if not args.output:
            parser.error('監査は --output に新しいディレクトリを指定してください')
        return report(args.mode, args.output, args.hours)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
