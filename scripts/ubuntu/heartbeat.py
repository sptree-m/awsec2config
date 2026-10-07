#!/usr/bin/env python3
"""Run as root every five minutes; CloudWatch Agent tails this JSONL file."""
import datetime as dt
import json
import os
from pathlib import Path
import shutil
import subprocess

if os.geteuid() != 0:
    raise SystemExit('root is required')
failures = []
for name in ('systemd-journald', 'rsyslog', 'auditd', 'amazon-cloudwatch-agent'):
    p = subprocess.run(['systemctl', 'is-active', name], capture_output=True, text=True, timeout=20)
    if p.returncode:
        failures.append(name)
audit = subprocess.run(['auditctl', '-s'], capture_output=True, text=True, timeout=20)
lost = None
enabled = None
for line in audit.stdout.splitlines():
    if line.startswith('enabled '):
        enabled = int(line.split()[-1])
    if line.startswith('lost '):
        lost = int(line.split()[-1])
if audit.returncode or lost is None:
    failures.append('audit-status-unknown')
usage = shutil.disk_usage('/var/log')
record = {'type': 'heartbeat', 'time_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
          'disk_free_percent': int(usage.free * 100 / usage.total), 'audit_lost': lost,
          'service_failures': failures, 'audit_disabled': enabled not in (1, 2)}
path = Path('/var/log/awsec2config-heartbeat.jsonl')
if path.is_symlink():
    raise SystemExit('Refusing a symlink heartbeat path')
# Mode/owner match rsyslog auth access; content contains no credentials or commands.
with path.open('a') as stream:
    path.chmod(0o640)
    stream.write(json.dumps(record) + '\n')
