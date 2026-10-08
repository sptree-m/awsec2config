#!/usr/bin/env python3
"""Reversible dedicated systemd heartbeat timer; retains captured logs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

STATE=Path('/var/lib/awsec2config-heartbeat')
NAME='awsec2config-heartbeat'

def run(*args): subprocess.run(args,check=True,timeout=60)

def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('mode',choices=['apply','restore']); p.add_argument('--execute',action='store_true'); args=p.parse_args()
    if os.geteuid()!=0: raise RuntimeError('root required')
    path=Path(__file__).with_name('heartbeat.py').resolve()
    if not re.fullmatch(r'[A-Za-z0-9_./-]+',str(path)): raise ValueError('Install under a path without spaces or special characters')
    files={f'/etc/systemd/system/{NAME}.service':f'[Unit]\nDescription=EC2 security heartbeat\n[Service]\nType=oneshot\nUser=root\nExecStart=/usr/bin/python3 {path}\n',
           f'/etc/systemd/system/{NAME}.timer':f'[Unit]\nDescription=EC2 security heartbeat every five minutes\n[Timer]\nOnCalendar=*-*-* *:0/5:00\nPersistent=true\nUnit={NAME}.service\n[Install]\nWantedBy=timers.target\n'}
    if args.mode=='apply':
        if STATE.exists() or any(Path(f).exists() or Path(f).is_symlink() for f in files): raise RuntimeError('State or dedicated units already exist; refusing overwrite')
        STATE.mkdir(mode=0o700)
        manifest={f:hashlib.sha256(data.encode()).hexdigest() for f,data in files.items()}
        state=STATE/'state.json'; state.write_text(json.dumps(manifest)); state.chmod(0o600)
        for file,data in files.items():
            with Path(file).open('x') as stream: stream.write(data)
            Path(file).chmod(0o644)
        run('systemctl','daemon-reload'); run('systemctl','enable','--now',NAME+'.timer')
        run('systemctl','start',NAME+'.service')
    else:
        if (STATE/'restored').exists():
            print('Already restored; logs and state retained')
            return
        manifest=json.loads((STATE/'state.json').read_text())
        for file,expected in manifest.items():
            f=Path(file)
            if f.is_symlink() or f.exists() and hashlib.sha256(f.read_bytes()).hexdigest()!=expected: raise RuntimeError('Administrator drift: '+file)
        print('Remove dedicated timer/service; preserve heartbeat logs and state backup')
        if args.execute:
            run('systemctl','disable','--now',NAME+'.timer')
            run('systemctl','stop',NAME+'.service')
            for file in manifest: Path(file).unlink(missing_ok=True)
            run('systemctl','daemon-reload')
            (STATE/'restored').write_text('restored')

if __name__=='__main__': main()
