"""A release must contain committed source, exclude local secrets, and verify every artifact."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('release_build',ROOT/'scripts/release/build.py')
builder=importlib.util.module_from_spec(spec); spec.loader.exec_module(builder)

class Release(unittest.TestCase):
    def test_exact_commit_complete_source_and_checksums(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/'repo'; root.mkdir()
            sources={'VERSION':'0.2.0\n','.github/workflows/checks.yml':'test: yes\n',
                     'docs/runbook.md':'instructions','lambda_src/common.py':'# runtime',
                     'scripts/windows/Ec2Logging.ps1':'# Windows','tests/test_example.py':'# tests'}
            for name,body in sources.items():
                file=root/name; file.parent.mkdir(parents=True,exist_ok=True); file.write_text(body)
            def git(*args): return subprocess.check_output(['git',*args],cwd=root,stderr=subprocess.DEVNULL)
            git('init'); git('add','.'); git('-c','user.name=Release Test','-c','user.email=test@example.invalid','commit','-m','fixture')
            (root/'local-secret.json').write_text('must never ship')
            (root/'docs/runbook.md').write_text('uncommitted changes must not ship')
            with patch.object(builder,'ROOT',root):
                manifest=builder.build('v0.2.0',Path(temp)/'dist')
                again=builder.build('v0.2.0',Path(temp)/'second')
            self.assertEqual(manifest,again)
            self.assertEqual(set(manifest['source_files']),set(sources))
            folder=Path(temp)/'dist'
            with zipfile.ZipFile(folder/'awsec2config-v0.2.0-source.zip') as archive:
                self.assertEqual(set(archive.namelist()),{'awsec2config-v0.2.0/'+name for name in sources})
                self.assertEqual(archive.read('awsec2config-v0.2.0/docs/runbook.md'),b'instructions')
            with zipfile.ZipFile(folder/'awsec2config-v0.2.0-lambda.zip') as archive:
                self.assertEqual(archive.namelist(),['common.py'])
            for line in (folder/'SHA256SUMS.txt').read_text().splitlines():
                sha,name=line.split('  ')
                self.assertEqual(sha,hashlib.sha256((folder/name).read_bytes()).hexdigest())
