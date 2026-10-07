import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, BASE / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ubuntu = load('ubuntu', 'scripts/ubuntu/ec2_logging.py')
aws = load('aws_audit', 'scripts/aws/audit.py')


class Lifecycle(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.file = self.base / 'etc' / 'owned.conf'
        self.state = self.base / 'state'
        self.addCleanup(patch.stopall)
        patch.object(ubuntu, 'STATE', self.state).start()
        patch.object(ubuntu, 'FILES', {str(self.file): 'logging=true\n'}).start()
        patch.object(ubuntu, 'root').start()
        patch.object(ubuntu, 'preflight').start()
        self.run = patch.object(ubuntu, 'run', return_value={'code': 0, 'stdout': '', 'stderr': ''}).start()

    def test_apply_and_restore_preserves_foreign_file(self):
        foreign = self.base / 'other.conf'
        foreign.write_text('keep')
        ubuntu.apply()
        self.assertEqual(self.file.read_text(), 'logging=true\n')
        ubuntu.restore(False)
        self.assertTrue(self.file.exists())
        ubuntu.restore(True)
        self.assertFalse(self.file.exists())
        self.assertEqual(foreign.read_text(), 'keep')
        self.assertEqual(json.loads((self.state / 'state.json').read_text())['phase'], 'restored')

    def test_conflict_stops_restore(self):
        ubuntu.apply()
        self.file.write_text('administrator edit')
        with self.assertRaises(RuntimeError):
            ubuntu.restore(True)
        self.assertEqual(self.file.read_text(), 'administrator edit')

    def test_partial_failure_is_recoverable(self):
        self.run.return_value = {'code': 1, 'stdout': '', 'stderr': 'denied'}
        with self.assertRaises(RuntimeError):
            ubuntu.apply()
        self.assertEqual(json.loads((self.state / 'state.json').read_text())['phase'], 'applying')
        self.run.return_value = {'code': 0, 'stdout': '', 'stderr': ''}
        ubuntu.restore(True)
        self.assertFalse(self.file.exists())

    def test_second_apply_does_not_overwrite_state(self):
        ubuntu.apply()
        old = (self.state / 'state.json').read_bytes()
        with self.assertRaises(RuntimeError):
            ubuntu.apply()
        self.assertEqual(old, (self.state / 'state.json').read_bytes())

    def test_normalization_does_not_treat_path_prefix_as_same_rule(self):
        self.assertEqual(ubuntu.normalized_rule('-w /etc/passwd -p wa -k awsec2_identity'),
                         ubuntu.normalized_rule('-w /etc/passwd -p aw -k awsec2_identity'))
        self.assertNotEqual(ubuntu.normalized_rule('-w /etc/passwd -p wa -k awsec2_identity'),
                            ubuntu.normalized_rule('-w /etc/passwd.bak -p wa -k awsec2_identity'))

    def test_restore_does_not_remove_modified_runtime_watch(self):
        rules = '/etc/audit/rules.d/90-awsec2config.rules'
        self.state.mkdir()
        ubuntu.atomic_json(self.state / 'state.json', {
            'phase': 'applied', 'files': {rules: {'installed_sha256': ubuntu.digest(b'not-there')}}, 'commands': []})
        self.run.return_value = {'code': 0, 'stdout': '-w /etc/passwd -p r -k awsec2_identity', 'stderr': ''}
        with patch.object(ubuntu, 'FILES', {rules: '-w /etc/passwd -p wa -k awsec2_identity\n'}):
            with self.assertRaises(RuntimeError):
                ubuntu.restore(True)
        self.assertEqual(self.run.call_count, 1)


class AwsAudit(unittest.TestCase):
    def test_ipv4_ipv6_port_range_and_all_protocols(self):
        def group(rule):
            return [{'GroupId': 'sg-test', 'IpPermissions': [rule]}]
        for rule in (
            {'IpProtocol': 'tcp', 'FromPort': 20, 'ToPort': 23, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
            {'IpProtocol': '6', 'FromPort': 3389, 'ToPort': 3389, 'Ipv6Ranges': [{'CidrIpv6': '::/0'}]},
            {'IpProtocol': '-1', 'Ipv6Ranges': [{'CidrIpv6': '::/0'}]},
        ):
            self.assertTrue(aws.exposure(group(rule)))
        self.assertFalse(aws.exposure(group({'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443,
                                           'IpRanges': [{'CidrIp': '0.0.0.0/0'}]})))

    def test_denied_calls_produce_unknown_report(self):
        import argparse
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            args = argparse.Namespace(profile='deputy', region='ap-northeast-1', instance_id='i-1234567890abcdef0',
                                      output=Path(directory) / 'report', log_group=None, log_stream=None, hours=24)
            result = subprocess.CompletedProcess([], 254, '', 'AccessDenied')
            with patch.object(aws.subprocess, 'run', return_value=result):
                self.assertEqual(aws.collect(args), 2)
            report = json.loads((args.output / 'report.json').read_text())
            self.assertTrue(all(c['status'] == 'UNKNOWN' for c in report['checks']))
            self.assertTrue((args.output / 'sha256.json').exists())


if __name__ == '__main__':
    unittest.main()
