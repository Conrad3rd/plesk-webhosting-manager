"""Offline-Regressionen fuer den eigenstaendigen parallelen Plesk-Batch."""
import io
import unittest
from argparse import Namespace
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from plesk_webhosting import cli, parallel


def args(**changes):
    obj = dict(account='test', domain='test.example.org', domain_id=None,
               php_version='8.4', basedir='WEBSPACEROOT', https_redirect=True,
               ssl_install=False, plan=True, apply=False, yes=False,
               verify_attempts=2, verify_interval=1, json=False,
               operation_id='testparallel0001', log=Path('/tmp/test-parallel-events.jsonl'))
    obj.update(changes)
    return Namespace(**obj)


class FakeProcess:
    def __init__(self, returncode=0):
        self.returncode = returncode
        self.waited = False
    def communicate(self, timeout):
        self.waited = True
        return ('OK', '')


class ParallelTests(unittest.TestCase):
    def test_two_distinct_subprocesses_and_exact_options(self):
        seen = []
        processes = []
        def launch(command, **kwargs):
            seen.append(command)
            process = FakeProcess()
            processes.append(process)
            self.assertEqual(kwargs['text'], True)
            return process
        with patch.object(parallel, 'log_event'), redirect_stdout(io.StringIO()):
            result = parallel.run(args(), 'test', '/tmp/test-parallel-events.jsonl',
                                  script=Path('/fake/plesk-webhosting.py'), popen=launch)
        self.assertEqual(result, 0)
        self.assertEqual(len(seen), 2)
        self.assertTrue(all(p.waited for p in processes))
        self.assertIn('php', seen[0])
        self.assertIn('ssl', seen[1])
        self.assertIn('--plan', seen[0])
        self.assertIn('--plan', seen[1])
        self.assertNotIn('--yes', seen[0])
        self.assertEqual(seen[0][2:4], ['--operation-id', 'testparallel0001'])
        self.assertEqual(seen[1][2:4], ['--operation-id', 'testparallel0001'])

    def test_apply_passes_explicit_yes_to_both(self):
        commands = parallel.worker_commands(args(apply=True, plan=False, yes=True), '/fake/cli.py')
        for _, command in commands:
            self.assertIn('--apply', command)
            self.assertIn('--yes', command)

    def test_reject_two_ssl_writes(self):
        with self.assertRaises(ValueError):
            parallel.worker_commands(args(ssl_install=True), '/fake/cli.py')

    def test_reject_single_worker(self):
        with self.assertRaises(ValueError):
            parallel.worker_commands(args(https_redirect=False), '/fake/cli.py')

    def test_one_worker_failure_keeps_other_running(self):
        instances = [FakeProcess(3), FakeProcess(0)]
        def launch(command, **kwargs):
            return instances.pop(0)
        with patch.object(parallel, 'log_event'), redirect_stdout(io.StringIO()):
            result = parallel.run(args(), 'test', '/tmp/test-parallel-events.jsonl',
                                  popen=launch)
        self.assertEqual(result, 3)

    def test_cli_help_supports_parallel_and_serial_is_default(self):
        parser = cli.build_parser()
        original = parser.parse_args(['--domain', 'example.org', 'batch', '--plan',
                                      '--php-version', '8.4', '--https-redirect'])
        self.assertFalse(original.parallel)
        selected = parser.parse_args(['--domain', 'example.org', 'batch', '--plan',
                                      '--parallel', '--php-version', '8.4', '--https-redirect'])
        self.assertTrue(selected.parallel)


if __name__ == '__main__':
    unittest.main()
