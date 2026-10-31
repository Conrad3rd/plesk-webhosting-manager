"""Shared operation ID is optional and never replaces the per-call Plesk run ID."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from contextlib import redirect_stdout
from io import StringIO

from plesk_webhosting import cli, core


class CorrelationTests(unittest.TestCase):
    def test_parser_rejects_unsafe_correlation_id(self):
        for bad in ('short', '../evil', 'x yyy 999', 'x'*65, 'a;touch /tmp/x'):
            with self.subTest(bad=bad), self.assertRaises(SystemExit):
                with patch('sys.stderr', new_callable=StringIO):
                    cli.build_parser().parse_args(['--operation-id', bad, 'self-test'])
        parsed = cli.build_parser().parse_args(['--operation-id', 'abc_123456', 'self-test'])
        self.assertEqual(parsed.operation_id, 'abc_123456')

    def test_parent_and_run_ids_are_independent(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'events.jsonl'
            core.log_event(path, 'standalone-1', 'started', section='ssl')
            with core.correlation_context('setup_abcd1234'):
                core.log_event(path, 'run-a', 'started', section='ssl')
                core.log_event(path, 'run-b', 'verified', section='ssl')
            core.log_event(path, 'standalone-2', 'status_ok', section='ssl')
            entries = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertNotIn('operation_id', entries[0])
            self.assertEqual([event['operation_id'] for event in entries[1:3]],
                             ['setup_abcd1234', 'setup_abcd1234'])
            self.assertEqual([event['run_id'] for event in entries[1:3]], ['run-a','run-b'])
            self.assertNotIn('operation_id', entries[3])

    def test_cli_domains_logging_inherits_parent_id(self):
        with tempfile.TemporaryDirectory() as folder:
            filename = Path(folder) / 'events.jsonl'
            def fake_domain_run(args, client, name, host, logfile):
                core.log_event(logfile, 'one-run', 'started', section='domains')
                return 0
            with (patch.object(cli.accounts, 'find_profile', return_value=('profile', {'host':'panel.example.com', 'user':'user'})),
                  patch.object(cli.accounts, 'get_password', return_value='masked'),
                  patch.object(cli, 'PleskSession') as session,
                  patch.object(cli.domains, 'run', side_effect=fake_domain_run)):
                with redirect_stdout(StringIO()):
                    self.assertEqual(cli.run(['--operation-id', 'parent_id_1234', '--log', str(filename), 'domains', 'list', '--json']), 0)
                    self.assertEqual(cli.run(['--log', str(filename), 'domains', 'list', '--json']), 0)
            entries = [json.loads(s) for s in filename.read_text().splitlines()]
            self.assertEqual(entries[0]['operation_id'], 'parent_id_1234')
            self.assertNotIn('operation_id', entries[1])


if __name__ == '__main__':
    unittest.main()
