"""CLI-Vorgangskennung bleibt bei automatisch abgemeldeten Sitzungen erhalten."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from plesk_webhosting import cli
from plesk_webhosting.core import log_event


class LogoutOperationIdTests(unittest.TestCase):
    def _events(self, argv):
        with tempfile.TemporaryDirectory() as folder:
            logfile = Path(folder) / 'events.jsonl'
            observed = []

            class FakeSession:
                host = 'example.test'
                def logout_on_exit(self):
                    return {'status': 'confirmed', 'verification_path': '/login_up.php'}
                def close(self):
                    pass

            def dispatch(parser, args):
                observed.append(args.operation_id)
                cli._active_cli_sessions.get().append(FakeSession())
                log_event(logfile, args._cli_run_id, 'started', section='parallel_batch',
                          operation_id=args.operation_id)
                return 0

            with patch.object(cli, '_run_with_args', dispatch):
                result = cli.run(['--log', str(logfile), *argv])
            self.assertEqual(result, 0)
            return observed[0], [json.loads(s) for s in logfile.read_text().splitlines()]

    def test_generated_shared_session_id_reaches_logout(self):
        operation_id, events = self._events([
            'batch', '--plan', '--parallel', '--shared-session',
            '--php-version', '8.5', '--https-redirect'])
        self.assertEqual(len(operation_id), 16)
        self.assertEqual([e['event'] for e in events], ['started', 'session_logout'])
        self.assertEqual([e['operation_id'] for e in events], [operation_id] * 2)
        self.assertEqual(len({e['run_id'] for e in events}), 1)

    def test_generated_two_session_parallel_id_reaches_logout(self):
        operation_id, events = self._events([
            'batch', '--plan', '--parallel', '--php-version', '8.5', '--https-redirect'])
        self.assertEqual([e['operation_id'] for e in events], [operation_id] * 2)

    def test_explicit_parent_id_is_preserved(self):
        operation_id, events = self._events([
            '--operation-id', 'project_12345678', 'batch', '--plan', '--parallel',
            '--shared-session', '--php-version', '8.5', '--https-redirect'])
        self.assertEqual(operation_id, 'project_12345678')
        self.assertEqual(events[-1]['operation_id'], 'project_12345678')

    def test_regular_call_without_parent_remains_without_operation_id(self):
        operation_id, events = self._events(['inspect', '--json'])
        self.assertIsNone(operation_id)
        self.assertNotIn('operation_id', events[-1])


if __name__ == '__main__':
    unittest.main()
