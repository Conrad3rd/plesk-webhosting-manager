"""Regression: Fachereignisse und Logout gehoeren zum selben CLI-Lauf."""
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from plesk_webhosting import cli
from plesk_webhosting.core import log_event


class LogoutCorrelationTests(unittest.TestCase):
    def test_run_and_logout_have_identical_run_id(self):
        with tempfile.TemporaryDirectory() as folder:
            logfile = Path(folder) / 'events.jsonl'
            class FakeSession:
                host = 'example.test'
                def logout_on_exit(self):
                    return {'status': 'confirmed', 'verification_path': '/login_up.php'}
                def close(self):
                    pass
            def fake_dispatch(parser, args):
                registry = cli._active_cli_sessions.get()
                registry.append(FakeSession())
                log_event(logfile, args._cli_run_id, 'started', section='inspect')
                log_event(logfile, args._cli_run_id, 'completed', section='inspect')
                return 0
            with patch.object(cli, '_run_with_args', fake_dispatch):
                rc = cli.run(['--log', str(logfile), 'inspect', '--json'])
            self.assertEqual(rc, 0)
            events = [json.loads(line) for line in logfile.read_text().splitlines()]
            self.assertEqual([e['event'] for e in events],
                             ['started', 'completed', 'session_logout'])
            self.assertEqual(len({e['run_id'] for e in events}), 1)

    def test_shared_parallel_receives_cli_run_id(self):
        from plesk_webhosting import shared_parallel
        source = Path(shared_parallel.__file__).read_text()
        self.assertIn("getattr(args, '_cli_run_id', None)", source)

    def test_distinct_cli_calls_get_distinct_ids(self):
        observed = []
        def fake_dispatch(parser, args):
            observed.append(args._cli_run_id)
            return 0
        with patch.object(cli, '_run_with_args', fake_dispatch):
            self.assertEqual(cli.run(['self-test']), 0)
            self.assertEqual(cli.run(['self-test']), 0)
        self.assertEqual(len(observed), 2)
        self.assertNotEqual(*observed)


if __name__ == '__main__':
    unittest.main()
