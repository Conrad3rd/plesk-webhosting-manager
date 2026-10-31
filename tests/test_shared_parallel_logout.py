"""Regression: Shared-Session-Elternlogin erst nach Worker-Ende abmelden."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from plesk_webhosting import cli, shared_parallel


class SharedParallelLogoutTests(unittest.TestCase):
    def test_logout_after_workers_before_close(self):
        events = []
        class FakeSession:
            host = 'example.org'
            def __init__(self, host, username, password):
                self.host = host
                events.append('session_created')
            def login(self):
                events.append('login')
                return 'view'
            def logout_on_exit(self):
                events.append('logout')
                return {'status': 'confirmed', 'verification_path': '/login_up.php'}
            def close(self):
                events.append('close')
        def fake_parallel(*args, **kwargs):
            events.append('workers_completed')
            return 0
        with tempfile.TemporaryDirectory() as tmp:
            with (patch.object(cli.accounts, 'find_profile', return_value=('test', {'host':'example.org', 'user':'user'})),
                  patch.object(cli.accounts, 'get_password', return_value='example-secret'),
                  patch.object(cli, 'PleskSession', FakeSession),
                  patch.object(shared_parallel, 'run', side_effect=fake_parallel),
                  patch.object(cli, 'log_event')):
                result = cli.run(['--account', 'test', '--domain', 'test.example.org',
                                  '--log', str(Path(tmp)/'events.jsonl'), 'batch', '--plan',
                                  '--parallel', '--shared-session', '--php-version', '8.5',
                                  '--https-redirect'])
        self.assertEqual(result, 0)
        self.assertEqual(events, ['session_created', 'login', 'workers_completed', 'logout', 'close'])

    def test_logout_even_if_worker_orchestration_fails(self):
        events = []
        class FakeSession:
            host = 'example.org'
            def __init__(self, host, username, password):
                self.host = host
            def login(self): return 'view'
            def logout_on_exit(self):
                events.append('logout')
                return {'status': 'confirmed'}
            def close(self): events.append('close')
        with tempfile.TemporaryDirectory() as tmp:
            with (patch.object(cli.accounts, 'find_profile', return_value=('test', {'host':'example.org', 'user':'user'})),
                  patch.object(cli.accounts, 'get_password', return_value='example-secret'),
                  patch.object(cli, 'PleskSession', FakeSession),
                  patch.object(shared_parallel, 'run', side_effect=RuntimeError('worker test failure')),
                  patch.object(cli, 'log_event')):
                result = cli.run(['--account', 'test', '--domain', 'test.example.org',
                             '--log', str(Path(tmp)/'events.jsonl'), 'batch', '--plan',
                             '--parallel', '--shared-session', '--php-version', '8.5',
                             '--https-redirect'])
        self.assertEqual(result, 1)
        self.assertEqual(events, ['logout', 'close'])
