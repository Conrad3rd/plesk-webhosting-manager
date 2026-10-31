"""Automatischer Abschluss der authentifizierten Python-Plesk-Sitzungen."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from plesk_webhosting.core import PleskSession
from plesk_webhosting.cli import _finish_cli_sessions


class AutoLogoutTests(unittest.TestCase):
    def _session(self):
        s = PleskSession('example.test', 'tester', 'password')
        s._password = None
        s.csrf = 'x' * 32
        return s

    def test_success_logs_out_before_close(self):
        s = self._session()
        events = []
        def logout():
            events.append('logout')
            return {'status': 'confirmed'}
        def close():
            events.append('close')
        s.logout_on_exit = logout
        s.close = close
        with tempfile.TemporaryDirectory() as temp:
            _finish_cli_sessions([s], Path(temp)/'events.jsonl')
        self.assertEqual(events, ['logout', 'close'])

    def test_already_logged_out_is_not_repeated(self):
        s = self._session()
        s._logout_confirmed = True
        with patch.object(s, 'logout_regression_check') as logout:
            self.assertEqual(s.logout_on_exit()['status'], 'already_logged_out')
            logout.assert_not_called()

    def test_no_login_makes_no_network_request(self):
        s = PleskSession('example.test', 'tester', 'password')
        with patch.object(s, 'logout_regression_check') as logout:
            self.assertEqual(s.logout_on_exit()['status'], 'not_authenticated')
            logout.assert_not_called()

    def test_pending_write_does_not_logout(self):
        s = self._session()
        s._write_in_flight = True
        with patch.object(s, 'logout_regression_check') as logout:
            self.assertEqual(s.logout_on_exit()['status'], 'blocked_in_flight')
            logout.assert_not_called()

    def test_failure_does_not_block_close(self):
        s = self._session()
        events = []
        def fail():
            raise RuntimeError('test error')
        s.logout_on_exit = fail
        s.close = lambda: events.append('close')
        with tempfile.TemporaryDirectory() as temp:
            _finish_cli_sessions([s], Path(temp)/'events.jsonl')
        self.assertEqual(events, ['close'])


if __name__ == '__main__':
    unittest.main()
