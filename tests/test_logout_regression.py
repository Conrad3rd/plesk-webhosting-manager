import unittest
from unittest.mock import patch
from io import BytesIO
from plesk_webhosting.cli import build_parser
from plesk_webhosting.core import PleskSession, PleskError


class Response:
    def __init__(self, url):
        self.url = url
        self.status = 200
    def __enter__(self): return self
    def __exit__(self, *args): return None
    def geturl(self): return self.url
    def read(self, n): return b''


class LogoutRegressionTests(unittest.TestCase):
    def test_cli_command_is_explicit(self):
        args = build_parser().parse_args(['--account', 'test', 'logout-check'])
        self.assertEqual(args.command, 'logout-check')
        self.assertFalse(hasattr(args, 'apply'))

    def _client(self, after):
        session = PleskSession('example.test', 'tester', 'password')
        session._password = None
        session.csrf = 'a' * 32
        responses = iter([Response('https://example.test/login_up.php'),
                          Response('https://example.test' + after)])
        session.opener.open = lambda req, timeout: next(responses)
        return session

    def test_confirmed_logout_same_client(self):
        session = self._client('/login_up.php')
        self.assertTrue(session.logout_regression_check()['session_invalidated'])
        self.assertTrue(session._session_retired)

    def test_still_authenticated_fails(self):
        session = self._client('/smb/web/view')
        self.assertFalse(session.logout_regression_check()['session_invalidated'])

    def test_no_login_no_logout(self):
        session = PleskSession('example.test', 'tester', 'password')
        with self.assertRaises(PleskError):
            session.logout_regression_check()

    def test_write_pending_blocks_logout(self):
        session = self._client('/login_up.php')
        session._write_in_flight = True
        with self.assertRaises(PleskError):
            session.logout_regression_check()
