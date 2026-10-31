"""Offline-Sicherheitstests fuer Shared-Session-Parallelisierung."""
import http.cookiejar
from urllib.request import HTTPCookieProcessor
import io
import unittest
from argparse import Namespace
from contextlib import redirect_stdout
from unittest.mock import patch

from plesk_webhosting import cli, shared_parallel
from plesk_webhosting.core import PleskSession, PleskError


def cookie_jar(client):
    return next(h.cookiejar for h in client.opener.handlers
                if isinstance(h, HTTPCookieProcessor))


class SharedSessionTests(unittest.TestCase):
    def test_requires_verified_login_and_cookie(self):
        session = PleskSession('example.org', 'user', 'password')
        with self.assertRaises(PleskError):
            session.fork_authenticated_worker()

    def test_isolates_cookies_and_write_permissions(self):
        original = PleskSession('example.org', 'user', 'password')
        original._password = None
        original.csrf = 'a' * 32
        jar = cookie_jar(original)
        jar.set_cookie(http.cookiejar.Cookie(version=0, name='PHPSESSID', value='testtoken',
            port=None, port_specified=False, domain='example.org', domain_specified=True,
            domain_initial_dot=False, path='/', path_specified=True, secure=True,
            expires=None, discard=True, comment=None, comment_url=None,
            rest={}, rfc2109=False))
        first = original.fork_authenticated_worker()
        second = original.fork_authenticated_worker()
        self.assertIsNot(cookie_jar(first), jar)
        self.assertIsNot(cookie_jar(first), cookie_jar(second))
        self.assertEqual(next(iter(cookie_jar(first))).value, 'testtoken')
        self.assertIsNone(first._write_grant)
        first.close()
        self.assertEqual(len(list(cookie_jar(first))), 0)
        self.assertEqual(len(list(cookie_jar(second))), 1)
        original.close()
        second.close()

    def test_parser_requires_parallel(self):
        parser = cli.build_parser()
        a = parser.parse_args(['--domain', 'test.example.org', 'batch', '--plan', '--parallel',
                               '--shared-session', '--php-version', '8.5', '--https-redirect'])
        self.assertTrue(a.shared_session)

    def test_workers_both_run_and_cleanup(self):
        class FakeWorker:
            _write_consumed = False
            def __init__(self): self.closed = False
            def close(self): self.closed = True
            def retire_writes(self): pass
        class FakeClient:
            def __init__(self): self.workers = []
            def fork_authenticated_worker(self):
                worker = FakeWorker()
                self.workers.append(worker)
                return worker
        client = FakeClient()
        args = Namespace(account='test', domain='test.example.org', domain_id=None,
                         php_version='8.5', https_redirect=True, ssl_install=False,
                         basedir='WEBSPACEROOT', plan=True, apply=False, yes=False,
                         json=False, operation_id='sharedtest1234',
                         verify_attempts=1, verify_interval=1)
        with (patch.object(shared_parallel, 'domain_id_from_view', return_value=42),
              patch.object(shared_parallel, 'log_event'),
              patch.object(shared_parallel.php, 'run', return_value=0) as php_run,
              patch.object(shared_parallel.ssl, 'run', return_value=0) as ssl_run,
              redirect_stdout(io.StringIO())):
            outcome = shared_parallel.run(args, client, 'view', 'test', 'example.org', '/tmp/test.jsonl')
        self.assertEqual(outcome, 0)
        self.assertEqual(len(client.workers), 2)
        self.assertTrue(all(w.closed for w in client.workers))
        self.assertEqual(php_run.call_count, 1)
        self.assertEqual(ssl_run.call_count, 1)


if __name__ == '__main__':
    unittest.main()
