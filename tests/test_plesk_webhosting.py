"""Offline-Tests ohne netcup-Zugang, Browser und Secret-Service-Sitzung."""
from contextlib import redirect_stdout
from io import StringIO
import os
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from plesk_webhosting import accounts, php, ssl
from plesk_webhosting.cli import build_parser, run
from plesk_webhosting.core import (PleskError, PleskSession, SameHostRedirect,
                                   domain_id_from_view, log_event, default_log_path)

class PleskTests(unittest.TestCase):
    def test_self_tests(self):
        with redirect_stdout(StringIO()):
            php.self_test()
            ssl.self_test()

    def test_dynamic_hosts_and_single_write_grant(self):
        a = PleskSession('alpha.webhosting.systems','user-a','secret-a')
        b = PleskSession('beta.webhosting.systems','user-b','secret-b')
        self.assertNotEqual(a.base,b.base)
        with self.assertRaises(PleskError):
            a.request('/modules/sslit/index.php/https-redirect/enable/', body=b'{}',
                      headers={'Content-Type':'application/json'})
        a.authorize_write_once('/modules/sslit/index.php/https-redirect/enable/', b'{"id":"3"}', 'application/json')
        with self.assertRaises(PleskError):
            a.request('/modules/sslit/index.php/https-redirect/disable/', body=b'{"id":"3"}',
                      headers={'Content-Type':'application/json'})
        self.assertIsNotNone(a._write_grant)
        with self.assertRaises(PleskError):
            a.request('/modules/sslit/index.php/https-redirect/enable/', body=b'{"id":"4"}',
                      headers={'Content-Type':'application/json'})
        self.assertIsNotNone(a._write_grant)
        with self.assertRaises(PleskError):
            a.authorize_write_once('/modules/unknown/', b'{}', 'application/json')

    def test_reject_cross_host(self):
        with self.assertRaises(PleskError):
            SameHostRedirect('alpha.webhosting.systems').redirect_request(
                None, None, 302, 'redirect', {}, 'https://example.org/login')

    def test_unique_domain_id(self):
        html = '<script>Plesk.run({"data":{"data":{"data":[{"displayName":"example.de","domainId":12}]}}})</script>'
        self.assertEqual(domain_id_from_view(html,'example.de'),12)
        with self.assertRaises(PleskError):
            domain_id_from_view(html,'other.de')

    def test_config_permissions_and_no_passwords(self):
        with tempfile.TemporaryDirectory() as d, patch.dict(os.environ,{'XDG_CONFIG_HOME':d}):
            profiles={'one':{'host':'alpha.webhosting.systems','user':'u@example.org'}}
            accounts.save_profiles(profiles)
            self.assertEqual(accounts.load_profiles(),profiles)
            path=accounts.config_path()
            self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
            self.assertNotIn('password',path.read_text().lower())
            os.chmod(path,0o644)
            with self.assertRaises(PleskError):
                accounts.load_profiles()

    def test_account_selection(self):
        with tempfile.TemporaryDirectory() as d, patch.dict(os.environ,{'XDG_CONFIG_HOME':d}):
            accounts.save_profiles({'one':{'host':'alpha.webhosting.systems','user':'u'},
                                    'two':{'host':'beta.webhosting.systems','user':'v'}})
            with self.assertRaises(PleskError):
                accounts.find_profile(None)
            name, info=accounts.find_profile('two')
            self.assertEqual(name,'two')
            self.assertEqual(info['host'],'beta.webhosting.systems')

    def test_keyring_commands_profile_scoped(self):
        self.assertEqual(accounts.attrs('x','a.webhosting.systems','bob'),
                        ['application',accounts.APP_ID,'profile','x','host','a.webhosting.systems','user','bob'])

    def test_default_log_is_relative_to_installation_not_working_directory(self):
        install_dir = Path(__file__).resolve().parents[1]
        expected = install_dir / 'logs' / 'events.jsonl'
        self.assertEqual(default_log_path(), expected)
        self.assertEqual(build_parser().parse_args(['--domain', 'example.de',
                                                      'php', '--check']).log, expected)
        with tempfile.TemporaryDirectory() as other_cwd:
            previous = Path.cwd()
            try:
                os.chdir(other_cwd)
                self.assertEqual(default_log_path(), expected)
                self.assertEqual(build_parser().parse_args(['--domain', 'example.de',
                                                              'ssl', '--check']).log, expected)
            finally:
                os.chdir(previous)

    def test_explicit_log_path_overrides_installation_default(self):
        chosen = Path('/tmp/plesk-alternate.jsonl')
        args = build_parser().parse_args(['--domain', 'example.de', '--log',
                                           str(chosen), 'php', '--check'])
        self.assertEqual(args.log, chosen)
        self.assertNotEqual(args.log, default_log_path())

    def test_log_permissions(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'logs'/'events.jsonl'
            log_event(path,'run-1','check',section='php',host='a.webhosting.systems')
            self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
            self.assertIn('"section": "php"',path.read_text())

    def test_php_post_endpoint_log_event(self):
        """Regression: metadata named `path` must not collide with log filename."""
        with tempfile.TemporaryDirectory() as d:
            logfile = Path(d) / 'php.jsonl'
            php.log_event(logfile, 'test-php', 'post_submitting',
                          domain_id=123,
                          path='/smb/web/php-settings/id/123', fields=35)
            row = json.loads(logfile.read_text())
            self.assertEqual(row['section'], 'php')
            self.assertEqual(row['path'], '/smb/web/php-settings/id/123')
            self.assertEqual(row['event'], 'post_submitting')
            self.assertEqual(stat.S_IMODE(logfile.stat().st_mode), 0o600)

    def test_ssl_post_endpoint_log_event(self):
        """SSL uses exactly the same logger and field name."""
        with tempfile.TemporaryDirectory() as d:
            logfile = Path(d) / 'ssl.jsonl'
            ssl.log_event(logfile, 'test-ssl', 'post_submitting',
                          domain_id=123,
                          path='/modules/sslit/index.php/https-redirect/disable/')
            row = json.loads(logfile.read_text())
            self.assertEqual(row['section'], 'ssl')
            self.assertEqual(row['path'], '/modules/sslit/index.php/https-redirect/disable/')
            self.assertEqual(row['event'], 'post_submitting')
            self.assertEqual(stat.S_IMODE(logfile.stat().st_mode), 0o600)

    def test_cli_help_and_self_test_no_login(self):
        parser=build_parser()
        self.assertEqual(parser.parse_args(['--domain','example.de','php','--check']).domain,'example.de')
        with redirect_stdout(StringIO()):
            self.assertEqual(run(['self-test']),0)

if __name__=='__main__':
    unittest.main()
