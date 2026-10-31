"""Domain-Liste: isolierte Tests ohne Plesk-Login oder Netzwerk."""
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from plesk_webhosting import domains, subdomain
from plesk_webhosting.cli import build_parser, run
from plesk_webhosting.core import PleskError


class FakePlesk:
    def __init__(self, html, status=200):
        self.html = html
        self.status = status
        self.requests = []

    def request(self, path, *, body=None, **kwargs):
        self.requests.append((path, body))
        if path != subdomain.CREATE_PATH or body is not None:
            raise AssertionError('Unerwarteter oder schreibender Request')
        return self.status, self.html, 'text/html'


def form(choices, *, extra_lookups=(), method='POST', action=''):
    lookup = {'applyTo': 'domainName-domain', 'name': 'domainName[domain]',
              'data': choices}
    scripts = [lookup, *extra_lookups]
    return (f'<form id="smb-form-final-web-addsubdomain" method="{method}" action="{action}"></form>'
            + ''.join('<script>new Jsw.LookUp(' + json.dumps(entry) + ')</script>'
                      for entry in scripts))


class DomainListTests(unittest.TestCase):
    def test_cli_parser_requires_no_domain_argument(self):
        options = build_parser().parse_args(['--account', 'hosting-1', 'domains', 'list', '--json'])
        self.assertEqual(options.account, 'hosting-1')
        self.assertEqual(options.command, 'domains')
        self.assertTrue(options.json)

    def test_read_only_sorted_normalized_choices(self):
        html = form([{'id': '200', 'title': 'Zweite.Example.COM.'},
                     {'id': 100, 'title': 'example.org'},
                     {'id': '', 'title': 'Please select'}])
        client = FakePlesk(html)
        self.assertEqual(domains.read_domains(client), [
            {'name': 'example.org', 'id': 100},
            {'name': 'zweite.example.com', 'id': 200},
        ])
        self.assertEqual(client.requests, [(subdomain.CREATE_PATH, None)])

    def test_reuses_same_main_domain_lookup_as_subdomain_creation(self):
        html = form([{'id': 200, 'title': 'other.example.org'},
                     {'id': 100, 'title': 'example.org'}])
        instance = subdomain.CreationForm()
        instance.feed(html)
        self.assertEqual(subdomain.parent_lookup(instance, 'example.org'), 100)
        self.assertEqual(domains.read_domains(FakePlesk(html))[0]['name'], 'example.org')

    def test_refuse_ambiguous_or_invalid_form(self):
        valid = [{'id': 100, 'title': 'example.org'}]
        for invalid in [
            form(valid, method='GET'),
            form(valid, action='/elsewhere'),
            form(valid, extra_lookups=[{'applyTo': 'domainName-domain',
                                        'name': 'domainName[domain]', 'data': valid}]),
            form([{'id': 100, 'title': 'example.org'}, {'id': 101, 'title': 'example.org'}]),
            form([{'id': 100, 'title': 'example.org'}, {'id': 100, 'title': 'other.org'}]),
            form([{'id': 100, 'title': 'not-a-domain'}]),
            form([{'id': False, 'title': 'example.org'}]),
            form([{'id': 0, 'title': 'example.org'}]),
            form([{'id': 100, 'title': 'example.org'}, 123]),
            '<h1>Login expired</h1>',
        ]:
            with self.subTest(html=invalid[:75]):
                with self.assertRaises(PleskError):
                    domains.read_domains(FakePlesk(invalid))

    def test_empty_valid_lookup_returns_empty_domain_list(self):
        self.assertEqual(domains.read_domains(FakePlesk(form([]))), [])
        self.assertEqual(domains.read_domains(FakePlesk(
            form([{'id': '', 'title': 'Please select'}]))), [])

    def test_http_failure_fail_closed(self):
        with self.assertRaises(PleskError):
            domains.read_domains(FakePlesk(form([{'id':1,'title':'example.org'}]), status=403))

    def test_json_output_and_log_do_not_contain_secrets(self):
        with tempfile.TemporaryDirectory() as d:
            logfile = Path(d)/'events.jsonl'
            client = FakePlesk(form([{'id': 23, 'title': 'example.org'}]))
            args = build_parser().parse_args(['domains', 'list', '--json'])
            output = StringIO()
            with redirect_stdout(output):
                self.assertEqual(domains.run(args, client, 'profil', 'panel.example.org', logfile), 0)
            payload = json.loads(output.getvalue())
            self.assertEqual(payload['schema_version'], 1)
            self.assertEqual(payload['scope'], 'subdomain_parent_domains')
            self.assertEqual(payload['domains'], [{'id':23, 'name':'example.org'}])
            self.assertEqual(client.requests, [(subdomain.CREATE_PATH, None)])
            events = [json.loads(x) for x in logfile.read_text().splitlines()]
            self.assertEqual([e['event'] for e in events], ['started', 'list_ok'])
            self.assertEqual(events[1]['count'], 1)
            self.assertNotIn('password', logfile.read_text().lower())
            self.assertNotIn('password', output.getvalue().lower())

    def test_no_json_from_failed_list_and_logged_as_failed(self):
        with tempfile.TemporaryDirectory() as d:
            logfile = Path(d)/'events.jsonl'
            args = build_parser().parse_args(['domains', 'list', '--json'])
            output = StringIO()
            with redirect_stdout(output):
                with self.assertRaises(PleskError):
                    domains.run(args, FakePlesk('<html>not plesk</html>'), 'profil',
                                'panel.example.org', logfile)
            self.assertEqual(output.getvalue(), '')
            self.assertIn('"event": "failed"', logfile.read_text())

    def test_cli_dispatch_uses_keyring_and_authenticated_session(self):
        fake = FakePlesk(form([{'id': 23, 'title': 'example.org'}]))
        class MockSession:
            def __init__(self, host, username, password):
                self.host = host
                self.username = username
                self.password = password
            def login(self):
                return '<html>authenticated</html>'
            def request(self, path, **kwargs):
                return fake.request(path, **kwargs)
        with tempfile.TemporaryDirectory() as d, \
             patch('plesk_webhosting.cli.accounts.find_profile',
                   return_value=('profil', {'host':'panel.example.org','user':'admin'})), \
             patch('plesk_webhosting.cli.accounts.get_password', return_value='supersecret'), \
             patch('plesk_webhosting.cli.PleskSession', MockSession):
            out = StringIO()
            with redirect_stdout(out):
                status = run(['--account','profil','--log',str(Path(d)/'events.jsonl'),
                              'domains','list','--json'])
            self.assertEqual(status, 0)
            self.assertEqual(json.loads(out.getvalue())['domains'], [{'id':23, 'name':'example.org'}])
            self.assertEqual(fake.requests, [(subdomain.CREATE_PATH, None)])
            self.assertNotIn('supersecret', out.getvalue())

    def test_cli_explicit_domain_is_rejected_before_login(self):
        err = StringIO()
        with redirect_stderr(err), self.assertRaises(SystemExit) as caught:
            run(['--domain','example.org','domains','list','--json'])
        self.assertEqual(caught.exception.code, 2)
        self.assertIn('weder --domain', err.getvalue())


if __name__ == '__main__':
    unittest.main()
