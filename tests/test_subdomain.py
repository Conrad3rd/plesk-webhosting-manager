"""Subdomain-Mocks: keinerlei Netzwerk, keine Aenderungen an Plesk."""
from contextlib import redirect_stdout
from io import StringIO
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from urllib.parse import parse_qs

from plesk_webhosting import subdomain
from plesk_webhosting.cli import build_parser, run
from plesk_webhosting.core import PleskError, PleskSession, SUBDOMAIN_DELETE_PATH


PARENT = 'example.org'
TARGET = 'test.example.org'
ROOT = 'test.example.org/public'
CSRF = 'a' * 32


def view_html(created=False, *, complete=True):
    items = [dict(displayName=PARENT, domainId=100, isSubdomain=False,
                  webrootDir='example.org/httpdocs')]
    if created:
        items.append(dict(displayName=TARGET, domainId=120, isSubdomain=True,
                          isRemovable=True, webrootDir=ROOT,
                          parentDomain=dict(id=100, displayName=PARENT)))
    data = {'data': {'data': {'data': items,
            'pager': dict(totalItemCount=len(items) if complete else 99,
                          pageCount=1 if complete else 4, current=1)}}}
    return '<script>Plesk.run(' + json.dumps(data) + ')</script>'


def form_html():
    return ('<meta name="forgery_protection_token" content="' + CSRF + '">'
            '<form id="smb-form-final-web-addsubdomain" method="POST">'
            '<input type="text" name="domainName[name]" value="">'
            '<input type="hidden" name="hostingType[hosting]" value="hosting">'
            '<input type="text" name="hostingSettings[root]" value="">'
            '<input type="hidden" name="hostingSettings[rootPattern]" value="&lt;domain&gt;/httpdocs">'
            '<input type="hidden" name="sslit[enabled]" value="0">'
            '<input type="hidden" name="forgery_protection_token" value="' + CSRF + '">'
            '</form><script>new Jsw.LookUp(' + json.dumps({
                'applyTo': 'domainName-domain', 'name': 'domainName[domain]',
                'data': [{'title': PARENT, 'id': 100}]}) + ')</script>')


class FakeSession:
    def __init__(self):
        self.created = False
        self.csrf = CSRF
        self.base = 'https://panel.example.org'
        self.requests = []
        self.grants = []

    def request(self, path, *, body=None, headers=None, max_bytes=None):
        self.requests.append((path, body))
        if path == '/smb/web/view' and body is None:
            return 200, view_html(self.created), 'text/html'
        if path == subdomain.CREATE_PATH and body is None:
            return 200, form_html(), 'text/html'
        if path == subdomain.CREATE_PATH and body:
            assert len(self.grants) == 1
            assert self.grants[0][0] == path
            assert self.grants[0][1] == body
            self.created = True
            return 200, '{"status":"ok"}', 'application/json'
        raise AssertionError('Unerwartete Anfrage: ' + path)

    def update_csrf(self, html):
        pass

    def authorize_write_once(self, path, body, content_type):
        self.grants.append((path, body, content_type))




class FakeDeleteSession(FakeSession):
    def __init__(self):
        super().__init__()
        self.created = True
        self.deleted = False
        self.additional_writes = 0
        self.preflight_changed = False
        self.after_delete_incomplete = False
        self.remove_parent_after_delete = False

    def request(self, path, *, body=None, headers=None, max_bytes=None):
        self.requests.append((path, body))
        if path == '/smb/web/view' and body is None:
            if self.preflight_changed and len(self.requests) >= 1 and not self.deleted:
                return 200, '<meta name="forgery_protection_token" content="' + CSRF + '">' + view_html(False), 'text/html'
            if self.deleted:
                if self.remove_parent_after_delete:
                    return 200, '<script>Plesk.run(' + json.dumps({'data':{'data':{
                        'data': [], 'pager': {'totalItemCount': 0, 'pageCount': 1, 'current': 1}}}}) + ')</script>', 'text/html'
                return 200, '<meta name="forgery_protection_token" content="' + CSRF + '">' + view_html(False, complete=not self.after_delete_incomplete), 'text/html'
            return 200, '<meta name="forgery_protection_token" content="' + CSRF + '">' + view_html(True), 'text/html'
        if path == SUBDOMAIN_DELETE_PATH and body is not None:
            assert len(self.grants) == 1
            assert self.grants[0] == (path, body, 'application/json')
            assert body == b'{"ids":["domain:120"]}'
            self.deleted = True
            return 200, '{"status":"ok"}', 'application/json'
        raise AssertionError('Unbekannte Anfrage: '+path)

def opts(**kw):
    values = dict(domain=TARGET, parent_domain=PARENT, check=False, plan=True,
                  apply=False, operation='create', document_root=ROOT,
                  confirm_create=None, confirm_delete=None, confirm_delete_id=None,
                  yes=False, verify_attempts=2, verify_interval=0)
    values.update(kw)
    return SimpleNamespace(**values)


class SubdomainTests(unittest.TestCase):
    def test_parser_and_selftest(self):
        args = build_parser().parse_args(['--account', 'hosting-1', '--domain', TARGET,
                                          'subdomain', '--plan', '--parent-domain', PARENT,
                                          '--document-root', ROOT])
        self.assertEqual(args.document_root, ROOT)
        with redirect_stdout(StringIO()):
            self.assertEqual(run(['self-test']), 0)
            self.assertEqual(run(['subdomain','--self-test']), 0)

    def test_synthetic_form_and_csrf(self):
        parent_id, fields, body, _ = subdomain.build_create_request(form_html(), PARENT, 'test', ROOT)
        self.assertEqual(parent_id, 100)
        self.assertEqual(parse_qs(body.decode())['hostingSettings[root]'], [ROOT])
        self.assertEqual(dict(fields)['domainName[domain]'], '100')
        with self.assertRaises(PleskError):
            subdomain.build_create_request(form_html().replace(CSRF, 'b'*32, 1), PARENT, 'test', ROOT)

    def test_only_known_subdomain_create_endpoint_authorized(self):
        sess = PleskSession('panel.example.org','abc','pw')
        with self.assertRaises(PleskError):
            sess.authorize_write_once('/smb/web/delete-subdomain', b'id=120',
                                      'application/x-www-form-urlencoded')
        with self.assertRaises(PleskError):
            sess.authorize_write_once(subdomain.CREATE_PATH, b'foo', 'application/json')
        sess.authorize_write_once(subdomain.CREATE_PATH, b'body', 'application/x-www-form-urlencoded')
        self.assertIsNotNone(sess._write_grant)

    def test_plan_and_apply_exact_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / 'events.jsonl'
            client = FakeSession()
            with redirect_stdout(StringIO()) as output:
                self.assertEqual(subdomain.run(opts(), client, view_html(), log, 'plan-1'), 0)
            self.assertEqual(len(client.grants), 0)
            self.assertFalse(any(body is not None for _,body in client.requests))
            with redirect_stdout(StringIO()) as output:
                self.assertEqual(subdomain.run(opts(plan=False, apply=True, yes=True,
                                                      confirm_create=TARGET),
                                               client, view_html(), log, 'apply-1'), 0)
            self.assertTrue(client.created)
            self.assertEqual(len(client.grants), 1)
            self.assertEqual(sum(body is not None for _,body in client.requests), 1)
            self.assertIn('Dokumentenstamm: OK', output.getvalue())
            self.assertNotIn(CSRF, log.read_text())

    def test_delete_plan_does_not_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = FakeDeleteSession()
            with redirect_stdout(StringIO()) as out:
                self.assertEqual(subdomain.run(opts(operation='delete'), client,
                                               view_html(True), Path(tmp)/'events', 'test'), 0)
            self.assertIn('SIMULATION', out.getvalue())
            self.assertFalse(client.grants)
            self.assertFalse(any(body is not None for _, body in client.requests))

    def test_delete_apply_requires_all_confirmations(self):
        with tempfile.TemporaryDirectory() as tmp:
            for wrong in (dict(confirm_delete=None), dict(confirm_delete=PARENT),
                          dict(confirm_delete_id=100), dict(confirm_delete_id=121),
                          dict(document_root='incorrect-root/public'), dict(yes=False)):
                args = dict(operation='delete', plan=False, apply=True, yes=True,
                            confirm_delete=TARGET, confirm_delete_id=120, document_root=ROOT)
                args.update(wrong)
                client = FakeDeleteSession()
                with self.assertRaises(PleskError):
                    with redirect_stdout(StringIO()):
                        subdomain.run(opts(**args), client, view_html(True), Path(tmp)/'events', 'test')
                self.assertFalse(client.grants)
                self.assertFalse(any(body is not None for _, body in client.requests))

    def test_delete_apply_exact_once_and_independent_confirmation(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = FakeDeleteSession()
            log = Path(tmp)/'events.jsonl'
            with redirect_stdout(StringIO()) as out:
                self.assertEqual(subdomain.run(opts(operation='delete', plan=False, apply=True, yes=True,
                                                    confirm_delete=TARGET, confirm_delete_id=120),
                                               client, view_html(True), log, 'run'), 0)
            self.assertTrue(client.deleted)
            self.assertEqual(len(client.grants), 1)
            self.assertEqual(sum(body is not None for _, body in client.requests), 1)
            self.assertIn('ERFOLG', out.getvalue())
            events = [json.loads(line) for line in log.read_text().splitlines()]
            self.assertIn('delete_verified', [entry['event'] for entry in events])
            self.assertNotIn(CSRF, log.read_text())

    def test_delete_preflight_change_blocks_post(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = FakeDeleteSession()
            client.preflight_changed = True
            with self.assertRaises(PleskError):
                with redirect_stdout(StringIO()):
                    subdomain.run(opts(operation='delete', plan=False, apply=True, yes=True,
                                       confirm_delete=TARGET, confirm_delete_id=120),
                                  client, view_html(True), Path(tmp)/'events', 'test')
            self.assertFalse(client.grants)
            self.assertFalse(any(body is not None for _, body in client.requests))

    def test_delete_incomplete_after_post_never_resends(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = FakeDeleteSession()
            client.after_delete_incomplete = True
            with self.assertRaises(PleskError):
                with redirect_stdout(StringIO()):
                    subdomain.run(opts(operation='delete', plan=False, apply=True, yes=True,
                                       confirm_delete=TARGET, confirm_delete_id=120),
                                  client, view_html(True), Path(tmp)/'events', 'test')
            self.assertTrue(client.deleted)
            self.assertEqual(sum(body is not None for _, body in client.requests), 1)

    def test_delete_parent_removal_not_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = FakeDeleteSession()
            client.remove_parent_after_delete = True
            with self.assertRaises(PleskError):
                with redirect_stdout(StringIO()):
                    subdomain.run(opts(operation='delete', plan=False, apply=True, yes=True,
                                       confirm_delete=TARGET, confirm_delete_id=120),
                                  client, view_html(True), Path(tmp)/'events', 'test')
            self.assertEqual(sum(body is not None for _, body in client.requests), 1)

    def test_delete_endpoint_authorization_rejects_wrong_payloads(self):
        for payload, content_type in [
                (b'{"ids":["domain:120","domain:100"]}', 'application/json'),
                (b'{"ids":["subdomain:120"]}', 'application/json'),
                (b'{"ids":["domain:120"],"flag":true}', 'application/json'),
                (b'{"ids":["domain:120"]}', 'application/x-www-form-urlencoded'),
                (b'not-json', 'application/json')]:
            session = PleskSession('panel.example.org', 'abc','pw')
            with self.assertRaises(PleskError):
                session.authorize_write_once(SUBDOMAIN_DELETE_PATH, payload, content_type)
        session = PleskSession('panel.example.org', 'abc', 'pw')
        session.authorize_write_once(SUBDOMAIN_DELETE_PATH,
                                     b'{"ids":["domain:120"]}', 'application/json')
        self.assertIsNotNone(session._write_grant)

    def test_cli_delete_requires_confirmation_before_login(self):
        with redirect_stdout(StringIO()):
            args = build_parser().parse_args([
                '--domain', TARGET, 'subdomain', '--apply', '--operation', 'delete',
                '--parent-domain', PARENT, '--document-root', ROOT,
                '--confirm-delete', TARGET, '--confirm-delete-id', '120', '--yes'])
        self.assertEqual(args.confirm_delete_id, 120)

    def test_pagination_and_parent_protection(self):
        items = subdomain.domain_list(view_html(complete=False))
        self.assertFalse(items.complete)
        with self.assertRaises(PleskError):
            subdomain.exact_entry(items, TARGET)
        with self.assertRaises(PleskError):
            subdomain.check_subdomain(subdomain.exact_entry(
                subdomain.domain_list(view_html(True)), TARGET), TARGET, 'wrong.example.org', 100)


if __name__ == '__main__':
    unittest.main()
