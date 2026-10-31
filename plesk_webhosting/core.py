"""Gemeinsamer Plesk-Kern: Session, Authentifizierung, Parser, Logs und POST-Sperre."""
from __future__ import annotations

from datetime import datetime, timezone
from contextlib import contextmanager
from contextvars import ContextVar
from html.parser import HTMLParser
import hashlib
import copy
import http.cookiejar
import json
import os
from pathlib import Path
import re
import secrets
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, build_opener, HTTPCookieProcessor, HTTPRedirectHandler

VERSION = '1.3.0'


def default_log_path():
    """Logdatei relativ zur Installation, unabhaengig vom Arbeitsverzeichnis."""
    return Path(__file__).resolve().parent.parent / 'logs' / 'events.jsonl'
SUBDOMAIN_CREATE_PATH = '/smb/web/add-subdomain'
SUBDOMAIN_DELETE_PATH = '/smb/web/domain-delete-async/'
SSL_WRITES = {
    '/modules/sslit/index.php/index/install/',
    '/modules/sslit/index.php/https-redirect/enable/',
    '/modules/sslit/index.php/https-redirect/disable/',
    '/modules/sslit/index.php/index/unsecure/',
}

class PleskError(Exception):
    """Abbruch bei unbekanntem oder unsicherem Plesk-Verhalten."""

class InlineParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.active = False
        self.fragments = []
        self.scripts = []
        self.csrf = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'script':
            self.active, self.fragments = True, []
        elif tag == 'meta' and attrs.get('name') == 'forgery_protection_token':
            self.csrf = attrs.get('content')

    def handle_data(self, data):
        if self.active:
            self.fragments.append(data)

    def handle_endtag(self, tag):
        if tag == 'script' and self.active:
            self.scripts.append(''.join(self.fragments))
            self.active = False


def parse_html(html):
    parser = InlineParser()
    parser.feed(html)
    return parser


def json_calls(scripts, prefix):
    decoder = json.JSONDecoder()
    for script in scripts:
        for match in re.finditer(r'\b' + re.escape(prefix) + r'\(\s*', script):
            try:
                payload, _ = decoder.raw_decode(script[match.end():])
            except (TypeError, ValueError):
                continue
            if isinstance(payload, dict):
                yield payload


def page_data(html):
    yield from json_calls(parse_html(html).scripts, 'Plesk.run')


def domain_id_from_view(html, domain):
    ids = set()
    for obj in page_data(html):
        first = obj.get('data')
        second = first.get('data') if isinstance(first, dict) else None
        items = second.get('data') if isinstance(second, dict) else None
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            name = str(item.get('displayName') or '').rstrip('.').casefold()
            domain_id = str(item.get('domainId') or '')
            if name == domain.casefold() and domain_id.isdecimal() and int(domain_id) > 0:
                ids.add(int(domain_id))
    if len(ids) != 1:
        raise PleskError('Domain-ID nicht eindeutig ermittelt. Fuer paginierte Listen --domain-id nutzen.')
    return ids.pop()


def valid_domain(value):
    return (isinstance(value, str) and len(value) <= 253 and
            bool(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+', value)))


class SameHostRedirect(HTTPRedirectHandler):
    def __init__(self, host):
        super().__init__()
        self.host = host

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        dest = urlsplit(newurl)
        if dest.scheme != 'https' or dest.hostname != self.host or dest.port not in (None, 443):
            raise PleskError('Umleitung auf fremden oder unverschluesselten Host gesperrt')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class PleskSession:
    """Pro Account eine Sitzung. Schreibberechtigung nur fuer exakte einmalige POST-Bytes."""
    def __init__(self, host, username, password):
        if not valid_domain(host):
            raise PleskError('Ungueltiger Plesk-Host')
        if not isinstance(username, str) or not username or not isinstance(password, str) or not password:
            raise PleskError('Fehlende Anmeldedaten')
        self.host = host
        self.base = 'https://' + host
        self.username = username
        self._password = password
        self.opener = build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()), SameHostRedirect(host))
        self.csrf = None
        self._write_grant = None
        self._write_consumed = False
        self._verified_writes = 0
        self._write_in_flight = False
        self._session_retired = False
        self._logout_confirmed = False

    def fork_authenticated_worker(self):
        """Eigenen HTTP-Client mit Kopie der bestehenden Login-Cookies erzeugen.

        Die Worker teilen die *serverseitige* Login-Identitaet, aber niemals
        CookieJar, HTTP-Opener oder Schreibfreigaben. Kein zweites Login.
        Nur nach erfolgreich abgeschlossenem login() aufrufen.
        """
        if not self.csrf or self._password is not None or self._session_retired:
            raise PleskError('Nur bestaetigte, aktive Sitzung darf kopiert werden')
        child = object.__new__(type(self))
        child.host = self.host
        child.base = self.base
        child.username = self.username
        child._password = None
        jar = http.cookiejar.CookieJar()
        for cookie in self.opener.handlers:
            if isinstance(cookie, HTTPCookieProcessor):
                for item in cookie.cookiejar:
                    jar.set_cookie(copy.copy(item))
        if not list(jar):
            raise PleskError('Keine Authentifizierungs-Cookies zum Kopieren vorhanden')
        child.opener = build_opener(HTTPCookieProcessor(jar), SameHostRedirect(self.host))
        child.csrf = self.csrf
        child._write_grant = None
        child._write_consumed = False
        child._verified_writes = 0
        child._write_in_flight = False
        child._session_retired = False
        child._logout_confirmed = False
        return child

    def close(self):
        """Lokale Cookies und Schreibfreigaben verwerfen; KEIN Server-Logout."""
        self.retire_writes()
        self.csrf = None
        self._password = None
        for handler in self.opener.handlers:
            if isinstance(handler, HTTPCookieProcessor):
                handler.cookiejar.clear()

    def logout_regression_check(self):
        """Einmaliger Logout-Live-Test, nicht Teil des normalen close().

        Nach positiv bestaetigtem Login wird die echte serverseitige Sitzung
        abgemeldet. Anschliessend wird mit DEMSELBEN HTTP-Client der Zugriff
        auf die geschuetzte Domainliste erneut getestet. Es werden weder
        Cookies noch Tokens ausgegeben oder protokolliert.
        """
        if self._password is not None or not self.csrf:
            raise PleskError('Logout-Test erfordert eine bestaetigte aktive Anmeldung')
        if self._write_grant is not None or self._write_in_flight:
            raise PleskError('Logout waehrend aktiver Schreibaktion gesperrt')
        self.retire_writes()
        headers = {'User-Agent': 'Plesk-Webhosting-Manager/' + VERSION}
        try:
            with self.opener.open(Request(self.base + '/logout.php', headers=headers,
                                          method='GET'), timeout=35) as response:
                target = urlsplit(response.geturl())
                if (target.scheme != 'https' or target.hostname != self.host or
                        target.port not in (None, 443)):
                    raise PleskError('Logout-Antwort ausserhalb des Plesk-Hosts')
                response.read(64_000)
                logout_status = response.status
            with self.opener.open(Request(self.base + '/smb/web/view', headers=headers,
                                          method='GET'), timeout=35) as response:
                target = urlsplit(response.geturl())
                if (target.scheme != 'https' or target.hostname != self.host or
                        target.port not in (None, 443)):
                    raise PleskError('Statuspruefung ausserhalb des Plesk-Hosts')
                response.read(64_000)
                verified = target.path in ('/login.php', '/login_up.php')
                self._logout_confirmed = verified
                return {'logout_http_status': logout_status,
                        'verification_path': target.path if target.path in
                            ('/login.php', '/login_up.php', '/smb/web/view') else '(other)',
                        'session_invalidated': verified}
        except HTTPError as exc:
            raise PleskError('Logout-Test: HTTP-Fehler, Sitzung nicht bestaetigt abgemeldet') from exc
        except URLError as exc:
            raise PleskError('Logout-Test: Plesk-HTTPS-Verbindung fehlgeschlagen') from exc

    def logout_on_exit(self):
        """Best effort: serverseitig abmelden, bevor lokale Cookies geloescht werden.

        Ausschliesslich nach authentifizierter Anmeldung und nie waehrend eines
        laufenden POST. Ein schon verifizierter Logout wird nicht wiederholt.
        """
        if self._logout_confirmed:
            return {'status': 'already_logged_out'}
        if self._password is not None or not self.csrf:
            return {'status': 'not_authenticated'}
        if self._write_in_flight:
            return {'status': 'blocked_in_flight'}
        # Etwaige nur lokal vorbereitete Schreibfreigaben widerrufen.
        self._write_grant = None
        try:
            result = self.logout_regression_check()
            return {'status': 'confirmed' if result['session_invalidated'] else 'unverified',
                    'verification_path': result['verification_path']}
        except (PleskError, OSError, TimeoutError) as exc:
            return {'status': 'failed', 'error_type': type(exc).__name__}

    def finish_verified_write(self, *, verified: bool):
        """Freigabe des naechsten Schreibvorgangs nur nach externer Statuspruefung.

        Der aufrufende Workflow muss nach dem POST den Zielzustand erneut lesen
        und eindeutig verifizieren. Bei unklarem Resultat wird diese Sitzung
        dauerhaft fuer weitere Schreibvorgaenge gesperrt. Keine Wiederholung.
        """
        if not self._write_consumed or self._write_grant is not None or self._session_retired:
            raise PleskError('Kein abgeschlossener Schreibvorgang zur Bestaetigung vorhanden')
        if type(verified) is not bool:
            raise PleskError('Verifikation muss ein boolescher Wert sein')
        if not verified:
            self._session_retired = True
            raise PleskError('Schreibstatus ungeklaert: Sitzung fuer weitere POSTs gesperrt')
        self._verified_writes += 1
        self._write_consumed = False

    def retire_writes(self):
        """Bei Netzwerkfehler oder unklarem Status keine neuen Writes zulassen."""
        self._session_retired = True
        self._write_grant = None

    def authorize_write_once(self, path, body, content_type):
        if (self._session_retired or self._write_consumed or self._write_grant is not None or
                not isinstance(body, bytes) or not isinstance(content_type, str)):
            raise PleskError('Schreibfreigabe ungueltig')
        if re.fullmatch(r'/smb/web/php-settings/id/[1-9][0-9]*', path):
            if (len(body) > 256_000 or not re.fullmatch(
                    r'multipart/form-data; boundary=----PleskPHPPlan[0-9a-f]{24}', content_type)):
                raise PleskError('PHP-Speicherfreigabe ungueltig')
        elif path in SSL_WRITES:
            if len(body) > 16_384 or content_type != 'application/json':
                raise PleskError('SSL-Speicherfreigabe ungueltig')
        elif path == SUBDOMAIN_CREATE_PATH:
            if not (0 < len(body) <= 32_000 and content_type == 'application/x-www-form-urlencoded'):
                raise PleskError('Subdomain-Erstellungsfreigabe ungueltig')
        elif path == SUBDOMAIN_DELETE_PATH:
            if content_type != 'application/json' or len(body) > 1024 or len(body) < 12:
                raise PleskError('Subdomain-Loeschfreigabe: unerwartetes Format')
            try:
                data = json.loads(body)
            except (UnicodeError, ValueError, TypeError) as exc:
                raise PleskError('Subdomain-Loeschfreigabe: ungueltiges JSON') from exc
            if (not isinstance(data, dict) or set(data) != {'ids'} or
                    not isinstance(data['ids'], list) or len(data['ids']) != 1 or
                    not isinstance(data['ids'][0], str) or
                    not re.fullmatch(r'domain:[1-9][0-9]*', data['ids'][0])):
                raise PleskError('Subdomain-Loeschfreigabe: keine einzelne Domain-ID')
        else:
            raise PleskError('Schreiben an unbekannten Plesk-Endpunkt gesperrt')
        self._write_grant = (path, hashlib.sha256(body).digest(), content_type)

    def request(self, path, *, body=None, headers=None, max_bytes=5_000_000):
        if not isinstance(path, str) or not path.startswith('/') or path.startswith('//') or '?' in path or '#' in path:
            raise PleskError('Unerwarteter Anfragepfad')
        if not 1 <= max_bytes <= 5_000_000:
            raise PleskError('Ungueltige Antwortgrenze')
        prepared = {'User-Agent': 'Plesk-Webhosting-Manager/' + VERSION,
                    'Accept': 'text/html,application/json;q=0.9,*/*;q=0.8'}
        prepared.update(headers or {})
        if body is not None:
            if path not in ('/login_up.php', '/cp/graphql'):
                if (self._write_grant is None or self._write_consumed or
                        path != self._write_grant[0] or not isinstance(body, bytes) or
                        not secrets.compare_digest(hashlib.sha256(body).digest(), self._write_grant[1]) or
                        prepared.get('Content-Type') != self._write_grant[2] or not self.csrf):
                    raise PleskError('Nicht autorisierter Plesk-Schreib-POST blockiert')
                self._write_grant = None
                self._write_consumed = True  # vor jeder Netzwerkaktivitaet verbrauchen
            prepared['X-Requested-With'] = 'XMLHttpRequest'
            prepared['Origin'] = self.base
            if self.csrf:
                prepared['X-Forgery-Protection-Token'] = self.csrf
        req = Request(self.base + path, data=body, headers=prepared,
                      method='POST' if body is not None else 'GET')
        try:
            with self.opener.open(req, timeout=35) as resp:
                content = resp.read(max_bytes + 1)
                if len(content) > max_bytes:
                    raise PleskError('Plesk-Antwort unerwartet gross')
                final = urlsplit(resp.url)
                if final.scheme != 'https' or final.hostname != self.host or final.port not in (None, 443):
                    raise PleskError('Unerwartete Antwort-URL')
                return resp.status, content.decode('utf-8', 'replace'), resp.headers.get('Content-Type', '')
        except HTTPError as exc:
            raise PleskError(f'Plesk antwortet mit HTTP {exc.code}') from exc
        except URLError as exc:
            raise PleskError('Plesk-HTTPS-Verbindung fehlgeschlagen') from exc

    def update_csrf(self, html):
        meta = parse_html(html).csrf
        if meta:
            if not re.fullmatch(r'[A-Za-z0-9_-]{16,256}', meta):
                raise PleskError('CSRF-Tokenformat unbekannt')
            self.csrf = meta

    def login(self):
        code, html, _ = self.request('/login_up.php')
        if code != 200:
            raise PleskError('Plesk-Anmeldeseite nicht erreichbar')
        self.update_csrf(html)
        if not self.csrf:
            raise PleskError('CSRF-Anmeldetoken fehlt')
        login = urlencode({'login_name': self.username, 'passwd': self._password,
                           'locale_id': 'default', 'send': 'Anmelden'}).encode('utf-8')
        self._password = None
        try:
            code, _, _ = self.request('/login_up.php', body=login,
                                      headers={'Content-Type': 'application/x-www-form-urlencoded'})
        finally:
            del login
        if code != 200:
            raise PleskError('Plesk-Anmeldung fehlgeschlagen')
        code, view, _ = self.request('/smb/web/view')
        if code != 200:
            raise PleskError('Plesk-Domainliste nicht erreichbar')
        self.update_csrf(view)
        graph_query = json.dumps({'query': 'query LoginCheck { viewer { login } }'}).encode('utf-8')
        code, payload, _ = self.request('/cp/graphql', body=graph_query,
                                        headers={'Content-Type': 'application/json'})
        if code != 200:
            raise PleskError('GraphQL-Anmeldung nicht bestaetigt')
        try:
            viewer = json.loads(payload)['data']['viewer']['login']
            if not isinstance(viewer, str) or not viewer:
                raise ValueError
            # Plesk kann Account-Identitaet unterschiedlich darstellen; Viewer muss dennoch belegt sein.
        except (ValueError, TypeError, AttributeError, KeyError) as exc:
            raise PleskError('Keine bestaetigte Plesk-Sitzung') from exc
        return view


# The parent ID is distinct from Plesk's individual run_id and only controls
# metadata in the local JSONL log. No access tokens or passwords are propagated.
_PARENT_OPERATION_ID = ContextVar('plesk_parent_operation_id', default='')


@contextmanager
def correlation_context(operation_id=None):
    token = _PARENT_OPERATION_ID.set(operation_id or '')
    try:
        yield
    finally:
        _PARENT_OPERATION_ID.reset(token)


def log_event(logfile, run_id, event, *, section, **values):
    """Append safe JSONL metadata; `values` may contain a request field named `path`.

    Keep `logfile` distinct from event metadata keys to avoid an argument
    collision before the first write POST (PHP and SSL both log `path`).
    """
    logfile = Path(logfile)
    logfile.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    old_umask = os.umask(0o077)
    try:
        fd = os.open(logfile, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    finally:
        os.umask(old_umask)
    with os.fdopen(fd, 'a', encoding='utf-8') as fh:
        payload = {'time': datetime.now(timezone.utc).isoformat(timespec='seconds'),
                   'action': 'plesk-webhosting', 'version': VERSION,
                   'section': section, 'run_id': run_id, 'event': event, **values}
        parent_id = _PARENT_OPERATION_ID.get()
        if parent_id:
            payload['operation_id'] = parent_id
        fh.write(json.dumps(payload, ensure_ascii=False) + '\n')
