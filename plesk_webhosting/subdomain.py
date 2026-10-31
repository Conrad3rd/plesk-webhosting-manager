"""Plesk-Subdomains verwalten: Lesen, Anlegen und kontrolliertes Loeschen.

Bei jedem Schreibvorgang gilt eine Einmal-POST-Sperre mit Nachpruefung.
"""
from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser
import json
import re
import secrets
import sys
import time
from urllib.parse import urlencode

from .core import PleskError, SUBDOMAIN_DELETE_PATH, log_event, page_data, parse_html, valid_domain

CREATE_PATH = '/smb/web/add-subdomain'
FIELD_NAME = 'domainName[name]'
FIELD_PARENT = 'domainName[domain]'
FIELD_ROOT = 'hostingSettings[root]'
SUBDOMAIN_FIELD_SET = {FIELD_NAME, 'hostingType[hosting]', FIELD_ROOT,
                       'hostingSettings[rootPattern]', 'sslit[enabled]',
                       'forgery_protection_token'}
FIELD_PATTERN = re.compile(r'(?:domainName\[(?:name|domain)\]|hostingType\[hosting\]|'
                           r'hostingSettings\[(?:root|rootPattern)\]|'
                           r'sslit\[[A-Za-z0-9_]+\]|forgery_protection_token|hidden)')


@dataclass(frozen=True)
class DomainList:
    entries: list[dict]
    complete: bool


def domain_list(html):
    """Einzigartiges Domain-Listenpayload, inkl. Plesk-Pagination."""
    found = []
    for obj in page_data(html):
        outer = obj.get('data')
        payload = outer.get('data') if isinstance(outer, dict) else None
        entries = payload.get('data') if isinstance(payload, dict) else None
        pager = payload.get('pager') if isinstance(payload, dict) else None
        if isinstance(entries, list) and isinstance(pager, dict):
            if not all(isinstance(x, dict) for x in entries):
                raise PleskError('Plesk-Domainliste enthaelt ungueltige Elemente')
            total, pages, current = (pager.get('totalItemCount'), pager.get('pageCount'),
                                     pager.get('current'))
            state = payload.get('state')
            filters = state.get('searchFilters', {}) if isinstance(state, dict) else {}
            filtered = not isinstance(filters, dict)
            if isinstance(filters, dict):
                for spec in filters.values():
                    if not isinstance(spec, dict):
                        filtered = True
                        break
                    if any(str(v or '').strip() for v in spec.values()):
                        filtered = True
                        break
            complete = (type(total) is int and total == len(entries)
                        and pages == 1 and current == 1 and not filtered)
            found.append(DomainList(entries, complete))
    if len(found) != 1:
        raise PleskError('Plesk-Domainliste nicht eindeutig erkennbar')
    return found[0]


def exact_entry(listing, fqdn):
    rows = [r for r in listing.entries
            if str(r.get('displayName') or '').rstrip('.').casefold() == fqdn.casefold()]
    if len(rows) > 1:
        raise PleskError('Doppelte Ziel-Subdomain in Plesk-Domainliste')
    if not rows:
        if not listing.complete:
            raise PleskError('Ziel fehlt in paginierter/gefilterter Domainliste; Abwesenheit nicht beweisbar')
        return None
    row = rows[0]
    if not str(row.get('domainId') or '').isdecimal() or int(row['domainId']) <= 0:
        raise PleskError('Ziel-Subdomain besitzt keine gueltige ID')
    return row


def check_subdomain(row, fqdn, parent, parent_id):
    if not isinstance(row, dict) or row.get('isSubdomain') is not True:
        raise PleskError('Die Zieldomain ist laut Plesk keine Subdomain')
    info = row.get('parentDomain')
    if (not isinstance(info, dict) or
        str(info.get('id')) != str(parent_id) or
        str(info.get('displayName') or '').casefold() != parent.casefold() or
        str(row.get('displayName') or '').casefold() != fqdn.casefold()):
        raise PleskError('Plesk-Ziel stimmt nicht mit der Hauptdomain ueberein')
    root = row.get('webrootDir')
    if not isinstance(root, str) or not root:
        raise PleskError('Plesk liefert keinen Dokumentenstamm fuer die Subdomain')
    return root


def valid_root(root):
    """Webspace-relativer UNIX-Pfad; keine Traversals, Absolute oder NULs."""
    return (isinstance(root, str) and 1 <= len(root) <= 240 and not root.startswith('/')
            and not root.endswith('/') and '\\' not in root and '\x00' not in root
            and not any(ch in root for ch in ('\r', '\n', '\t', '?', '#'))
            and all(x not in ('', '.', '..') and re.fullmatch(r'[A-Za-z0-9._-]+', x)
                    for x in root.split('/')))


class CreationForm(HTMLParser):
    """Verwendet genau das Formular und die vorhandenen Hidden-Felder."""
    def __init__(self):
        super().__init__()
        self.active = False
        self.found = False
        self.method = ''
        self.action = ''
        self.fields = []
        self.scripts = []
        self.in_script = False
        self.parts = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == 'form' and a.get('id') == 'smb-form-final-web-addsubdomain':
            if self.found:
                raise PleskError('Mehrere Subdomain-Erstellungsformulare')
            self.found, self.active = True, True
            self.method = (a.get('method') or 'GET').upper()
            self.action = a.get('action') or ''
        elif tag == 'script':
            self.in_script, self.parts = True, []
        elif tag == 'input' and self.active:
            name = a.get('name')
            if not name or 'disabled' in a:
                return
            typ = (a.get('type') or 'text').lower()
            if typ in ('checkbox', 'radio') and 'checked' not in a:
                return
            if typ in ('file', 'button', 'image', 'submit'):
                return
            self.fields.append((name, a.get('value') or ''))

    def handle_data(self, data):
        if self.in_script:
            self.parts.append(data)

    def handle_endtag(self, tag):
        if tag == 'form' and self.active:
            self.active = False
        if tag == 'script' and self.in_script:
            self.scripts.append(''.join(self.parts))
            self.in_script = False


def selectable_parent_domains(form):
    """Hauptdomains aus der Plesk-Subdomain-Auswahl, ohne POST.

    Nur explizite, eindeutige Lookup-Eintraege werden zurueckgegeben. Bei
    unbekanntem Formularformat keine vermuteten/gespeicherten Domains liefern.
    """
    if not form.found or form.method != 'POST' or form.action not in ('', CREATE_PATH):
        raise PleskError('Plesk-Subdomain-Auswahlformular fehlt oder ist unbekannt')
    decoder = json.JSONDecoder()
    matches = []
    for script in form.scripts:
        for match in re.finditer(r'new\s+Jsw\.LookUp\s*\(\s*', script):
            try:
                obj, _ = decoder.raw_decode(script[match.end():])
            except (ValueError, TypeError):
                continue
            if (isinstance(obj, dict) and obj.get('applyTo') == 'domainName-domain'
                    and obj.get('name') == FIELD_PARENT):
                matches.append(obj)
    if len(matches) != 1 or not isinstance(matches[0].get('data'), list):
        raise PleskError('Plesk-Hauptdomain-Auswahl nicht eindeutig vorhanden')

    result = []
    names, identifiers = set(), set()
    for option in matches[0]['data']:
        if not isinstance(option, dict):
            raise PleskError('Unbekanntes Element in Plesk-Hauptdomain-Auswahl')
        name_value = option.get('title')
        raw_id = option.get('id')
        domain = name_value.strip().rstrip('.').lower() if isinstance(name_value, str) else ''
        # Leere Auswahloptionen (z. B. "Bitte auswaehlen") sind keine Domains.
        if raw_id in ('', None, 0) and not valid_domain(domain):
            continue
        if (not valid_domain(domain) or isinstance(raw_id, bool)
                or not str(raw_id).isdecimal() or len(str(raw_id)) > 18
                or int(raw_id) < 1):
            raise PleskError('Ungueltiger Domainname oder Domain-ID in Plesk-Auswahl')
        domain_id = int(raw_id)
        if domain in names or domain_id in identifiers:
            raise PleskError('Doppelte Hauptdomain oder ID in Plesk-Auswahl')
        names.add(domain)
        identifiers.add(domain_id)
        result.append({'name': domain, 'id': domain_id})
    return sorted(result, key=lambda item: item['name'])


def parent_lookup(form, parent):
    choices = [item for item in selectable_parent_domains(form)
               if item['name'] == parent.casefold()]
    if len(choices) != 1:
        raise PleskError('Hauptdomain ist im aktuellen Plesk-Formular nicht eindeutig auswaehlbar')
    return choices[0]['id']


def build_create_request(html, parent, label, root):
    if not valid_domain(parent) or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label):
        raise PleskError('Ungueltiger Hauptdomain- oder Subdomainname')
    if not valid_root(root):
        raise PleskError('Ungueltiger relativer Dokumentenstamm')
    form = CreationForm()
    form.feed(html)
    if not form.found or form.method != 'POST' or form.action not in ('', CREATE_PATH):
        raise PleskError('Plesk-Erstellungsformular fehlt oder verwendet einen unerwarteten Endpunkt')
    names = [key for key, _ in form.fields]
    if not SUBDOMAIN_FIELD_SET.issubset(names):
        raise PleskError('Plesk-Erstellungsformular enthaelt nicht alle Pflichtfelder')
    if any(not FIELD_PATTERN.fullmatch(key) for key in names):
        raise PleskError('Unbekannte Felder im Plesk-Erstellungsformular')
    for key in SUBDOMAIN_FIELD_SET - {'sslit[enabled]'}:
        if names.count(key) != 1:
            raise PleskError('Pflichtfeld fehlt oder ist doppelt: ' + key)
    if names.count(FIELD_PARENT) > 1:
        raise PleskError('Doppelte Hauptdomain-Auswahl')
    values = dict(form.fields)
    if values.get('hostingType[hosting]') != 'hosting':
        raise PleskError('Unbekannter Hosting-Typ')
    meta = parse_html(html).csrf
    csrf = values.get('forgery_protection_token')
    if not meta or not isinstance(csrf, str) or not secrets.compare_digest(meta, csrf):
        raise PleskError('CSRF-Token aus HTML-Meta und Formular stimmen nicht ueberein')
    parent_id = parent_lookup(form, parent)
    fields = []
    for key, value in form.fields:
        if key == FIELD_NAME:
            value = label
        elif key == FIELD_PARENT:
            value = str(parent_id)
        elif key == FIELD_ROOT:
            value = root
        fields.append((key, value))
    if FIELD_PARENT not in names:
        fields.append((FIELD_PARENT, str(parent_id)))
    encoded = urlencode(fields).encode('utf-8')
    if len(encoded) > 32_000:
        raise PleskError('Subdomain-Anfrage unerwartet gross')
    from urllib.parse import parse_qsl
    if parse_qsl(encoded.decode('utf-8'), keep_blank_values=True) != fields:
        raise PleskError('Subdomain-POST-Bytes weichen vom Formular ab')
    return parent_id, fields, encoded, csrf


def report_server_reply(text, content_type, http_code):
    if http_code >= 400:
        return 'error'
    if 'json' not in (content_type or '').lower():
        return 'unknown'
    try:
        value = json.loads(text)
    except ValueError:
        return 'unknown'
    if isinstance(value, dict):
        if value.get('success') is False or value.get('errors') or value.get('error') or str(value.get('status')).lower() in ('failed','error'):
            return 'error'
        if value.get('success') is True or str(value.get('status')).lower() in ('ok','success'):
            return 'ok'
    return 'unknown'


def build_delete_request(row, fqdn, parent, parent_id, expected_root):
    """Genaue JSON-Struktur aus der blockierten Playwright-Aufzeichnung.

    Identitaet und Berechtigung kommen ausschliesslich aus der aktuellen
    Plesk-Domainliste. Nie eine vom Anwender frei gewaehlte ID uebermitteln.
    """
    actual_root = check_subdomain(row, fqdn, parent, parent_id)
    if row.get('isRemovable') is not True:
        raise PleskError('Diese Subdomain ist laut Plesk nicht entfernbar')
    if not valid_root(actual_root):
        raise PleskError('Dokumentenstamm aus Plesk ist fuer Loeschfreigabe ungueltig')
    if expected_root is not None and actual_root != expected_root:
        raise PleskError('Dokumentenstamm weicht von --document-root ab; STOP')
    domain_id = int(row['domainId'])
    if domain_id == parent_id or domain_id <= 0:
        raise PleskError('Loeschziel ist eine Hauptdomain oder besitzt eine ungueltige ID')
    # Playwright hat exakt ein JSON-Feld ids[0] als getypten Identifier
    # mit der Laenge 12 fuer 10445 beobachtet: domain:10445.
    body = json.dumps({'ids': [f'domain:{domain_id}']},
                      separators=(',', ':'), ensure_ascii=True).encode('ascii')
    assert json.loads(body)['ids'] == [f'domain:{domain_id}']
    return domain_id, actual_root, body


def _verified_delete_absence(html, fqdn, parent, parent_id, original_ids):
    """Nur eine vollstaendige Plesk-Liste beweist die Abwesenheit."""
    listing = domain_list(html)
    if not listing.complete:
        return False, 'Domainliste nicht vollstaendig'
    if exact_entry(listing, fqdn) is not None:
        return False, 'Subdomain noch vorhanden'
    parent_rows = [r for r in listing.entries
                   if str(r.get('displayName') or '').rstrip('.').casefold() == parent.casefold()]
    if len(parent_rows) != 1 or int(parent_rows[0].get('domainId') or 0) != parent_id:
        raise PleskError('KRITISCH: Hauptdomain ist nach Loeschung nicht eindeutig vorhanden')
    current_ids = {int(x['domainId']) for x in listing.entries
                   if str(x.get('domainId') or '').isdecimal()}
    missing_other = (original_ids - current_ids)
    if missing_other:
        raise PleskError('KRITISCH: Weitere zuvor vorhandene Domain-IDs fehlen in Plesk!')
    return True, 'Ziel fehlt; Hauptdomain und andere Domains vorhanden'


def run(args, client, view, logfile, run_id):
    """Je Schreibaktion exakt ein gepruefter POST, danach nur GET-Verifikation."""
    parent = args.parent_domain.strip().rstrip('.').lower()
    fqdn = args.domain
    label = fqdn[:-(len(parent) + 1)] if fqdn.endswith('.' + parent) else ''
    if not valid_domain(parent) or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label):
        raise PleskError('Ziel muss eine unmittelbare Subdomain von --parent-domain sein')
    listing = domain_list(view)
    target = exact_entry(listing, fqdn)
    parent_rows = [r for r in listing.entries
                   if str(r.get('displayName') or '').casefold() == parent]
    known_parent_id = None
    if len(parent_rows) == 1:
        known_parent_id = int(parent_rows[0]['domainId'])
    elif len(parent_rows) > 1:
        raise PleskError('Doppelte Hauptdomain in Plesk')
    # Ohne parentDomain-ID aus der aktuellen Liste ist kein Loeschen moeglich.
    if target:
        info = target.get('parentDomain') or {}
        if not isinstance(info, dict) or str(info.get('displayName') or '').casefold() != parent:
            raise PleskError('Ziel ist keiner eindeutigen Hauptdomain zugeordnet')
        if known_parent_id is not None and str(info.get('id')) != str(known_parent_id):
            raise PleskError('Hauptdomain-ID widerspricht der Ziel-Subdomain')
        known_parent_id = int(info['id'])
        actual_root = check_subdomain(target, fqdn, parent, known_parent_id)
    else:
        actual_root = None
    log_event(logfile, run_id, 'subdomain_status', section='subdomain', domain_id=target.get('domainId') if target else None,
              parent=parent, parent_domain_id=known_parent_id, exists=bool(target),
              document_root=actual_root, domain_list_complete=listing.complete)
    print('=== Subdomain-Verwaltung (Python/HTTPS) ===')
    print('Subdomain:', fqdn)
    print('Hauptdomain:', parent, '| ID:', known_parent_id if known_parent_id else 'noch nicht ermittelt')
    print('Status:', 'vorhanden' if target else 'nicht in vollstaendiger Plesk-Liste vorhanden')
    if target:
        print('Subdomain-ID:', target['domainId'])
        print('Dokumentenstamm:', actual_root)
    if args.check:
        print('Nur gelesen. Keine Aenderung vorgenommen.')
        return 0
    if args.operation == 'delete':
        if not target:
            if not listing.complete:
                raise PleskError('Subdomain-Abwesenheit nicht sicher nachweisbar')
            print('Keine Loeschung notwendig: Subdomain nicht vorhanden.')
            return 0
        if not listing.complete:
            raise PleskError('Loeschung erfordert eine vollstaendige, ungefilterte Domainliste')
        if known_parent_id is None:
            raise PleskError('Hauptdomain-ID konnte nicht verifiziert werden')
        domain_id, actual_root, body = build_delete_request(
            target, fqdn, parent, known_parent_id, args.document_root)
        print('Loeschziel:', fqdn, '| ID:', domain_id)
        print('Aktueller Dokumentenstamm:', actual_root)
        print('HTTP-POST (verifiziertes Schema):', SUBDOMAIN_DELETE_PATH)
        print('JSON-Feld: ids[0] = domain:<ermittelte-ID>')
        print('ACHTUNG: Plesk kann beim Loeschen auch Webdateien und Verzeichnisse entfernen!')
        log_event(logfile, run_id, 'delete_plan', section='subdomain',
                  domain_id=domain_id, parent_id=known_parent_id,
                  document_root=actual_root, endpoint=SUBDOMAIN_DELETE_PATH,
                  request_sent=False)
        if args.plan:
            print('SIMULATION: Keine Loeschanfrage gesendet.')
            return 0
        if not args.apply:
            raise PleskError('Loeschung nur mit --apply moeglich')
        if (args.yes is not True or args.confirm_delete != fqdn or
                args.confirm_delete_id != domain_id or args.document_root != actual_root):
            raise PleskError('Loeschung erfordert --yes, --confirm-delete DOMAIN, '
                             '--confirm-delete-id ID und --document-root exakt wie in Plesk')
        # Aktuell lesend neu pruefen, unmittelbar bevor eine destruktive Anfrage
        # moeglich wird. Bei widerspruechlichen Daten fail closed.
        code, fresh_html, _ = client.request('/smb/web/view')
        if code != 200:
            raise PleskError('Plesk-Domainliste vor Loeschung nicht erreichbar')
        fresh_csrf = parse_html(fresh_html).csrf
        if not fresh_csrf:
            raise PleskError('Aktuelles CSRF-Token auf Plesk-Domainseite fehlt')
        client.update_csrf(fresh_html)
        refreshed = domain_list(fresh_html)
        if not refreshed.complete:
            raise PleskError('Domainliste vor Loeschung unvollstaendig')
        fresh_target = exact_entry(refreshed, fqdn)
        if fresh_target is None:
            raise PleskError('Subdomain nicht mehr vorhanden; keinen Loesch-POST senden')
        fresh_parent = [r for r in refreshed.entries
                        if str(r.get('displayName') or '').rstrip('.').casefold() == parent.casefold()]
        if len(fresh_parent) != 1 or str(fresh_parent[0].get('domainId')) != str(known_parent_id):
            raise PleskError('Hauptdomain stimmt vor Loeschung nicht mehr ueberein')
        second_id, second_root, second_body = build_delete_request(
            fresh_target, fqdn, parent, known_parent_id, args.document_root)
        if second_id != domain_id or second_root != actual_root or second_body != body:
            raise PleskError('Subdomain-ID oder Dokumentenstamm vor Loeschung geaendert')
        if not client.csrf:
            raise PleskError('CSRF-Token vor Loeschung fehlt')
        # Die anderen IDs muessen nach dem Loeschen weiterhin vorhanden sein.
        original_ids = {int(r['domainId']) for r in refreshed.entries
                        if str(r.get('domainId') or '').isdecimal() and int(r['domainId']) != domain_id}
        client.authorize_write_once(SUBDOMAIN_DELETE_PATH, body, 'application/json')
        log_event(logfile, run_id, 'post_submitting', section='subdomain',
                  path=SUBDOMAIN_DELETE_PATH, domain_id=domain_id, fields=1)
        print('Sende genau EINE validierte Subdomain-Loeschanfrage ...')
        try:
            status_code, response, content_type = client.request(
                SUBDOMAIN_DELETE_PATH, body=body,
                headers={'Content-Type': 'application/json',
                         'Referer': client.base + '/smb/web/view'}, max_bytes=1_000_000)
            outcome = report_server_reply(response, content_type, status_code)
            log_event(logfile, run_id, 'post_response', section='subdomain',
                      http_status=status_code, response_kind=outcome)
            if outcome == 'error':
                raise PleskError('Plesk meldet einen Loeschfehler; Zustand vor Wiederholung pruefen')
            for attempt in range(1, args.verify_attempts + 1):
                code, verify_html, _ = client.request('/smb/web/view')
                if code != 200:
                    raise PleskError('Plesk-Domainliste nach Loeschung nicht erreichbar')
                verified, reason = _verified_delete_absence(
                    verify_html, fqdn, parent, known_parent_id, original_ids)
                log_event(logfile, run_id, 'delete_verify', section='subdomain',
                          attempt=attempt, removed=verified)
                print(f'Nachpruefung {attempt}/{args.verify_attempts}: {reason}')
                if verified:
                    print('ERFOLG: Ausschliesslich die Ziel-Subdomain ist nicht mehr '
                          'in der vollstaendigen Plesk-Domainliste vorhanden.')
                    log_event(logfile, run_id, 'delete_verified', section='subdomain',
                              domain_id=domain_id, success=True)
                    return 0
                if attempt < args.verify_attempts:
                    time.sleep(args.verify_interval)
            raise PleskError('Loeschung nach POST noch nicht bestaetigt; vor erneutem Versuch --check')
        except Exception:
            print('WICHTIG: Der Loesch-POST wurde moeglicherweise verarbeitet. '
                  'NICHT erneut ausfuehren; zuerst --check!', file=sys.stderr)
            raise
    if args.operation != 'create':
        raise PleskError('Unbekannte Subdomain-Aktion')
    if target:
        print('Subdomain bereits vorhanden, keine weitere Erstellung.')
        if args.document_root and actual_root != args.document_root:
            raise PleskError('Dokumentenstamm unterscheidet sich vom gewuenschten Wert')
        return 0
    if not listing.complete:
        raise PleskError('Domainliste paginiert: Abwesenheit nicht sicher nachweisbar, kein POST')
    if not args.document_root or not valid_root(args.document_root):
        raise PleskError('Fuer die Erstellung ist --document-root als relativer Pfad erforderlich')
    code, html, _ = client.request(CREATE_PATH)
    if code != 200:
        raise PleskError('Plesk-Erstellungsformular nicht erreichbar')
    client.update_csrf(html)
    parent_id, fields, body, csrf = build_create_request(html, parent, label, args.document_root)
    if known_parent_id is not None and parent_id != known_parent_id:
        raise PleskError('Hauptdomain-ID aus Formular und Domainliste widersprechen sich')
    print('Dokumentenstamm (Ziel):', args.document_root)
    print('Erstellungsformular validiert:', len(fields), 'Felder,', len(body), 'Bytes')
    log_event(logfile, run_id, 'create_plan', section='subdomain', parent_id=parent_id,
              document_root=args.document_root, fields=len(fields), request_sent=False)
    if args.plan:
        print('SIMULATION: Kein Speicher-POST gesendet.')
        return 0
    if not args.yes:
        raise PleskError('Subdomain --apply erfordert --yes')
    if args.confirm_create != fqdn:
        raise PleskError('Erstellung erfordert --confirm-create mit exakt dem Subdomainnamen')
    # Direkt vor dem POST Abwesenheit erneut nachweisen; kein blindes Wiederholen.
    _, refreshed, _ = client.request('/smb/web/view')
    client.update_csrf(refreshed)
    refreshed_list = domain_list(refreshed)
    if not refreshed_list.complete or exact_entry(refreshed_list, fqdn) is not None:
        raise PleskError('Subdomainliste hat sich geaendert oder ist nicht vollstaendig')
    if not secrets.compare_digest(csrf, client.csrf or ''):
        raise PleskError('CSRF-Token hat sich vor dem POST geaendert')
    client.authorize_write_once(CREATE_PATH, body, 'application/x-www-form-urlencoded')
    log_event(logfile, run_id, 'post_submitting', section='subdomain', path=CREATE_PATH,
              parent_id=parent_id, fields=len(fields))
    print('Sende genau EINE validierte Subdomain-Erstellungsanfrage ...')
    try:
        status_code, response, content_type = client.request(
            CREATE_PATH, body=body,
            headers={'Content-Type':'application/x-www-form-urlencoded',
                     'Referer':client.base + CREATE_PATH}, max_bytes=1_000_000)
        outcome = report_server_reply(response, content_type, status_code)
        log_event(logfile, run_id, 'post_response', section='subdomain',
                  http_status=status_code, response_kind=outcome)
        if outcome == 'error':
            raise PleskError('Plesk meldet einen Erstellungsfehler; nicht blind wiederholen')
        for attempt in range(1, args.verify_attempts + 1):
            code, fresh_html, _ = client.request('/smb/web/view')
            if code != 200:
                raise PleskError('Plesk-Domainliste nach Erstellung nicht erreichbar')
            current_list = domain_list(fresh_html)
            row = exact_entry(current_list, fqdn)
            if row:
                found_root = check_subdomain(row, fqdn, parent, parent_id)
                root_ok = found_root == args.document_root
                print(f'Nachpruefung {attempt}/{args.verify_attempts}: Domain vorhanden, Dokumentenstamm:',
                      'OK' if root_ok else 'ABWEICHEND')
                log_event(logfile, run_id, 'verify', section='subdomain',
                          attempt=attempt, domain_id=int(row['domainId']), document_root_ok=root_ok)
                if not root_ok:
                    raise PleskError('KRITISCH: Subdomain angelegt, aber Dokumentenstamm weicht ab! Manuell pruefen')
                print('ERFOLG: Subdomain und Dokumentenstamm in Plesk verifiziert.')
                return 0
            if attempt < args.verify_attempts:
                time.sleep(args.verify_interval)
        raise PleskError('Subdomain-Erstellung nicht verifiziert; vor erneutem Versuch --check')
    except PleskError:
        print('WICHTIG: Eine Erstellungsanfrage wurde moeglicherweise verarbeitet. Nicht blind wiederholen.',
              file=sys.stderr)
        raise


def self_test():
    """Synthetische Plesk-Daten; keinerlei HTTPS-Anfragen."""
    data = {
        'data': {'data': {'pager': {'totalItemCount': 2, 'pageCount': 1, 'current': 1},
                          'data': [
                              {'displayName': 'example.org', 'domainId': 100,
                               'isSubdomain': False, 'webrootDir':'example.org/httpdocs'},
                              {'displayName': 'old.example.org', 'domainId': 120,
                               'isSubdomain': True, 'isRemovable': True,
                               'parentDomain': {'id': 100, 'displayName': 'example.org'},
                               'webrootDir': 'old.example.org/public'}]}}
    }
    html = '<script>Plesk.run(' + json.dumps(data) + ')</script>'
    listing = domain_list(html)
    assert listing.complete
    assert exact_entry(listing, 'new.example.org') is None
    row = exact_entry(listing, 'old.example.org')
    assert check_subdomain(row, 'old.example.org', 'example.org', 100) == 'old.example.org/public'
    csrf = 'a' * 32
    form = (f'<meta name="forgery_protection_token" content="{csrf}">'
            '<form id="smb-form-final-web-addsubdomain" method="post">'
            '<input name="domainName[name]" value="">'
            '<input name="hostingType[hosting]" value="hosting">'
            '<input name="hostingSettings[root]" value="">'
            '<input name="hostingSettings[rootPattern]" value="&lt;domain&gt;/httpdocs">'
            '<input name="sslit[enabled]" value="0">'
            f'<input name="forgery_protection_token" value="{csrf}">'
            '</form>'
            '<script>new Jsw.LookUp(' + json.dumps({
                'applyTo':'domainName-domain', 'name':'domainName[domain]',
                'data':[{'title':'example.org','id':100}]}) + ')</script>')
    parent_id, fields, body, parsed_csrf = build_create_request(form, 'example.org', 'new',
                                                                 'new.example.org/public')
    from urllib.parse import parse_qs
    parsed = parse_qs(body.decode())
    assert parent_id == 100 and parsed_csrf == csrf
    assert parsed[FIELD_NAME] == ['new']
    assert parsed[FIELD_PARENT] == ['100']
    assert parsed[FIELD_ROOT] == ['new.example.org/public']
    assert len(fields) == 7 and parsed['sslit[enabled]'] == ['0']
    for invalid in ('/absolute/path', '../escape', 'a//b', 'a/./b', 'a\\b'):
        assert not valid_root(invalid)
    assert valid_root('new.example.org/public')
    # Unbekanntes Formular darf nicht zu einem schreibfaehigen POST fuehren.
    try:
        build_create_request(form.replace('sslit[enabled]', 'unexpected[enabled]'),
                             'example.org', 'new', 'new.example.org/public')
        raise AssertionError('Unbekannte Plesk-Felder akzeptiert')
    except PleskError:
        pass
    assert report_server_reply('<html></html>', 'text/html', 200) == 'unknown'
    print('Selbsttest erfolgreich: Subdomain, Hauptdomain-ID, Dokumentenstamm, Formular und POST-Sperren.')
