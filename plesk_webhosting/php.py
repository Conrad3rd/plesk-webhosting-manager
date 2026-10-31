"""PHP-Verwaltung: unveraenderte v1.4-Formularlogik und serverseitige Validierung."""
from __future__ import annotations
import re
import json
import time
import secrets
import sys
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from html import unescape
from tempfile import TemporaryDirectory
from pathlib import Path

from .core import PleskError, PleskSession, page_data, log_event as emit

BASEDIR = {
    'DOCROOT': '{DOCROOT}{/}{:}{TMP}{/}{:}{/}var{/}lib{/}php{/}sessions{:}{WEBSPACEROOT}{/}tmp',
    'WEBSPACEROOT': '{WEBSPACEROOT}{/}{:}{TMP}{/}{:}{/}var{/}lib{/}php{/}sessions',
}
FORM_BASEDIR = 'mainSettings[general][open_basedir]'

def log_event(log, run_id, event, **values):
    emit(log, run_id, event, section='php', **values)

def settings_data(html, domain, domain_id):
    matches = []
    for obj in page_data(html):
        data = obj.get('data')
        if not isinstance(data, dict) or str(data.get('domainId')) != str(domain_id):
            continue
        heading = re.sub(r'<[^>]+>', '', unescape(str(data.get('pageTitle') or '')))
        if not re.search(r'(?<![\w.-])' + re.escape(domain) + r'(?![\w.-])', heading, re.I):
            continue
        handler = data.get('handler')
        values = data.get('values')
        if not isinstance(handler, dict) or not isinstance(values, dict):
            continue
        settings = values.get('mainSettings')
        general = settings.get('general') if isinstance(settings, dict) else None
        if not isinstance(general, dict) or not isinstance(general.get('open_basedir'), str):
            continue
        version = handler.get('version')
        if not isinstance(version, str) or not re.fullmatch(r'\d+\.\d+', version):
            continue
        choices = ((data.get('settingsConfig') or {}).get('open_basedir') or {}).get('values') or []
        if not isinstance(choices, list) or any(not isinstance(x, str) for x in choices):
            raise PleskError('Ungueltige open_basedir-Auswahl der Plesk-Seite')
        versions = {}
        for row in data.get('handlers') or []:
            if not isinstance(row, dict):
                continue
            match = re.match(r'^(\d+\.\d+)(?:\s|$)', str(row.get('version') or ''))
            key = str(row.get('id') or '')
            if match and re.fullmatch('[0-9a-f]{32}', key):
                ver = match.group(1)
                if ver in versions:
                    raise PleskError('Doppelte PHP-Version in Plesk')
                versions[ver] = (key, row.get('options') or {})
        matches.append({'data': data, 'version': version,
                        'handler': str(handler.get('id') or ''),
                        'basedir': general['open_basedir'],
                        'basedir_options': choices, 'versions': versions,
                        'allow_change': data.get('allowChangePhpVersion') is True,
                        'php_enabled': (values.get('php') is True and data.get('isPhpEnabled') is True),
                        'performance_editable': data.get('allowPerformanceManagement') is True,
                        'settings_editable': data.get('allowPhpSettingsManagement') is True})
    if len(matches) != 1:
        raise PleskError('PHP-Einstellungsseite passt nicht eindeutig zu Domain und ID')
    return matches[0]

@dataclass
class Plan:
    domain_id: int
    version_key: str
    handler_id: str
    fields: list[tuple[str, str]]
    boundary: str
    body: bytes

def primitive(value):
    """Konvertierung der sonstigen PHP-Einstellungswerte aus Plesk.

    Der zentrale Schalter `php` ist eine AUSNAHME: Browser-POST sendet
    die Zeichenkette '1' und wird in build_plan() gesondert verarbeitet.
    Andere boolesche Werte: 'true'/'false', null: leer.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, (int, float)):
        return str(value)
    if value is None:
        return ''
    raise PleskError('Unerwarteter PHP-Formular-Datentyp')

def multipart(fields, boundary):
    chunks = []
    for key, value in fields:
        if not re.fullmatch(r'[A-Za-z0-9_\[\]~.-]{1,160}', key):
            raise PleskError('Ungueltiger Formularfeldname')
        if not isinstance(value, str) or len(value) > 8192 or '\x00' in value:
            raise PleskError('Ungueltiger Formularfeldwert')
        chunks.append((f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n'
                       f'{value}\r\n').encode('utf-8'))
    chunks.append(f'--{boundary}--\r\n'.encode('ascii'))
    return b''.join(chunks)

def build_plan(status, domain_id, version, basedir_name, csrf_meta):
    if not status['allow_change']:
        raise PleskError('PHP-Version ist fuer diese Domain nicht aenderbar')
    if not status['settings_editable']:
        raise PleskError('PHP-Einstellungen laut Plesk nicht bearbeitbar')
    # Die konkrete Browser-Feldliste wurde bisher nur fuer gesperrte
    # Performance-Optionen verifiziert. Bei anderen Rechten NICHT raten.
    if status['performance_editable']:
        raise PleskError('Leistungseinstellungen bearbeitbar: POST-Format noch nicht verglichen')
    if not status['php_enabled']:
        raise PleskError('PHP-Unterstuetzung deaktiviert; Speichern gesperrt')
    options = status['basedir_options']
    expected_basedir = BASEDIR[basedir_name]
    if options.count(expected_basedir) != 1:
        raise PleskError('Gewuenschtes open_basedir ist keine eindeutige Plesk-Option')
    available = status['versions'].get(version)
    handler_id = f'php{version.replace(".", "")}-fastcgi-nc'
    if available is None or not isinstance(available[1], dict) or handler_id not in available[1]:
        raise PleskError('PHP-FastCGI-Handler nicht eindeutig verfuegbar')
    version_key = available[0]
    raw_values = status['data']['values']
    if not isinstance(raw_values.get('mainSettings'), dict):
        raise PleskError('Plesk liefert keine vollstaendigen PHP-Einstellungen')
    form_csrf = raw_values.get('forgery_protection_token')
    if not isinstance(form_csrf, str) or not form_csrf or not secrets.compare_digest(form_csrf, csrf_meta or ''):
        raise PleskError('CSRF-Token aus Metadaten und PHP-Formular stimmen nicht ueberein')
    if raw_values.get('php') is not True:
        raise PleskError('PHP ist nicht aktiv; keine automatische Aktivierung')
    if not isinstance(raw_values.get('phpHandler'), str):
        raise PleskError('PHP-Handler-Auswahl fehlt')
    fields = []
    handler_ids = set()
    for key, value in raw_values.items():
        if key == 'mainSettings':
            if set(value) != {'general', 'performance'}:
                raise PleskError('Unerwartete PHP-Konfigurationsgruppen')
            for group, options in value.items():
                if not isinstance(options, dict) or not options:
                    raise PleskError('PHP-Konfigurationsgruppe ist unvollstaendig')
                for setting, actual in options.items():
                    # Live-Vergleich mit Playwright: Dieses Feld ist bei
                    # gesperrter Performance-Gruppe nur in der Plesk-HTML-
                    # Initialisierung vorhanden, NICHT im echten Browser-POST.
                    if group == 'performance' and setting == 'opcacheenable':
                        continue
                    if not re.fullmatch(r'[a-z][a-z0-9_]{0,63}', setting):
                        raise PleskError('Unbekannter PHP-Einstellungsname')
                    field = f'mainSettings[{group}][{setting}]'
                    if field == FORM_BASEDIR:
                        actual = expected_basedir
                    fields.append((field, primitive(actual)))
        else:
            if key not in {'php', 'phpHandler', 'forgery_protection_token'} and not re.fullmatch(r'phpHandlerId[0-9a-f]{32}', key):
                raise PleskError('Unerwartetes PHP-Formularfeld')
            if key.startswith('phpHandlerId'):
                handler_ids.add(key[12:])
                if not isinstance(value, str):
                    raise PleskError('PHP-Handler-Zuordnung ist kein Text')
            if key == 'phpHandler':
                value = version_key
            if key == 'php':
                # Live-Vergleich vom 26.10.2026: Browser sendet `php=1`.
                # `php=true` deaktiviert die PHP-Unterstuetzung in Plesk!
                if value is not True:
                    raise PleskError('PHP-Unterstuetzung nicht eindeutig aktiv')
                fields.append(('php', '1'))
            else:
                fields.append((key, primitive(value)))
    if len(handler_ids) < 2 or version_key not in handler_ids:
        raise PleskError('Plesk-Handlerkennungen sind nicht vollstaendig')
    field_dict = dict(fields)
    if len(fields) != len(field_dict) or not (30 <= len(fields) <= 120):
        raise PleskError('Unerwartete Anzahl oder doppelte PHP-Felder')
    # Serverdaten sind aktuell; alle nicht gezielt geaenderten Felder bleiben erhalten.
    if field_dict.get('phpHandlerId' + version_key) != handler_id:
        raise PleskError('PHP-Handler-Zuordnung stimmt nicht')
    if field_dict.get(FORM_BASEDIR) != expected_basedir:
        raise PleskError('open_basedir-Zielwert fehlt')
    if field_dict.get('phpHandler') != version_key or field_dict.get('forgery_protection_token') != form_csrf:
        raise PleskError('PHP-Auswahl oder CSRF-Token fehlt')
    if field_dict.get('php') != '1':
        raise PleskError('PHP-Aktivierung darf nicht veraendert werden')
    boundary = '----PleskPHPPlan' + secrets.token_hex(12)
    body = multipart(fields, boundary)
    if len(body) > 256_000:
        raise PleskError('Formulardaten unerwartet umfangreich')
    return Plan(domain_id, version_key, handler_id, fields, boundary, body)

def validate_wire_plan(plan, version, basedir_name, csrf):
    """Prueft das tatsaechliche Multipart-Bytearray, nicht nur die Feldliste."""
    if not isinstance(plan, Plan) or not (30 <= len(plan.fields) <= 120):
        raise PleskError('PHP-Formular unvollstaendig')
    ct = 'multipart/form-data; boundary=' + plan.boundary
    try:
        parsed = BytesParser(policy=policy.default).parsebytes(
            b'MIME-Version: 1.0\r\nContent-Type: ' + ct.encode('ascii') +
            b'\r\n\r\n' + plan.body)
        if not parsed.is_multipart():
            raise PleskError('Multipart-Koerper ungueltig')
        data = []
        for part in parsed.iter_parts():
            if part.get_filename() is not None:
                raise PleskError('Unerwarteter Datei-Upload im PHP-POST')
            name = part.get_param('name', header='content-disposition')
            if not isinstance(name, str):
                raise PleskError('Formularfeldname fehlt')
            content = part.get_payload(decode=True)
            if content is None:
                raise PleskError('Formularfeldwert fehlt')
            data.append((name, content.decode('utf-8')))
    except (UnicodeError, ValueError, TypeError) as exc:
        raise PleskError('Multipart-Koerper unlesbar') from exc
    if data != plan.fields:
        raise PleskError('Multipart-Daten weichen von validierter Formularliste ab')
    actual = dict(data)
    if len(actual) != len(data):
        raise PleskError('Doppelte PHP-Formularfelder')
    if 'mainSettings[performance][opcacheenable]' in actual:
        raise PleskError('Unzulaessiges OPcache-Feld im PHP-POST')
    if not (actual.get('php') == '1' and
            actual.get('phpHandler') == plan.version_key and
            actual.get('phpHandlerId' + plan.version_key) == plan.handler_id and
            actual.get(FORM_BASEDIR) == BASEDIR[basedir_name] and
            isinstance(csrf, str) and csrf and
            secrets.compare_digest(actual.get('forgery_protection_token') or '', csrf) and
            plan.handler_id == f'php{version.replace(".", "")}-fastcgi-nc'):
        raise PleskError('Sicherheitspruefung des PHP-POST fehlgeschlagen')
    return len(data)

def changed_other_settings(before, after):
    """(Ungeplante Unterschiede, nur versionsbedingte Anzeigeunterschiede).

    PHP 8.5 liefert `performance.opcacheenable` in dieser Plesk-Oberflaeche
    nicht mehr, PHP 8.4 dagegen schon. Ein nur bei einem Versionswechsel
    fehlender/vorhandener Schluessel ist KEIN Beweis einer Einstellungsaenderung.
    Zwei explizit vorhandene unterschiedliche Werte bleiben dagegen kritisch.
    """
    previous = before['data']['values'].get('mainSettings') or {}
    current = after['data']['values'].get('mainSettings') or {}
    unexpected, display_only = [], []
    version_switched = before['version'] != after['version']
    for group in sorted(set(previous) | set(current)):
        old_group = previous.get(group) or {}
        new_group = current.get(group) or {}
        if not isinstance(old_group, dict) or not isinstance(new_group, dict):
            unexpected.append(group)
            continue
        for key in sorted(set(old_group) | set(new_group)):
            if group == 'general' and key == 'open_basedir':
                continue
            if key in old_group and key in new_group and old_group[key] == new_group[key]:
                continue
            label = f'{group}.{key}'
            if (version_switched and group == 'performance' and key == 'opcacheenable'
                    and (key in old_group) != (key in new_group)):
                display_only.append(label)
            else:
                unexpected.append(label)
    return unexpected, display_only

def show_settings(status, *, detailed=False):
    """Gleiche statusbasierte Ausgabe fuer --check, --plan und --apply."""
    print('[3] Aktuelle PHP-Einstellungen:')
    print('    PHP-Unterstuetzung:', 'aktiv' if status['php_enabled'] else 'DEAKTIVIERT')
    print('    PHP-Version:', status['version'])
    print('    PHP-Handler:', status['handler'])
    print('    open_basedir:', status['basedir'])
    performance = status['data']['values']['mainSettings'].get('performance') or {}
    print('    opcache.enable:', performance.get('opcacheenable', 'nicht angegeben'))
    print('    max_input_time:', performance.get('max_input_time', 'nicht angegeben'))
    print('    Leistungseinstellungen bearbeitbar:',
          'ja' if status['performance_editable'] else 'nein')
    print('    PHP-Versionen verfuegbar:', ', '.join(status['versions']))
    if detailed:
        config = status['data'].get('settingsConfig') or {}
        groups = status['data']['values']['mainSettings']
        print('    Konfiguration und Berechtigungen:')
        for group in ('performance', 'general'):
            allowed = (status['performance_editable'] if group == 'performance'
                       else status['settings_editable'])
            print('     ', group, '(bearbeitbar:', 'ja' if allowed else 'nein', ')')
            for name, raw in groups.get(group, {}).items():
                value = '(leer)' if raw is None else str(raw)[:110]
                print('       ', name + ':', value)
                if name in ('max_input_time', 'opcacheenable'):
                    conf_key = 'opcache.enable' if name == 'opcacheenable' else name
                    choices = (config.get(conf_key) or {}).get('values') or []
                    print('         Auswahl:', ', '.join(map(str, choices)))
    return performance

def self_test():
    from tempfile import TemporaryDirectory
    domain = 'php.example.test'
    php_choices = list(BASEDIR.values())
    versions = {'8.0': '585375c1448bfa3494298bdd79408081',
                '8.5': '845e85fa64a2d6037055beba19fe0bd8'}
    handlers = [{'version': ver, 'id': key,
                 'options': {f'php{ver.replace(".", "")}-fastcgi-nc': 'FastCGI'}}
                for ver, key in versions.items()]
    csrf = 'A' * 32
    vals = {'php': True, **{'phpHandlerId' + row['id']: next(iter(row['options'])) for row in handlers},
            'phpHandler': versions['8.0'], 'forgery_protection_token': csrf,
            'mainSettings': {'general': {'open_basedir': php_choices[1], 'display_errors': 'off'},
                             'performance': {'memory_limit': '128M',
                                             'opcacheenable': 'on (Standard)',
                                             'disable_functions': None, 'example_disabled': False}}}
    def html_for(vals):
        data = {'data': {'pageTitle': 'PHP-Einstellungen fuer ' + domain,
                         'domainId': 101, 'values': vals,
                         'handler': {'id': 'php80-fastcgi-nc', 'version': '8.0'},
                         'handlers': handlers, 'allowChangePhpVersion': True,
                         'isPhpEnabled': vals['php'], 'allowPerformanceManagement': False,
                         'allowPhpSettingsManagement': True,
                         'settingsConfig': {'open_basedir': {'values': php_choices}}}}
        return '<meta name="forgery_protection_token" content="' + csrf + '">' + '<script>Plesk.run(' + json.dumps(data) + ')</script>'
    page = html_for(vals)
    decoded = settings_data(page, domain, 101)
    assert decoded['version'] == '8.0'
    try:
        build_plan(decoded, 101, '8.5', 'DOCROOT', csrf)
        raise AssertionError('Unvollstaendige Feldliste akzeptiert')
    except PleskError:
        pass
    for i in range(28):
        vals['mainSettings']['performance'][f'extra{i}'] = 'x'
    plan = build_plan(settings_data(html_for(vals), domain, 101), 101, '8.5', 'DOCROOT', csrf)
    fields = dict(plan.fields)
    assert fields['mainSettings[performance][disable_functions]'] == ''
    assert fields['mainSettings[performance][example_disabled]'] == 'false'
    assert fields['php'] == '1'
    assert 'mainSettings[performance][opcacheenable]' not in fields
    assert primitive(False) == 'false' and primitive(None) == ''
    assert fields['phpHandler'] == versions['8.5']
    assert fields['phpHandlerId' + versions['8.5']] == 'php85-fastcgi-nc'
    assert fields[FORM_BASEDIR] == php_choices[0]
    assert fields['mainSettings[performance][memory_limit]'] == '128M'
    assert plan.body.count(b'Content-Disposition: form-data; name=') == len(plan.fields)
    assert b'php85-fastcgi-nc' in plan.body
    # Andere FormData-Werte bleiben unveraendert. Nur `php` ist 1.
    assert primitive(True) == 'true' and primitive(False) == 'false'
    assert primitive(None) == ''
    assert b'------PleskPHPPlan' in plan.body
    assert validate_wire_plan(plan, '8.5', 'DOCROOT', csrf) == len(plan.fields)
    try:
        validate_wire_plan(plan, '8.5', 'WEBSPACEROOT', csrf)
        raise AssertionError('Falsches basedir beim Wire-Check akzeptiert')
    except PleskError:
        pass
    try:
        validate_wire_plan(plan, '8.5', 'DOCROOT', 'B' * 32)
        raise AssertionError('Falsches CSRF beim Wire-Check akzeptiert')
    except PleskError:
        pass
    try:
        build_plan(settings_data(page, domain, 101), 101, '8.5', 'DOCROOT', 'DIFFERENT')
        raise AssertionError('Fremdes CSRF-Token akzeptiert')
    except PleskError:
        pass
    # PHP 8.4 -> 8.5: OPcache-Feld verschwindet in Plesks Ansicht.
    old = {'version': '8.4', 'data': {'values': {'mainSettings': {
        'general': {'open_basedir': BASEDIR['DOCROOT'], 'display_errors': 'off'},
        'performance': {'opcacheenable': 'on (Standard)', 'max_input_time': '60 (Standard)'}}}}}
    new = {'version': '8.5', 'data': {'values': {'mainSettings': {
        'general': {'open_basedir': BASEDIR['WEBSPACEROOT'], 'display_errors': 'off'},
        'performance': {'max_input_time': '60 (Standard)'}}}}}
    unexpected, display = changed_other_settings(old, new)
    assert not unexpected and display == ['performance.opcacheenable']
    unexpected, display = changed_other_settings(new, old)
    assert not unexpected and display == ['performance.opcacheenable']
    # Gleiche Version + verschwundenes OPcache-Feld IST eine unerwartete Aenderung.
    same_version = {'version': '8.4', 'data': new['data']}
    unexpected, display = changed_other_settings(old, same_version)
    assert unexpected == ['performance.opcacheenable'] and not display
    # Sichtbarer Wertwechsel und weitere ungewollte Aenderungen nicht maskieren.
    changed_value = {'version': '8.5', 'data': {'values': {'mainSettings': {
        'general': {'open_basedir': BASEDIR['WEBSPACEROOT'], 'display_errors': 'on'},
        'performance': {'opcacheenable': 'off', 'max_input_time': '120'}}}}}
    unexpected, display = changed_other_settings(old, changed_value)
    assert set(unexpected) == {'general.display_errors',
                               'performance.opcacheenable', 'performance.max_input_time'}
    assert not display
    s = PleskSession('example.test', 'test', 'secret')
    try:
        s.request('/smb/web/php-settings/id/101', body=b'x')
        raise AssertionError('PHP-POST nicht blockiert')
    except PleskError:
        pass
    # Einmalige Freigabe nur fuer exakt dieselben Bytes und denselben Pfad.
    s.authorize_write_once('/smb/web/php-settings/id/101', plan.body, 'multipart/form-data; boundary=' + plan.boundary)
    try:
        s.request('/smb/web/php-settings/id/102', body=plan.body,
                  headers={'Content-Type': 'multipart/form-data; boundary=' + plan.boundary})
        raise AssertionError('Fremde Domain-ID akzeptiert')
    except PleskError:
        pass
    try:
        s.request('/smb/web/php-settings/id/101', body=plan.body + b'wrong',
                  headers={'Content-Type': 'multipart/form-data; boundary=' + plan.boundary})
        raise AssertionError('Veraenderte Bytes akzeptiert')
    except PleskError:
        pass
    assert s._write_grant is not None and not s._write_consumed
    with TemporaryDirectory() as work:
        target = Path(work) / 'log.jsonl'
        log_event(target, 'test', 'test_event', count=len(fields))
        assert target.stat().st_mode & 0o077 == 0
        assert csrf not in target.read_text()
    print('Selbsttest erfolgreich: PHP-Schalter, Multipart, CSRF, Einmal-POST, OPcache-Anzeige und Sperren.')

def run(args, client, discovered, log, run_id):
    write_started = False
    try:
        print('=== Plesk PHP direkt per Python/HTTPS (modular) ===')
        print('Domain:', args.domain)
        print('[1] Linux-Schluesselbund und HTTPS-Anmeldung: bestaetigt')
        print('[2] Domain-ID:', discovered, '(automatisch ermittelt oder einzeln verifiziert)')
        page_path = f'/smb/web/php-settings/id/{discovered}'
        http_status, html, _ = client.request(page_path)
        if http_status != 200:
            raise PleskError('PHP-Einstellungsseite nicht erreichbar')
        client.update_csrf(html)
        status = settings_data(html, args.domain, discovered)
        performance = show_settings(status, detailed=args.show_settings)
        expected_handler = f'php{args.php_version.replace(".", "")}-fastcgi-nc'
        already = (status['php_enabled'] and status['version'] == args.php_version and
                   status['handler'] == expected_handler and
                   status['basedir'] == BASEDIR[args.basedir])
        print('    Ziel bereits konfiguriert:', 'ja' if already else 'nein')
        log_event(log, run_id, 'status_ok', domain_id=discovered,
                  domain_id_source='verified_page', php_version=status['version'],
                  target_configured=already, can_change=status['allow_change'],
                  php_enabled=status['php_enabled'],
                  performance_editable=status['performance_editable'],
                  opcache=performance.get('opcacheenable'),
                  max_input_time=performance.get('max_input_time'))
        if args.check:
            print('Keine PHP-Einstellung veraendert.')
            print('Protokoll:', log)
            return 0
        if already:
            print('[4] Bereits korrekt konfiguriert; keine Speicheranfrage erforderlich.')
            log_event(log, run_id, 'already_configured', domain_id=discovered)
            return 0

        plan = build_plan(status, discovered, args.php_version, args.basedir, client.csrf)
        wire_fields = validate_wire_plan(plan, args.php_version, args.basedir, client.csrf)
        print('[4] PHP-Speicheranfrage lokal vorbereitet und validiert:')
        print('    POST', page_path)
        print('    Content-Type: multipart/form-data')
        print('    Anzahl Formularfelder:', wire_fields)
        print('    Nutzdatenbytes:', len(plan.body))
        print('    PHP-Ziel:', args.php_version, '/', plan.handler_id)
        print('    open_basedir-Ziel:', args.basedir)
        print('    Die sonstigen PHP-Formularwerte bleiben unveraendert.')
        log_event(log, run_id, 'post_validated', domain_id=discovered,
                  fields=wire_fields, post_bytes=len(plan.body),
                  handler_ok=True, basedir_ok=True, csrf_present=True,
                  request_sent=False)

        if args.plan:
            print('    SIMULATION: Keine Speicheranfrage gesendet.')
            print('Keine PHP-Einstellung veraendert.')
            print('Protokoll:', log)
            return 0
        if not args.yes:
            if not sys.stdin.isatty():
                raise PleskError('Ohne Terminal nur mit --yes schreibend ausfuehren')
            confirmation = f'ANWENDEN {discovered}'
            typed = input(f'Zum Aendern auf PHP {args.php_version} / {args.basedir} '
                          f'bitte {confirmation} eingeben: ').strip()
            if typed != confirmation:
                print('Abgebrochen, keine Anfrage gesendet.')
                log_event(log, run_id, 'cancelled')
                return 1

        # Die Autorisierung ist auf diese exakte Domain, den Body und einen POST beschraenkt.
        client.authorize_write_once(page_path, plan.body, 'multipart/form-data; boundary=' + plan.boundary)
        print('[5] Sende genau EINE validierte HTTPS-Speicheranfrage ...')
        log_event(log, run_id, 'post_submitting', domain_id=discovered,
                  path=page_path, fields=wire_fields)
        write_started = True
        response_code, response_html, _ = client.request(
            page_path, body=plan.body, headers={
                'Content-Type': 'multipart/form-data; boundary=' + plan.boundary,
                'Accept': 'text/html,application/json;q=0.9,*/*;q=0.8',
            })
        if response_code >= 400:
            raise PleskError(f'Plesk meldet HTTP {response_code} beim PHP-Speichern')
        # HTML 200 ist kein Erfolgssignal. Erst GET + korrekte Werte bestaetigen.
        response_kind = 'json' if response_html.lstrip().startswith('{') else 'html'
        if response_kind == 'json':
            try:
                result = json.loads(response_html)
                if isinstance(result, dict) and (result.get('errors') or result.get('status') in ('error', 'failed')):
                    raise PleskError('Plesk meldet einen PHP-Speicherfehler')
            except json.JSONDecodeError:
                response_kind = 'unknown'
        print('    HTTP-Status:', response_code, '| Antwort:', response_kind)
        log_event(log, run_id, 'post_response', domain_id=discovered,
                  http_status=response_code, response_kind=response_kind)

        print('[6] PHP und open_basedir unabhaengig bei Plesk nachpruefen ...')
        for attempt in range(1, args.verify_attempts + 1):
            try:
                code, latest_html, _ = client.request(page_path)
                if code != 200:
                    raise PleskError('PHP-Einstellungsseite nach Speichern nicht erreichbar')
                latest = settings_data(latest_html, args.domain, discovered)
                version_ok = latest['version'] == args.php_version
                handler_ok = latest['handler'] == plan.handler_id
                basedir_ok = latest['basedir'] == BASEDIR[args.basedir]
                php_enabled = latest['php_enabled']
                print(f'    Versuch {attempt}/{args.verify_attempts}: PHP:',
                      'OK' if version_ok and handler_ok else 'abweichend',
                      '| PHP-Unterstuetzung:', 'AKTIV' if php_enabled else 'DEAKTIVIERT',
                      '| open_basedir:', 'OK' if basedir_ok else 'abweichend')
                log_event(log, run_id, 'verify', domain_id=discovered,
                          attempt=attempt, php_ok=version_ok and handler_ok,
                          php_enabled=php_enabled, basedir_ok=basedir_ok,
                          opcache=(latest['data']['values']['mainSettings'].get('performance') or {}).get('opcacheenable'),
                          max_input_time=(latest['data']['values']['mainSettings'].get('performance') or {}).get('max_input_time'))
                if not php_enabled:
                    log_event(log, run_id, 'critical_php_disabled', domain_id=discovered)
                    raise PleskError('KRITISCH: PHP nach POST deaktiviert! Manuell reparieren; kein weiterer POST.')
                if version_ok and handler_ok and basedir_ok:
                    differences, display_only = changed_other_settings(status, latest)
                    if display_only:
                        print('    HINWEIS: OPcache-Anzeige hat sich beim PHP-Versionswechsel geaendert;'
                              ' keine nachgewiesene Aenderung am OPcache-Wert.')
                        log_event(log, run_id, 'version_dependent_display',
                                  keys=display_only,
                                  version_before=status['version'],
                                  version_after=latest['version'])
                    if differences:
                        print('    WARNUNG: Andere PHP-Einstellungen veraendert:', ', '.join(differences))
                        log_event(log, run_id, 'other_settings_changed',
                                  count=len(differences), keys=differences)
                        print('    Zielwerte gespeichert, aber Gesamtkonfiguration nicht unveraendert.')
                        print('    Bitte in Plesk kontrollieren, keine automatische Wiederholung.')
                        return 1
                    log_event(log, run_id, 'verified', domain_id=discovered,
                              php_version=args.php_version, basedir=args.basedir,
                              success=True)
                    print('ERFOLG: PHP', args.php_version, 'und', args.basedir,
                          'serverseitig bestaetigt.')
                    print('Protokoll:', log)
                    return 0
            except PleskError as exc:
                if 'KRITISCH: PHP nach POST' in str(exc):
                    raise
                print(f'    Versuch {attempt}/{args.verify_attempts}: Lesefehler')
                log_event(log, run_id, 'verify_read_error', attempt=attempt,
                          error_type=type(exc).__name__)
            if attempt < args.verify_attempts:
                time.sleep(args.verify_interval)
        raise PleskError('PHP-Speicherung NICHT verifiziert. Erst --check, dann weitere Schritte.')
    except (KeyboardInterrupt, EOFError):
        log_event(log, run_id, 'interrupted', write_started=write_started)
        print('Unterbrochen. ' + ('Moeglicherweise gespeichert: --check ausfuehren.' if write_started else
                                   'Keine PHP-Speicheranfrage gesendet.'), file=sys.stderr)
        return 130
    except PleskError as exc:
        log_event(log, run_id, 'failed', reason_type='PleskError', write_started=write_started)
        print('STOP:', str(exc), file=sys.stderr)
        if write_started:
            print('WICHTIG: Keine automatische Wiederholung; zuerst --check.', file=sys.stderr)
        return 1
    except Exception as exc:
        log_event(log, run_id, 'failed', reason_type=type(exc).__name__, write_started=write_started)
        print('STOP: Unerwarteter Fehler:', type(exc).__name__, file=sys.stderr)
        if write_started:
            print('WICHTIG: Keine automatische Wiederholung; zuerst --check.', file=sys.stderr)
        return 1
