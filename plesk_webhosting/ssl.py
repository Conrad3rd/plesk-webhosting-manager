"""SSL It! Verwaltung: bewiesene v1.2-POST-Formate und SSL-Nachpruefung."""
from __future__ import annotations
import json
import re
import socket
import ssl as tls_module
import time
import sys
from .core import PleskError, PleskSession, json_calls, parse_html, domain_id_from_view, log_event as emit

SafeError = PleskError
SSL_URL = '/modules/sslit/index.php/index/certificate/id/{}'
INSTALL_PATH = '/modules/sslit/index.php/index/install/'
REDIRECT_PATH = '/modules/sslit/index.php/https-redirect/enable/'
REDIRECT_DISABLE_PATH = '/modules/sslit/index.php/https-redirect/disable/'
UNASSIGN_PATH = '/modules/sslit/index.php/index/unsecure/'
VENDOR = 'letsencrypt.letsencrypt'
PRODUCT = 'letsencrypt.letsencrypt__base'


def log_event(log, run_id, event, **values):
    emit(log, run_id, event, section='ssl', **values)


def ssl_data(client, domain, domain_id):
    code, html, _ = client.request(SSL_URL.format(domain_id))
    if code != 200:
        raise SafeError('Plesk-SSL-Seite nicht erreichbar')
    client.update_csrf(html)
    return ssl_data_from_page(html, domain, domain_id)


def post_json(client, path, fields, domain_id):
    if path not in {INSTALL_PATH, REDIRECT_PATH, REDIRECT_DISABLE_PATH, UNASSIGN_PATH}:
        raise SafeError('Unbekannter SSL-Schreibendpunkt')
    body = json.dumps(fields, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('utf-8')
    if len(body) > 16_384:
        raise SafeError('Unerwartet grosse SSL-Anfrage')
    client.authorize_write_once(path, body, 'application/json')
    return client.request(path, body=body, headers={
        'Content-Type': 'application/json',
        'Accept': 'application/json,text/plain,*/*',
        'Referer': client.base + SSL_URL.format(domain_id),
    }, max_bytes=1_000_000)

def ssl_data_from_page(html, domain, domain_id):
    matches = []
    for data in json_calls(parse_html(html).scripts, 'main.default'):
        if 'secureDomainCapabilities' not in data:
            continue
        if (str(data.get('domainName') or '').casefold().rstrip('.') != domain.casefold().rstrip('.')
                or str(data.get('siteId')) != str(domain_id)):
            raise SafeError('SSL-It!-Seite hat eine abweichende Domain oder ID')
        matches.append(data)
    if len(matches) != 1:
        raise SafeError('SSL-It!-Initialdaten fehlen oder sind nicht eindeutig')
    return matches[0]

def ssl_status(data):
    redirect = data.get('httpsRedirect')
    if not isinstance(redirect, dict) or not isinstance(redirect.get('params'), dict):
        raise SafeError('HTTPS-Umleitungsstatus fehlt')
    enabled = redirect['params'].get('enabled')
    if not isinstance(enabled, bool):
        raise SafeError('HTTPS-Umleitungsstatus nicht lesbar')
    certificate = data.get('certificate')
    return {'certificate_assigned': isinstance(certificate, dict) and bool(certificate),
            'https_redirect': enabled,
            'pending_order': bool(data.get('pendingOrder')),
            'redirect_manageable': redirect.get('isManageable') is True,
            'webmail_redirect_supported': redirect['params'].get('canBeAppliedToWebMail') is True}

def install_capabilities(data):
    caps = data.get('secureDomainCapabilities') or {}
    product = (data.get('products') or {}).get(PRODUCT)
    return (isinstance(product, dict) and product.get('isPaid') is False
            and product.get('vendorExtendedId') == VENDOR and product.get('id') == 'base'
            and isinstance(product.get('installFormDescriptor'), dict)
            and caps.get('canSecureDomain') is True and caps.get('canSecureWww') is True
            and caps.get('canSelectChallengeType') is True
            and {'http-01', 'dns-01'}.issubset(set(product.get('supportedChallengeTypes') or [])))

def product_settings(data):
    """Nur kostenlose und erwartete Defaultwerte aus der echten Plesk-Seite verwenden.

    Die aktuelle Let's-Encrypt-Konfiguration enthaelt lediglich ein optionales
    Beschreibungsfeld. Neue/unbekannte Formularanforderungen werden abgelehnt.
    """
    product = (data.get('products') or {}).get(PRODUCT)
    if not isinstance(product, dict):
        raise SafeError('Lets-Encrypt-Produkt fehlt')
    descriptor = product.get('installFormDescriptor')
    if not isinstance(descriptor, dict):
        raise SafeError('Produktformular nicht lesbar')
    settings = {}
    for key, spec in descriptor.items():
        if key != 'description' or not isinstance(spec, dict):
            raise SafeError('Unbekannte Plesk-Produktanforderung; kein automatischer POST')
        if spec.get('required') is not False or spec.get('type') != 'description':
            raise SafeError('Neue Plesk-Pflichtangabe; kein automatischer POST')
        value = spec.get('value')
        if not isinstance(value, str) or value:
            raise SafeError('Unerwartete vorausgefuellte Produktbeschreibung')
        settings[key] = value
    return settings

def proposal(action, data, domain_id):
    state = ssl_status(data)
    if action == 'install':
        if state['certificate_assigned'] or state['pending_order']:
            return None, 'Zertifikat bereits zugewiesen oder Bestellung offen; keine neue Ausstellung'
        if not install_capabilities(data):
            return None, 'Kostenloses Lets Encrypt mit www und HTTP-01 nicht eindeutig angeboten'
        fields = {'validateWww': 'true', 'validateWebMail': 'false', 'validateMail': 'false',
                  'validateMailWithSan': 'false', 'validateDane': 'false',
                  'validateWildcard': 'false', 'productSettings': product_settings(data),
                  'id': str(domain_id), 'vendorId': VENDOR, 'productId': 'base',
                  'validateDomain': 'true', 'preferredChallengeType': 'http-01'}
        return (INSTALL_PATH, fields), None
    if action == 'redirect':
        if state['https_redirect']:
            return None, 'HTTPS-Umleitung bereits aktiv'
        if not state['redirect_manageable'] or state['webmail_redirect_supported']:
            return None, 'HTTPS-Umleitung erfordert zusaetzliche Plesk-Konfiguration'
        return (REDIRECT_PATH, {'id': str(domain_id)}), None
    if action == 'redirect-disable':
        if not state['https_redirect']:
            return None, 'HTTPS-Umleitung ist bereits deaktiviert'
        if not state['redirect_manageable']:
            return None, 'HTTPS-Umleitung ist in Plesk nicht verwaltbar'
        return (REDIRECT_DISABLE_PATH, {'id': str(domain_id)}), None
    if action == 'unassign':
        if not state['certificate_assigned']:
            return None, 'Es ist kein Zertifikat zugewiesen'
        return (UNASSIGN_PATH, {'id': str(domain_id)}), None
    raise SafeError('Unbekannte Aktion')

def validate_post(operation, path, fields, domain_id):
    expected_path = {'install': INSTALL_PATH, 'redirect': REDIRECT_PATH,
                     'redirect-disable': REDIRECT_DISABLE_PATH,
                     'unassign': UNASSIGN_PATH}.get(operation)
    if not expected_path or path != expected_path or not isinstance(fields, dict):
        raise SafeError('Endpunkt oder Format nicht erwartungsgemaess')
    if type(fields.get('id')) is not str or fields['id'] != str(domain_id):
        raise SafeError('POST-Domain-ID widerspricht der Plesk-Domain-ID')
    if operation != 'install':
        if set(fields) != {'id'}:
            raise SafeError('Unerwartete Felder im Verwaltungs-POST')
        return
    expected = {'id', 'vendorId', 'productId', 'validateDomain', 'validateWww',
                'validateWildcard', 'validateWebMail', 'validateMail',
                'validateMailWithSan', 'validateDane', 'preferredChallengeType',
                'productSettings'}
    if set(fields) != expected:
        raise SafeError('Unerwartete Felder im Installations-POST')
    if fields.get('vendorId') != VENDOR or fields.get('productId') != 'base':
        raise SafeError('Installations-POST ist nicht fuer kostenloses Lets Encrypt')
    if fields.get('preferredChallengeType') != 'http-01':
        raise SafeError('HTTP-01 nicht gesetzt')
    for key in ('validateDomain', 'validateWww'):
        if fields.get(key) != 'true':
            raise SafeError('Domain oder www nicht aktiviert')
    for key in ('validateWildcard', 'validateWebMail', 'validateMail',
                'validateMailWithSan', 'validateDane'):
        if fields.get(key) != 'false':
            raise SafeError('Unerwartete zusaetzliche Zertifikatsoption aktiviert')
    settings = fields.get('productSettings')
    if not isinstance(settings, dict) or any(k != 'description' or v != ''
                                              for k, v in settings.items()):
        raise SafeError('Unerwartete Lets-Encrypt-Produktangaben')

def server_response_kind(body, content_type, http_code):
    """Kein HTTP-200-HTML als definitive Plesk-Aktionsbestaetigung werten."""
    if http_code >= 400:
        return 'http_error'
    if 'json' not in content_type.lower():
        return 'unknown'
    try:
        obj = json.loads(body)
    except (TypeError, ValueError):
        return 'unknown'
    if not isinstance(obj, dict):
        return 'unknown'
    state = obj.get('status')
    if state is False or str(state).lower() in ('error', 'fail', 'failed'):
        return 'server_error'
    if obj.get('errors') or obj.get('formErrors') or obj.get('error'):
        return 'server_error'
    if state is True or str(state).lower() in ('success', 'ok'):
        return 'success'
    return 'unknown'

def safe_server_message(body, content_type):
    """Nur kurze JSON-Fehlertexte; keine HTML-Seiten, Cookies oder Rohantworten."""
    if 'json' not in content_type.lower():
        return None
    try:
        data = json.loads(body)
    except (TypeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    candidates = [data.get('message'), data.get('errorMessage'), data.get('error')]
    if isinstance(data.get('errors'), list):
        candidates.extend(data['errors'][:2])
    for item in candidates:
        if not isinstance(item, str) or not item.strip():
            continue
        msg = ' '.join(item.split())[:500]
        msg = re.sub(r'https?://[^\s]+', '[URL]', msg, flags=re.I)
        msg = re.sub(r'(?i)\b(password|token|secret|authorization|cookie|key)\s*[:=]\s*\S+',
                     r'\1=[redacted]', msg)
        msg = re.sub(r'[A-Za-z0-9_-]{40,}', '[redacted]', msg)
        msg = re.sub(r'[\x00-\x1f<>]', '', msg)
        return msg[:300]
    return None

def tls_trusted(host, timeout=5):
    try:
        ctx = tls_module.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                return bool(tls.getpeercert())
    except (OSError, tls_module.SSLError, ValueError):
        return False

def tls_diagnostics(host, timeout=5):
    """Read-only public TLS diagnosis, without logging certificate bodies or secrets."""
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(
            host, 443, type=socket.SOCK_STREAM)})[:8]
    except OSError:
        return {'host': host, 'tls_ok': False, 'reason': 'dns_failed', 'dns_addresses': []}
    try:
        ctx = tls_module.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as connection:
                return {'host': host, 'tls_ok': bool(connection.getpeercert()),
                        'reason': 'valid', 'dns_addresses': addresses}
    except tls_module.SSLCertVerificationError as exc:
        return {'host': host, 'tls_ok': False, 'reason': 'certificate_verification_failed',
                'verify_code': int(getattr(exc, 'verify_code', 0)), 'dns_addresses': addresses}
    except (OSError, tls_module.SSLError, ValueError):
        return {'host': host, 'tls_ok': False, 'reason': 'tls_or_connection_error',
                'dns_addresses': addresses}


def dns_precheck(domain):
    for host in (domain, 'www.' + domain):
        try:
            info = socket.getaddrinfo(host, 80, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise SafeError('DNS-Aufloesung fuer Domain oder www fehlgeschlagen') from exc
        if not info:
            raise SafeError('DNS-Aufloesung fuer Domain oder www leer')

def wait_for_verification(client, domain, domain_id, operation, attempts, interval, log, run_id):
    """Nur GET und TLS-Verbindungen nach EINEM schreibenden POST."""
    for number in range(1, attempts + 1):
        data = ssl_data(client, domain, domain_id)
        state = ssl_status(data)
        if operation == 'install':
            # Plesk assignment and public HTTPS are different facts.
            # Cloudflare can terminate public TLS with its own edge certificate.
            main_tls = tls_trusted(domain) if state['certificate_assigned'] else False
            www_tls = tls_trusted('www.' + domain) if state['certificate_assigned'] else False
            verified = bool(state['certificate_assigned'] and main_tls and www_tls)
        elif operation == 'redirect':
            verified = state['certificate_assigned'] and state['https_redirect']
        elif operation == 'redirect-disable':
            verified = not state['https_redirect']
        else:
            verified = not state['certificate_assigned']
        evidence = ({'tls_domain_ok': main_tls, 'tls_www_ok': www_tls}
                    if operation == 'install' else {})
        log_event(log, run_id, 'verify', operation=operation, attempt=number,
             verified=verified, **evidence, **state)
        if operation == 'install' and number == attempts and not verified and state['certificate_assigned']:
            for host in (domain, 'www.' + domain):
                log_event(log, run_id, 'public_tls_diagnostic',
                          operation=operation, **tls_diagnostics(host))
            log_event(log, run_id, 'assigned_but_public_tls_unverified',
                      operation=operation, domain_id=domain_id)
        print(f'    Pruefung {number}/{attempts}:', 'bestaetigt' if verified else 'noch nicht bestaetigt')
        if verified:
            return True
        if number < attempts:
            time.sleep(interval)
    return False

def self_test():
    domain = 'test.example.com'
    fake_view = ("<script>Plesk.run({\"data\":{\"data\":{\"data\":["
                 "{\"displayName\":\"test.example.com\",\"domainId\":123}]}}})</script>")
    assert domain_id_from_view(fake_view, domain) == 123
    descriptor = {'description': {'id': 'description', 'type': 'description',
                                  'value': '', 'required': False}}
    data = {'domainName': domain, 'siteId': 123,
            'secureDomainCapabilities': {'canSecureDomain': True, 'canSecureWww': True,
                                         'canSelectChallengeType': True},
            'products': {PRODUCT: {'isPaid': False, 'vendorExtendedId': VENDOR,
                                   'id': 'base', 'installFormDescriptor': descriptor,
                                   'supportedChallengeTypes': ['http-01', 'dns-01']}},
            'httpsRedirect': {'params': {'enabled': False,
                                        'canBeAppliedToWebMail': False},
                              'isManageable': True},
            'certificate': None, 'pendingOrder': None}
    html = '<script>main.default(' + json.dumps(data) + ')</script>'
    assert ssl_data_from_page(html, domain, 123) == data
    assert ssl_status(data)['https_redirect'] is False
    assert product_settings(data) == {'description': ''}
    assert install_capabilities(data)
    p, reason = proposal('install', data, 123)
    assert reason is None
    validate_post('install', *p, 123)
    # FormData-Werte werden im Plesk-AJAX-Transport als JSON-Strings kodiert.
    # Der synthetische Testdatensatz muss stabil kodiert werden.
    encoded = json.dumps(p[1], separators=(',', ':'), ensure_ascii=True).encode('utf-8')
    assert len(encoded) == 314, len(encoded)
    for change in ({'preferredChallengeType': 'dns-01'}, {'validateWildcard': 'true'},
                   {'validateWww': 'false'}, {'id': '9999'},
                   {'vendorId': 'sectigo'}, {'productSettings': {'secret': 'x'}}):
        try:
            validate_post('install', p[0], {**p[1], **change}, 123)
            raise AssertionError('Ungueltige Aenderung akzeptiert')
        except SafeError:
            pass
    assert proposal('redirect', data, 123)[0] is not None
    data['certificate'] = {'issued': True}
    for operation in ('redirect', 'unassign'):
        path, fields = proposal(operation, data, 123)[0]
        validate_post(operation, path, fields, 123)
    # Nach Aktivierung muss der gegenteilige POST allein mit der Domain-ID moeglich sein.
    data['httpsRedirect']['params']['enabled'] = True
    disable, reason = proposal('redirect-disable', data, 123)
    assert reason is None
    assert disable == (REDIRECT_DISABLE_PATH, {'id': '123'})
    validate_post('redirect-disable', *disable, 123)
    for wrong_path, wrong_fields in ((REDIRECT_PATH, disable[1]),
                                     (REDIRECT_DISABLE_PATH, {'id': '9999'}),
                                     (REDIRECT_DISABLE_PATH, {'id': '123', 'force': 'true'})):
        try:
            validate_post('redirect-disable', wrong_path, wrong_fields, 123)
            raise AssertionError('Nicht erlaubter Disable-POST wurde akzeptiert')
        except SafeError:
            pass
    data['httpsRedirect']['params']['enabled'] = False
    assert proposal('redirect-disable', data, 123)[0] is None
    data['certificate'] = None
    data['httpsRedirect']['params']['enabled'] = True
    assert proposal('redirect-disable', data, 123)[0] == disable
    data['httpsRedirect']['isManageable'] = False
    assert proposal('redirect-disable', data, 123)[0] is None
    assert server_response_kind('{"status":"error"}', 'application/json', 200) == 'server_error'
    assert server_response_kind('<html></html>', 'text/html', 200) == 'unknown'
    assert server_response_kind('{"status":"ok"}', 'application/json', 200) == 'success'
    assert safe_server_message('{"status":"error","message":"Challenge failed"}',
                               'application/json') == 'Challenge failed'
    print('Selbsttest OK: SSL-Formular, Domain-ID, Redirect ein/aus, POST-Sperren und Serverantworten.')

def run(args, client, domain_id, log, run_id):
    print('=== Plesk SSL It! direkt per Python/HTTPS (modular) ===')
    print('Domain:', args.domain)
    print('[1] Authentifizierte Plesk-Sitzung: bestaetigt')
    print('[2] Domain-ID:', domain_id, '(automatisch ermittelt oder einzeln verifiziert)')
    phase = 'status'
    submitted = False
    try:
        data = ssl_data(client, args.domain, domain_id)
        state = ssl_status(data)
        print('[3] SSL-Status:')
        print('    Zertifikat zugewiesen:', 'ja' if state['certificate_assigned'] else 'nein')
        print('    HTTPS-Umleitung:', 'aktiv' if state['https_redirect'] else 'aus')
        print('    Zertifikatsbestellung offen:', 'ja' if state['pending_order'] else 'nein')
        log_event(log, run_id, 'status_ok', domain_id=domain_id, **state)
        if args.check:
            print('Nur gelesen. Keine SSL-Aenderung ausgefuehrt.')
            return 0
        phase = 'prepare'
        planned, reason = proposal(args.operation, data, domain_id)
        if planned is None:
            print('[4] Keine Aenderung erforderlich oder moeglich:', reason)
            log_event(log, run_id, 'action_skipped', operation=args.operation, reason=reason)
            return 0
        path, fields = planned
        validate_post(args.operation, path, fields, domain_id)
        print('[4] HTTP-POST validiert:', path)
        print('    Felder:', ', '.join(sorted(fields)))
        log_event(log, run_id, 'post_validated', operation=args.operation, domain_id=domain_id,
             path=path, keys=sorted(fields), request_sent=False)
        if args.plan:
            print('    SIMULATION: Anfrage wurde nicht gesendet.')
            return 0
        if args.operation == 'install':
            phase = 'dns'
            dns_precheck(args.domain)
            print('    DNS fuer Domain und www aufloesbar.')
        if args.operation == 'unassign' and state['https_redirect']:
            print('    WARNUNG: HTTPS-Umleitung bleibt aktiv! Zur Deaktivierung zuerst --operation redirect-disable verwenden.')
        # Unmittelbar vor der Aenderung die gleiche Ziel-Domain nochmals abfragen.
        phase = 'recheck'
        fresh_data = ssl_data(client, args.domain, domain_id)
        fresh_planned, fresh_reason = proposal(args.operation, fresh_data, domain_id)
        if fresh_planned is None:
            raise SafeError('Plesk-Status geaendert: ' + (fresh_reason or 'unbekannt'))
        fresh_path, fresh_fields = fresh_planned
        validate_post(args.operation, fresh_path, fresh_fields, domain_id)
        if (fresh_path, fresh_fields) != (path, fields):
            raise SafeError('Formulardaten haben sich seit der Planung geaendert')
        phase = 'post'
        print('[5] Sende genau eine validierte HTTP-Anfrage ...')
        submitted = True  # Bei Verbindungsabbruch kein weiterer POST durch Skript.
        log_event(log, run_id, 'post_submitting', operation=args.operation,
             domain_id=domain_id, path=path)
        http_code, body, content_type = post_json(client, path, fields, domain_id)
        response_kind = server_response_kind(body, content_type, http_code)
        log_event(log, run_id, 'post_response', operation=args.operation,
             http_status=http_code, response_kind=response_kind,
             content_type=content_type.split(';', 1)[0][:80])
        print('    HTTP-Status:', http_code, '| Antwort:', response_kind)
        if response_kind in ('http_error', 'server_error'):
            message = safe_server_message(body, content_type)
            if message:
                print('    Plesk-Fehlermeldung:', message)
                log_event(log, run_id, 'server_error', operation=args.operation, message=message)
            raise SafeError('Plesk hat die Aktion serverseitig abgelehnt; keine Wiederholung')
        phase = 'verify'
        print('[6] Pruefe den tatsaechlichen Plesk-Status ...')
        if wait_for_verification(client, args.domain, domain_id, args.operation,
                                 args.verify_attempts, args.verify_interval, log, run_id):
            print('ERFOLG: SSL-Aktion serverseitig verifiziert.')
            log_event(log, run_id, 'verified', operation=args.operation, domain_id=domain_id)
            return 0
        log_event(log, run_id, 'outcome_unknown', operation=args.operation,
             reason='post_sent_but_not_verified')
        print('STATUS UNGEKLAERT: POST wurde gesendet, Ergebnis nicht verifiziert.', file=sys.stderr)
        print('Keine automatische Wiederholung; zuerst Plesk-Status pruefen.', file=sys.stderr)
        return 3
    except (SafeError, ValueError, TypeError) as exc:
        print('STOP:', exc, file=sys.stderr)
        if submitted:
            print('HINWEIS: Ein POST kann bereits verarbeitet worden sein. Nicht blind wiederholen.',
                  file=sys.stderr)
        log_event(log, run_id, 'failed', phase=phase, submitted=submitted,
             reason_type=type(exc).__name__)
        return 3 if submitted else 1
    except Exception as exc:
        print('STOP:', phase, type(exc).__name__, file=sys.stderr)
        if submitted:
            print('POST moeglicherweise verarbeitet. Erst Plesk-Status pruefen.', file=sys.stderr)
        log_event(log, run_id, 'failed', phase=phase, submitted=submitted,
             reason_type=type(exc).__name__)
        return 3 if submitted else 1
