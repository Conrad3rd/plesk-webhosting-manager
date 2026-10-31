"""Eigenstaendige Linux-Kommandozeile fuer Plesk-Webhosting."""
from __future__ import annotations

import argparse
from contextvars import ContextVar
from pathlib import Path
import sys
import re
from uuid import uuid4

from . import accounts, batch, domains, inspect, parallel, php, php_versions, ssl, subdomain
from .core import VERSION, PleskError, PleskSession, domain_id_from_view, log_event, valid_domain, default_log_path, correlation_context


# Eine Registrierung pro CLI-Aufruf, auch fuer unabhaengige Worker-Prozesse.
# Der Shared-Session-Batch registriert nur den urspruenglichen Login-Client.
_active_cli_sessions = ContextVar('plesk_cli_sessions', default=None)


def _new_session(host, username, password):
    client = PleskSession(host, username, password)
    registry = _active_cli_sessions.get()
    if registry is not None:
        registry.append(client)
    return client


def _finish_cli_sessions(registry, logfile, run_id=None):
    for client in reversed(registry):
        if not callable(getattr(client, 'logout_on_exit', None)):
            continue  # Aeltere Offline-Tests mit Minimal-MockSession.
        try:
            result = client.logout_on_exit()
            try:
                log_event(logfile, run_id or uuid4().hex[:12], 'session_logout',
                          section='session', host=client.host, **result)
            except Exception:
                pass  # Diagnose darf das fachliche CLI-Ergebnis nicht veraendern.
            if result['status'] in ('failed', 'unverified', 'blocked_in_flight'):
                print('WARNUNG: Plesk-Logout nicht bestaetigt (' + result['status'] + ')', file=sys.stderr)
        except Exception:
            print('WARNUNG: Fehler beim Sitzungsabschluss', file=sys.stderr)
        finally:
            close = getattr(client, 'close', None)
            if callable(close):
                close()


def operation_id_arg(value: str) -> str:
    """Accept a safe, bounded correlation ID, never a shell expression."""
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{7,63}', value):
        raise argparse.ArgumentTypeError('Ungueltige Vorgangskennung (8-64 Zeichen, A-Z, 0-9, _ oder -)')
    return value


def build_parser():
    parser = argparse.ArgumentParser(
        prog='plesk-webhosting.py',
        description='Plesk Webhosting Manager fuer Linux: Subdomains, Domainliste, SSL It!, PHP, Kontenprofile',
        epilog='Beispiele und Installation: README.txt')
    parser.add_argument('--operation-id', type=operation_id_arg,
                        help='Optionale gemeinsame Vorgangskennung aus einer aufrufenden Anwendung')
    parser.add_argument('--account', help='Gespeichertes Kontenprofil; bei genau einem Profil optional')
    parser.add_argument('--domain', help='Exakter Domainname fuer PHP, SSL oder Subdomain-Aktionen')
    parser.add_argument('--domain-id', type=int, help='Fallback bei paginierter Domainliste; Zielseite wird geprueft')
    parser.add_argument('--log', type=Path, default=default_log_path(),
                        help='JSONL-Protokoll, Standard: logs/events.jsonl im Programmverzeichnis')
    cmds = parser.add_subparsers(dest='command', required=True)
    account = cmds.add_parser('account', help='Unabhaengige Linux-Schluesselbund-Konten verwalten')
    account_cmds = account.add_subparsers(dest='account_command', required=True)
    account_cmds.add_parser('list', help='Kontenprofile ohne Passwoerter anzeigen')
    add = account_cmds.add_parser('add', help='Konto einrichten; Passwort verborgen eingeben')
    add.add_argument('--name', required=True, help='Eindeutiger Profilname')
    add.add_argument('--host', required=True, help='Plesk-Host, z. B. xxxxx.webhosting.systems')
    add.add_argument('--user', required=True, help='Plesk-Anmeldename')
    add.add_argument('--import-legacy', action='store_true',
                     help='Optionaler Import eines vorhandenen alten Schluesselbund-Eintrags')
    remove = account_cmds.add_parser('remove', help='Profil und eigenes Keyring-Passwort loeschen')
    remove.add_argument('--name', required=True)
    remove.add_argument('--yes', action='store_true')

    cmds.add_parser('self-test', help='Alle Offline-Selbsttests ohne Login ausfuehren')
    cmds.add_parser('logout-check', help='Einmaligen serverseitigen Logout kontrolliert pruefen')
    domain_cmd = cmds.add_parser('domains', help='Auswaehlbare Plesk-Hauptdomains nur lesen')
    domain_sub = domain_cmd.add_subparsers(dest='domains_command', required=True)
    domain_list = domain_sub.add_parser('list', help='Hauptdomains aus Subdomain-Auswahl anzeigen')
    domain_list.add_argument('--json', action='store_true', help='Maschinenlesbare JSON-Ausgabe auf stdout')
    version_cmd = cmds.add_parser('php-versions', help='PHP-Versionen und Plesk-Alterskennzeichnungen nur lesen')
    version_cmd.add_argument('--json', action='store_true', help='Maschinenlesbares JSON auf stdout')
    inspector = cmds.add_parser('inspect', help='PHP- und SSL-Status mit nur einer Anmeldung lesen')
    inspector.add_argument('--json', action='store_true', help='Strukturiertes JSON auf stdout')
    batch_cmd = cmds.add_parser('batch', help='PHP, HTTPS und SSL in einer Plesk-Sitzung abarbeiten')
    batch_mode = batch_cmd.add_mutually_exclusive_group(required=True)
    batch_mode.add_argument('--plan', action='store_true', help='Nur lesend planen')
    batch_mode.add_argument('--apply', action='store_true', help='Ausgewaehlte Aktionen ausfuehren')
    batch_cmd.add_argument('--parallel', action='store_true',
                           help='Unabhaengige Aktionen mit getrennten Plesk-Sitzungen parallel ausfuehren')
    batch_cmd.add_argument('--shared-session', action='store_true',
                           help='Experimentell: parallele Worker mit einer Plesk-Anmeldung und getrennten HTTP-Clients')
    batch_cmd.add_argument('--yes', action='store_true', help='Schreibaktionen ausdruecklich bestaetigen')
    batch_cmd.add_argument('--php-version', help='PHP-Zielversion, etwa 8.5')
    batch_cmd.add_argument('--basedir', choices=tuple(php.BASEDIR), default='WEBSPACEROOT')
    batch_cmd.add_argument('--https-redirect', action='store_true', help='HTTPS-Weiterleitung aktivieren')
    batch_cmd.add_argument('--ssl-install', action='store_true', help='Lets Encrypt installieren, falls erforderlich')
    batch_cmd.add_argument('--verify-attempts', type=int, default=8)
    batch_cmd.add_argument('--verify-interval', type=float, default=3.0)
    batch_cmd.add_argument('--json', action='store_true', help='Maschinenlesbares Ergebnis')
    for module_name in ('php', 'ssl'):
        sub = cmds.add_parser(module_name, help=f'{module_name.upper()} pruefen oder konfigurieren')
        mode = sub.add_mutually_exclusive_group(required=True)
        mode.add_argument('--check', action='store_true', help='Status nur lesen')
        mode.add_argument('--plan', '--dry-run', action='store_true', dest='plan',
                          help='Schreibaktion vorbereiten, NICHT absenden')
        mode.add_argument('--apply', action='store_true', help='Aktion tatsaechlich ausfuehren')
        mode.add_argument('--self-test', action='store_true', help='Nur modulspezifische Offline-Tests')
        sub.add_argument('--yes', action='store_true', help='Schreibaktion ausdruecklich freigeben')
        sub.add_argument('--verify-attempts', type=int, default=8 if module_name=='php' else 12)
        sub.add_argument('--verify-interval', type=float, default=3.0 if module_name=='php' else 5.0)
        if module_name == 'php':
            sub.add_argument('--php-version', default='8.5', help='Verfuegbare PHP-Version, z. B. 8.5')
            sub.add_argument('--basedir', choices=tuple(php.BASEDIR), default='WEBSPACEROOT')
            sub.add_argument('--show-settings', action='store_true')
        else:
            sub.add_argument('--operation', choices=['install', 'redirect', 'redirect-disable', 'unassign'],
                             default='install')
            sub.add_argument('--confirm-unassign', help='Bei unassign exakt den Domainnamen wiederholen')
    sub = cmds.add_parser('subdomain', help='Subdomain lesen oder erstellen; Loeschung abgesichert')
    mode = sub.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check', action='store_true', help='Subdomain und Dokumentenstamm lesen')
    mode.add_argument('--plan', '--dry-run', dest='plan', action='store_true',
                      help='Aktion nur planen, nichts schreiben')
    mode.add_argument('--apply', action='store_true', help='Subdomain-Aktion ausfuehren')
    mode.add_argument('--self-test', action='store_true', help='Offline-Tests fuer die Subdomain-Verwaltung')
    sub.add_argument('--operation', choices=['create', 'delete'], default='create')
    sub.add_argument('--parent-domain', required=False, help='Hauptdomain, z. B. example.de')
    sub.add_argument('--document-root', help='Relativer Dokumentenstamm, z. B. test.example.de/public')
    sub.add_argument('--confirm-create', help='Bei --apply den genauen Subdomainnamen bestaetigen')
    sub.add_argument('--confirm-delete', help='Bei --apply delete den exakten Subdomainnamen angeben')
    sub.add_argument('--confirm-delete-id', type=int, help='Bei --apply delete die zuvor angezeigte Plesk-Domain-ID angeben')
    sub.add_argument('--yes', action='store_true', help='Aktion bestaetigen')
    sub.add_argument('--verify-attempts', type=int, default=8)
    sub.add_argument('--verify-interval', type=float, default=3.0)
    return parser


def run(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    # Only log metadata is correlated. A separate run_id is retained for every
    # Plesk CLI invocation and every individual POST verification.
    registry = []
    args._cli_run_id = uuid4().hex[:12]
    # Parallel-Batches benoetigen ihre Vorgangskennung bereits VOR dem
    # correlation_context: Sonst erzeugt der Orchestrator die ID erst spaeter,
    # und die abschliessende session_logout-Meldung verliert sie.
    # Explizit uebergebene operation_id bleibt unveraendert.
    if (args.command == 'batch' and getattr(args, 'parallel', False)
            and not args.operation_id):
        args.operation_id = uuid4().hex[:16]
    token = _active_cli_sessions.set(registry)
    try:
        with correlation_context(args.operation_id):
            return _run_with_args(parser, args)
    finally:
        try:
            # Der Kontext muss auch beim Logout aktiv bleiben. Hierdurch
            # uebernimmt log_event dieselbe operation_id wie Fachereignisse.
            with correlation_context(args.operation_id):
                _finish_cli_sessions(registry, args.log.expanduser().resolve(), args._cli_run_id)
        finally:
            _active_cli_sessions.reset(token)


def _run_with_args(parser, args):
    try:
        if args.command == 'account':
            if args.account_command == 'list':
                accounts.list_profiles()
            elif args.account_command == 'add':
                accounts.add_profile(args.name, args.host, args.user, args.import_legacy)
            else:
                accounts.remove_profile(args.name, args.yes)
            return 0
        if args.command == 'self-test' or getattr(args, 'self_test', False):
            if args.command in ('self-test', 'php'):
                php.self_test()
            if args.command in ('self-test', 'ssl'):
                ssl.self_test()
            if args.command in ('self-test', 'subdomain'):
                subdomain.self_test()
            if args.command == 'self-test':
                print('Alle Offline-Selbsttests erfolgreich. Keine Netzwerkanfragen.')
            return 0
        if args.command == 'logout-check':
            if args.domain or args.domain_id is not None:
                parser.error('logout-check braucht keine Domain oder Domain-ID')
            name, entry = accounts.find_profile(args.account)
            password = accounts.get_password(name, entry)
            client = _new_session(entry['host'], entry['user'], password)
            del password
            run_id = args._cli_run_id
            logfile = args.log.expanduser().resolve()
            try:
                client.login()
                print('Plesk-Anmeldung bestaetigt. Fuehre einmaligen Logout aus.')
                result = client.logout_regression_check()
                log_event(logfile, run_id, 'logout_regression', section='logout-check',
                          account=name, host=entry['host'], **result)
                print('Logout-HTTP-Status:', result['logout_http_status'])
                print('Verifikation:', result['verification_path'])
                print('Serverseitiger Logout bestaetigt:',
                      'ja' if result['session_invalidated'] else 'NEIN')
                return 0 if result['session_invalidated'] else 2
            finally:
                client.close()
        if args.command == 'domains':
            if args.domain or args.domain_id is not None:
                parser.error('domains list benoetigt weder --domain noch --domain-id')
            name, entry = accounts.find_profile(args.account)
            password = accounts.get_password(name, entry)
            client = _new_session(entry['host'], entry['user'], password)
            del password
            client.login()
            return domains.run(args, client, name, entry['host'], args.log.expanduser().resolve())
        if not args.domain:
            parser.error('Fuer PHP/SSL/Subdomains ist --domain vor dem Unterbefehl erforderlich')
        args.domain = args.domain.strip().rstrip('.').lower()
        if not valid_domain(args.domain):
            parser.error('Ungueltiger Domainname')
        if args.domain_id is not None and args.domain_id < 1:
            parser.error('--domain-id muss positiv sein')
        if args.command == 'subdomain':
            if args.domain_id is not None:
                parser.error('Bei subdomain wird die Domain-ID automatisch ermittelt; --domain-id nicht verwenden')
            if not args.parent_domain:
                parser.error('Subdomain-Befehl erfordert --parent-domain')
            args.parent_domain = args.parent_domain.strip().rstrip('.').lower()
            if not valid_domain(args.parent_domain):
                parser.error('Ungueltige --parent-domain')
            if args.apply and not args.yes:
                parser.error('Subdomain --apply erfordert --yes')
            if args.apply and args.operation == 'delete':
                if (args.confirm_delete != args.domain or
                        not args.confirm_delete_id or args.confirm_delete_id <= 0 or
                        not args.document_root):
                    parser.error('Loeschen erfordert --confirm-delete DOMAIN, '
                                 '--confirm-delete-id ID und --document-root sowie --yes')
        if args.command == 'batch':
            if not (args.php_version or args.https_redirect or args.ssl_install):
                parser.error('batch erfordert mindestens eine Aktion')
            if args.apply and not args.yes:
                parser.error('batch --apply erfordert --yes')
            if args.yes and not args.apply:
                parser.error('batch --yes ist nur mit --apply erlaubt')
            if args.php_version and not re.fullmatch(r'\d+\.\d+', args.php_version):
                parser.error('PHP-Version z. B. 8.5 angeben')
            if not 1 <= args.verify_attempts <= 20 or not 1 <= args.verify_interval <= 30:
                parser.error('Ungueltige Verifikationswerte')
            if args.shared_session and args.json:
                parser.error('--shared-session --json noch nicht unterstuetzt (Thread-Ausgaben)')
            if args.shared_session and not args.parallel:
                parser.error('--shared-session erfordert --parallel')
            if args.parallel:
                if args.https_redirect and args.ssl_install:
                    parser.error('Gleichzeitige SSL-Installation und HTTPS-Umleitung ist nicht freigegeben')
                if sum(bool(x) for x in (args.php_version, args.https_redirect, args.ssl_install)) < 2:
                    parser.error('batch --parallel benoetigt mindestens zwei Aktionen')
                name, entry = accounts.find_profile(args.account)
                args.operation_id = getattr(args, 'operation_id', None)
                if args.shared_session:
                    from . import shared_parallel
                    password = accounts.get_password(name, entry)
                    client = _new_session(entry['host'], entry['user'], password)
                    del password
                    # Die zentrale CLI-Abschlussbehandlung meldet die gemeinsame
                    # Sitzung erst NACH dem Ende beider Worker serverseitig ab.
                    # Kein vorzeitiges close(): es loescht Login-Cookies/CSRF.
                    view = client.login()
                    return shared_parallel.run(args, client, view, name, entry['host'],
                                               args.log.expanduser().resolve())
                return parallel.run(args, name, args.log.expanduser().resolve())
            name, entry = accounts.find_profile(args.account)
            password = accounts.get_password(name, entry)
            client = _new_session(entry['host'], entry['user'], password)
            del password
            view = client.login()
            return batch.run(args, client, view, name, entry['host'], args.log.expanduser().resolve())
        if args.command == 'php-versions':
            name, entry = accounts.find_profile(args.account)
            password = accounts.get_password(name, entry)
            client = _new_session(entry['host'], entry['user'], password)
            del password
            view = client.login()
            return php_versions.run(args, client, view, name, entry['host'], args.log.expanduser().resolve())
        if args.command == 'inspect':
            if not args.domain:
                parser.error('inspect erfordert --domain')
            name, entry = accounts.find_profile(args.account)
            password = accounts.get_password(name, entry)
            client = _new_session(entry['host'], entry['user'], password)
            del password
            view = client.login()
            return inspect.run(args, client, view, name, entry['host'], args.log.expanduser().resolve())
        if args.yes and not args.apply:
            parser.error('--yes ist nur mit --apply erlaubt')
        if args.apply and args.command=='ssl' and not args.yes:
            parser.error('SSL --apply erfordert --yes')
        if args.command=='ssl' and args.apply and args.operation=='unassign' and args.confirm_unassign!=args.domain:
            parser.error('Zertifikatzuweisung aufheben erfordert --confirm-unassign DOMAIN')
        if not 1 <= args.verify_attempts <= (20 if args.command in ('php', 'subdomain') else 30):
            parser.error('Ungueltige --verify-attempts')
        if args.command in ('php', 'subdomain') and not 1 <= args.verify_interval <= 30:
            parser.error('PHP --verify-interval muss zwischen 1 und 30 liegen')
        if args.command == 'ssl' and not 0 <= args.verify_interval <= 30:
            parser.error('SSL --verify-interval muss zwischen 0 und 30 liegen')
        if args.command == 'php':
            if not re.fullmatch(r'\d+\.\d+', args.php_version):
                parser.error('PHP-Version z. B. 8.5 angeben')
        name, entry = accounts.find_profile(args.account)
        password = accounts.get_password(name, entry)
        client = _new_session(entry['host'], entry['user'], password)
        del password
        view = client.login()
        # Eine neu zu erstellende Subdomain besitzt noch keine Domain-ID.
        # Der Subdomain-Befehl prueft die Zielidentitaet selbst gegen die Domainliste.
        if args.command == 'subdomain':
            run_id = args._cli_run_id
            path = args.log.expanduser().resolve()
            log_event(path, run_id, 'started', section='subdomain', domain=args.domain,
                      account=name, host=entry['host'],
                      operation=('check' if args.check else 'plan' if args.plan else 'apply'),
                      subdomain_action=args.operation)
            print('Konto:', name, '| Host:', entry['host'])
            return subdomain.run(args, client, view, path, run_id)
        try:
            domain_id = domain_id_from_view(view, args.domain)
        except PleskError:
            if not args.domain_id:
                raise
            domain_id = args.domain_id
        else:
            if args.domain_id is not None and args.domain_id != domain_id:
                raise PleskError('Explizite Domain-ID widerspricht der Plesk-Domainliste')
        run_id = args._cli_run_id
        path = args.log.expanduser().resolve()
        log_event(path, run_id, 'started', section=args.command, domain=args.domain,
                  domain_id=domain_id, account=name, host=entry['host'],
                  operation=('check' if args.check else 'plan' if args.plan else 'apply'))
        print('Konto:', name, '| Host:', entry['host'])
        if args.command == 'php':
            return php.run(args, client, domain_id, path, run_id)
        return ssl.run(args, client, domain_id, path, run_id)
    except PleskError as exc:
        print('STOP:', str(exc), file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print('Abgebrochen.', file=sys.stderr)
        return 130
    except Exception as exc:
        print('STOP: Unerwarteter Fehler:', type(exc).__name__, file=sys.stderr)
        return 1
