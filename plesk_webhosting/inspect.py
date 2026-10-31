"""Eigenstaendige, nur lesende Sammelpruefung mit einer Plesk-Anmeldung."""
from __future__ import annotations

import json
from uuid import uuid4

from . import php, ssl
from .core import PleskError, domain_id_from_view, log_event


def collect(client, view, domain: str, domain_id: int | None = None) -> dict:
    """Liest PHP und SSL in derselben Sitzung. Keine Schreibberechtigung."""
    identified = domain_id_from_view(view, domain)
    if domain_id is not None and identified != domain_id:
        raise PleskError('Explizite Domain-ID widerspricht der Plesk-Domainliste')
    path = f'/smb/web/php-settings/id/{identified}'
    status_code, html, _ = client.request(path)
    if status_code != 200:
        raise PleskError('PHP-Einstellungsseite nicht erreichbar')
    php_data = php.settings_data(html, domain, identified)
    ssl_data = ssl.ssl_data(client, domain, identified)
    ssl_state = ssl.ssl_status(ssl_data)
    return {
        'schema_version': 1, 'domain': domain, 'domain_id': identified,
        'php': {
            'enabled': php_data['php_enabled'],
            'version': php_data['version'],
            'open_basedir': php_data['basedir'],
        },
        'ssl': {
            'certificate_assigned': ssl_state['certificate_assigned'],
            'https_redirect': ssl_state['https_redirect'],
            'pending_order': ssl_state['pending_order'],
            'redirect_manageable': ssl_state['redirect_manageable'],
        },
    }


def run(args, client, view, account: str, host: str, logfile) -> int:
    run_id = getattr(args, '_cli_run_id', None) or uuid4().hex[:12]
    log_event(logfile, run_id, 'started', section='inspect', domain=args.domain,
              account=account, host=host)
    try:
        result = collect(client, view, args.domain, args.domain_id)
        result['account'] = account
        result['host'] = host
        log_event(logfile, run_id, 'completed', section='inspect',
                  domain=args.domain, domain_id=result['domain_id'],
                  php_enabled=result['php']['enabled'],
                  certificate_assigned=result['ssl']['certificate_assigned'],
                  https_redirect=result['ssl']['https_redirect'])
        if args.json:
            print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        else:
            print('Domain:', result['domain'])
            print('Domain-ID:', result['domain_id'])
            print('PHP:', result['php']['version'], '| aktiv:', result['php']['enabled'])
            print('open_basedir:', result['php']['open_basedir'])
            print('SSL-Zertifikat zugewiesen:', result['ssl']['certificate_assigned'])
            print('HTTPS-Umleitung:', result['ssl']['https_redirect'])
            print('Zertifikatsbestellung offen:', result['ssl']['pending_order'])
        return 0
    except Exception as exc:
        log_event(logfile, run_id, 'failed', section='inspect',
                  domain=args.domain, reason_type=type(exc).__name__)
        raise
