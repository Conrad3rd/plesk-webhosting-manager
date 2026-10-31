"""Read-only PHP choices from the authenticated Plesk PHP settings form."""
from __future__ import annotations

import json
import re
from uuid import uuid4

from . import php
from .core import PleskError, domain_id_from_view, log_event

_MARKED = re.compile(r'\b(outdated|obsolete|deprecated|end.of.life|eol|veraltet|ueberholt|überholt)\b', re.I)


def _obsolete_metadata(row):
    """Return True/False only for explicit Plesk flags, otherwise None."""
    for name in ('isOutdated', 'outdated', 'isObsolete', 'obsolete', 'isDeprecated', 'deprecated'):
        if type(row.get(name)) is bool:
            return row[name]
    for name in ('version', 'label', 'title', 'displayName'):
        value = row.get(name)
        if isinstance(value, str) and _MARKED.search(value):
            return True
    return None


def collect(client, view, domain, domain_id=None):
    identified = domain_id_from_view(view, domain)
    if domain_id is not None and domain_id != identified:
        raise PleskError('Explizite Domain-ID widerspricht der Plesk-Domainliste')
    code, html, _ = client.request(f'/smb/web/php-settings/id/{identified}')
    if code != 200:
        raise PleskError('PHP-Einstellungsseite nicht erreichbar')
    status = php.settings_data(html, domain, identified)
    rows = status['data'].get('handlers') or []
    result = []
    for version in sorted(status['versions'], key=lambda v: tuple(map(int, v.split('.'))), reverse=True):
        key, options = status['versions'][version]
        matching = [row for row in rows if isinstance(row, dict) and row.get('id') == key]
        if len(matching) != 1:
            raise PleskError('PHP-Handler-Metadaten nicht eindeutig')
        obsolete = _obsolete_metadata(matching[0])
        handler = f'php{version.replace(".", "")}-fastcgi-nc'
        result.append({'version': version, 'available': isinstance(options, dict) and handler in options,
                       'outdated': obsolete, 'outdated_status': 'unknown' if obsolete is None else ('outdated' if obsolete else 'supported'),
                       'selected': status['version'] == version, 'handler': handler if isinstance(options, dict) and handler in options else None})
    return {'schema_version': 1, 'domain': domain, 'domain_id': identified,
            'default_version': '8.5', 'current_version': status['version'],
            'versions': result}


def run(args, client, view, account, host, logfile):
    run_id = getattr(args, '_cli_run_id', None) or uuid4().hex[:12]
    log_event(logfile, run_id, 'started', section='php_versions', domain=args.domain, account=account, host=host)
    try:
        result = collect(client, view, args.domain, args.domain_id)
        result['account'] = account
        result['host'] = host
        log_event(logfile, run_id, 'completed', section='php_versions', domain=args.domain,
                  version_count=len(result['versions']))
        if args.json:
            print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        else:
            for row in result['versions']:
                print(row['version'], '|', row['outdated_status'], '|', 'verfuegbar' if row['available'] else 'nicht verfuegbar')
        return 0
    except Exception as exc:
        log_event(logfile, run_id, 'failed', section='php_versions', domain=args.domain, reason_type=type(exc).__name__)
        raise
