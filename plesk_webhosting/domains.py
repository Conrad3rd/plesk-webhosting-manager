"""Nur lesender Export der Plesk-Hauptdomains fuer andere Anwendungen."""
from __future__ import annotations

import json
from uuid import uuid4

from .core import PleskError, log_event
from .subdomain import CREATE_PATH, CreationForm, selectable_parent_domains

SCHEMA_VERSION = 1


def read_domains(client):
    """Exakt die im Plesk-Formular auswaehlbaren Hauptdomains auslesen.

    Das Formular wird per GET abgerufen. Dies ist keine vollstaendige Liste
    aller Subdomains, Aliase oder aller unter einem Account vorhandenen Sites.
    """
    code, html, _ = client.request(CREATE_PATH)
    if code != 200:
        raise PleskError('Plesk-Hauptdomain-Auswahl nicht erreichbar')
    form = CreationForm()
    form.feed(html)
    return selectable_parent_domains(form)


def run(args, client, account_name, host, logfile):
    run_id = getattr(args, '_cli_run_id', None) or uuid4().hex[:12]
    log_event(logfile, run_id, 'started', section='domains',
              account=account_name, host=host, operation='list')
    try:
        choices = read_domains(client)
    except PleskError:
        log_event(logfile, run_id, 'failed', section='domains', reason='read_or_parse_error')
        raise
    log_event(logfile, run_id, 'list_ok', section='domains', count=len(choices),
              source='plesk_subdomain_form')
    if args.json:
        # Einziges stdout-Element fuer maschinelle Verwendung.
        print(json.dumps({
            'schema_version': SCHEMA_VERSION,
            'account': account_name,
            'host': host,
            'scope': 'subdomain_parent_domains',
            'source': 'plesk_subdomain_form',
            'domains': choices,
        }, ensure_ascii=False, sort_keys=True))
    else:
        print('Konto:', account_name, '| Host:', host)
        print('Plesk-Hauptdomains fuer neue Subdomains:')
        for entry in choices:
            print('  ' + entry['name'] + ' (ID: ' + str(entry['id']) + ')')
        print('Nur gelesen. Keine Aenderungen vorgenommen.')
    return 0
