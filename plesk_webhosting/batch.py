"""Eigenstaendiger Plesk-Batch: eine Anmeldung, gepruefte Schreibaktionen nacheinander."""
from __future__ import annotations

from argparse import Namespace
import json
import sys
from contextlib import redirect_stdout
from time import monotonic
from uuid import uuid4

from . import inspect, php, ssl
from .core import PleskError, domain_id_from_view, log_event


def choose_steps(args):
    steps = []
    if args.php_version:
        steps.append(('php', None))
    if args.https_redirect:
        steps.append(('https_redirect', 'redirect'))
    if args.ssl_install:
        steps.append(('ssl_install', 'install'))
    return steps


def run(args, client, view, account, host, logfile):
    run_id = getattr(args, '_cli_run_id', None) or uuid4().hex[:12]
    domain_id = domain_id_from_view(view, args.domain)
    if args.domain_id is not None and args.domain_id != domain_id:
        raise PleskError('Explizite Domain-ID widerspricht der Domainliste')
    steps = choose_steps(args)
    results = []
    log_event(logfile, run_id, 'started', section='batch', domain=args.domain,
              domain_id=domain_id, account=account, host=host, mode='apply' if args.apply else 'plan')
    for label, ssl_operation in steps:
        started = monotonic()
        if label == 'php':
            options = Namespace(domain=args.domain, php_version=args.php_version, basedir=args.basedir,
                                check=False, plan=args.plan, apply=args.apply, yes=args.yes,
                                show_settings=False, verify_attempts=args.verify_attempts,
                                verify_interval=args.verify_interval)
            if args.json:
                with redirect_stdout(sys.stderr):
                    status = php.run(options, client, domain_id, logfile, run_id)
            else:
                status = php.run(options, client, domain_id, logfile, run_id)
        else:
            options = Namespace(domain=args.domain, operation=ssl_operation,
                                check=False, plan=args.plan, apply=args.apply, yes=args.yes,
                                verify_attempts=12, verify_interval=5.0)
            if args.json:
                with redirect_stdout(sys.stderr):
                    status = ssl.run(options, client, domain_id, logfile, run_id)
            else:
                status = ssl.run(options, client, domain_id, logfile, run_id)
        consumed = client._write_consumed
        if status == 0 and args.apply:
            # Das Untermodul muss bereits die serverseitige Verifikation erfolgreich
            # abgeschlossen haben. Anschliessend nochmals den gemeinsamen Istzustand lesen.
            try:
                snapshot = inspect.collect(client, view, args.domain, domain_id)
                if label == 'php':
                    verified = (snapshot['php']['enabled'] and
                                snapshot['php']['version'] == args.php_version and
                                snapshot['php']['open_basedir'] == php.BASEDIR[args.basedir])
                elif label == 'https_redirect':
                    verified = snapshot['ssl']['https_redirect'] is True
                else:
                    verified = snapshot['ssl']['certificate_assigned'] is True
                if not verified:
                    raise PleskError('Gewuenschter Zielzustand nicht bestaetigt')
                if consumed:
                    client.finish_verified_write(verified=True)
            except Exception:
                client.retire_writes()
                status = 3
        elapsed = round(monotonic() - started, 3)
        results.append({'step': label, 'exit_code': status, 'duration_seconds': elapsed,
                        'post_submitted': consumed})
        log_event(logfile, run_id, 'step_completed', section='batch', domain=args.domain,
                  step=label, exit_code=status, duration_seconds=elapsed)
        if status != 0:
            client.retire_writes()
            break  # Keine weiteren schreibenden Aktionen bei ungeklärtem Ergebnis.
    result = {'schema_version': 1, 'domain': args.domain, 'run_id': run_id,
              'mode': 'apply' if args.apply else 'plan', 'steps': results,
              'completed': len(results) == len(steps) and all(r['exit_code'] == 0 for r in results)}
    if args.json:
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    else:
        print('Batch:', 'abgeschlossen' if result['completed'] else 'unterbrochen',
              '| Schritte:', len(results), '/', len(steps))
    log_event(logfile, run_id, 'completed' if result['completed'] else 'failed',
              section='batch', domain=args.domain, completed=result['completed'])
    return 0 if result['completed'] else (results[-1]['exit_code'] or 1)
