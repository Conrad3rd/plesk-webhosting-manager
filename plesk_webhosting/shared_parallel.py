"""Experimenteller Standalone-Batch: eine Anmeldung, isolierte HTTP-Worker.

Keine gemeinsamen CookieJars/Opener/POST-Grants; kein automatisches Retry.
Nur PHP und HTTPS-Redirect, nie zwei SSL-It!-Schreibaktionen gleichzeitig.
"""
from __future__ import annotations

from argparse import Namespace
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import redirect_stdout
from io import StringIO
from time import monotonic
from uuid import uuid4
import json
import sys

from . import inspect, php, ssl
from .core import PleskError, correlation_context, domain_id_from_view, log_event


def run(args, client, view, account, host, logfile):
    if not (args.php_version and args.https_redirect) or args.ssl_install:
        raise PleskError('--shared-session erlaubt nur PHP und HTTPS-Umleitung gemeinsam')
    domain_id = domain_id_from_view(view, args.domain)
    if args.domain_id is not None and args.domain_id != domain_id:
        raise PleskError('Domain-ID widerspricht Plesk-Domainliste')
    # Vor dem parallelen Start unabhaengige HTTP-Clients mit derselben Login-Identitaet.
    workers = {'php': client.fork_authenticated_worker(),
               'https_redirect': client.fork_authenticated_worker()}
    run_id = getattr(args, '_cli_run_id', None) or uuid4().hex[:12]
    operation_id = getattr(args, 'operation_id', None) or uuid4().hex[:16]
    log_event(logfile, run_id, 'started', section='shared_parallel_batch',
              domain=args.domain, account=account, host=host, operation_id=operation_id,
              mode='apply' if args.apply else 'plan', workers=2)

    def work(label, worker):
        # ContextVars werden nicht automatisch in ThreadPoolExecutor-Threads
        # uebernommen. Jeder Worker erhaelt den zugeordneten Vorgangskontext.
        with correlation_context(operation_id):
            return work_correlated(label, worker)

    def work_correlated(label, worker):
        started = monotonic()
        output = StringIO()
        status = 3
        error_type = None
        consumed = False
        try:
            # redirect_stdout ist global, deshalb nicht in Threads verwenden.
            # Untermodul-Ausgaben sind im interaktiven Modus sichtbar.
            if label == 'php':
                options = Namespace(domain=args.domain, php_version=args.php_version,
                                    basedir=args.basedir, check=False, plan=args.plan,
                                    apply=args.apply, yes=args.yes, show_settings=False,
                                    verify_attempts=args.verify_attempts,
                                    verify_interval=args.verify_interval)
                status = php.run(options, worker, domain_id, logfile, run_id)
            else:
                options = Namespace(domain=args.domain, operation='redirect', check=False,
                                    plan=args.plan, apply=args.apply, yes=args.yes,
                                    verify_attempts=args.verify_attempts,
                                    verify_interval=args.verify_interval)
                status = ssl.run(options, worker, domain_id, logfile, run_id)
            consumed = worker._write_consumed
            if status == 0 and args.apply:
                # Beide Worker verifizieren ausschliesslich ihr eigenes Ziel.
                snapshot = inspect.collect(worker, view, args.domain, domain_id)
                if label == 'php':
                    good = (snapshot['php']['enabled'] and
                            snapshot['php']['version'] == args.php_version and
                            snapshot['php']['open_basedir'] == php.BASEDIR[args.basedir])
                else:
                    good = snapshot['ssl']['https_redirect'] is True
                if not good:
                    raise PleskError('Abschliessender Zielzustand nicht bestaetigt')
                if consumed:
                    worker.finish_verified_write(verified=True)
        except Exception as exc:
            error_type = type(exc).__name__
            status = 3
            worker.retire_writes()
        finally:
            worker.close()
        result = {'step': label, 'exit_code': status,
                  'duration_seconds': round(monotonic()-started, 3),
                  'post_submitted': consumed}
        if error_type:
            result['error_type'] = error_type
        log_event(logfile, run_id, 'step_completed', section='shared_parallel_batch',
                  domain=args.domain, operation_id=operation_id, **result)
        return result

    results = []
    with ThreadPoolExecutor(max_workers=2, thread_name_prefix='plesk-shared') as pool:
        futures = {pool.submit(work, label, worker): label for label, worker in workers.items()}
        for future in as_completed(futures):
            results.append(future.result())
    results.sort(key=lambda x: 0 if x['step'] == 'php' else 1)
    completed = len(results) == 2 and all(r['exit_code'] == 0 for r in results)
    summary = {'schema_version': 1, 'domain': args.domain, 'run_id': run_id,
               'operation_id': operation_id, 'parallel': True, 'shared_session': True,
               'completed': completed, 'steps': results,
               'mode': 'apply' if args.apply else 'plan'}
    if args.json:
        print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    else:
        print('Shared-Session-Batch:', 'abgeschlossen' if completed else 'fehlgeschlagen',
              '| Schritte:', sum(r['exit_code'] == 0 for r in results), '/ 2')
        for r in results:
            print(f"  {r['step']}: Exit-Code {r['exit_code']} ({r['duration_seconds']} s)")
    log_event(logfile, run_id, 'completed' if completed else 'failed',
              section='shared_parallel_batch', domain=args.domain,
              operation_id=operation_id, completed=completed)
    return 0 if completed else 3
