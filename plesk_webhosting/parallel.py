"""Standalone-Orchestrierung unabhaengiger Plesk-Aktionen in getrennten Prozessen.

Keine gemeinsame HTTP-Sitzung, keine parallelen SSL-It-Schreibaktionen und keine
Wiederholung ungeklärter POSTs. Jeder Worker verifiziert seine eigene Aenderung.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from time import monotonic
from uuid import uuid4

from .core import log_event


WORKER_TIMEOUT_SECONDS = 600


def worker_commands(args, script):
    """Erzeugt nur erlaubte, voneinander unabhaengige Worker-Befehle."""
    selected = []
    if args.php_version:
        selected.append(('php', 'php', ['--php-version', args.php_version, '--basedir', args.basedir]))
    if args.https_redirect:
        selected.append(('https_redirect', 'ssl', ['--operation', 'redirect']))
    if args.ssl_install:
        selected.append(('ssl_install', 'ssl', ['--operation', 'install']))
    if len(selected) < 2:
        raise ValueError('--parallel benoetigt mindestens zwei Aktionen')
    if args.https_redirect and args.ssl_install:
        raise ValueError('HTTPS-Umleitung und SSL-Installation duerfen nicht gleichzeitig in SSL It! schreiben')
    result = []
    for label, module, extra in selected:
        command = [sys.executable, str(script), '--account', args.account,
                   '--domain', args.domain, '--log', str(args.log)]
        if args.domain_id is not None:
            command.extend(['--domain-id', str(args.domain_id)])
        command.extend([module, '--apply' if args.apply else '--plan'])
        if args.apply:
            command.append('--yes')
        command.extend(extra)
        command.extend(['--verify-attempts', str(args.verify_attempts),
                        '--verify-interval', str(args.verify_interval)])
        result.append((label, command))
    return result


def run(args, account, logfile, *, script=None, popen=None):
    """Fuehrt unabhaengige CLI-Worker aus und wartet auf ALLE Resultate."""
    script = script or (Path(__file__).resolve().parent.parent / 'plesk-webhosting.py')
    popen = popen or subprocess.Popen
    args.account = account
    args.log = Path(logfile)
    jobs = worker_commands(args, script)
    run_id = getattr(args, '_cli_run_id', None) or uuid4().hex[:12]
    operation_id = getattr(args, 'operation_id', None) or uuid4().hex[:16]
    log_event(logfile, run_id, 'started', section='parallel_batch',
              domain=args.domain, account=account, mode='apply' if args.apply else 'plan',
              workers=len(jobs), operation_id=operation_id)
    running = []
    for label, command in jobs:
        # Die gemeinsame operation_id ist nur Korrelation, keine Sitzungskopie.
        command[2:2] = ['--operation-id', operation_id]
        started = monotonic()
        try:
            process = popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True)
            running.append((label, process, started))
        except OSError as exc:
            running.append((label, None, started))
            log_event(logfile, run_id, 'worker_start_failed', section='parallel_batch',
                      step=label, error_type=type(exc).__name__)
    results = []
    # Alle Worker werden erst gestartet, bevor auf einen gewartet wird.
    for label, process, started in running:
        if process is None:
            results.append({'step': label, 'exit_code': 1, 'duration_seconds': 0,
                            'error': 'worker_start_failed'})
            continue
        try:
            stdout, stderr = process.communicate(timeout=WORKER_TIMEOUT_SECONDS)
            code = process.returncode
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            code = 124
            stderr += '\nZeitlimit erreicht; moeglicherweise wurde der POST verarbeitet. Vor einem erneuten Versuch Status pruefen.\n'
        duration = round(monotonic() - started, 3)
        if not args.json:
            print(f'=== {label}: Exit-Code {code} ({duration} s) ===')
            if stdout:
                print(stdout.rstrip())
            if stderr:
                print(stderr.rstrip(), file=sys.stderr)
        results.append({'step': label, 'exit_code': code, 'duration_seconds': duration})
        log_event(logfile, run_id, 'step_completed', section='parallel_batch', domain=args.domain,
                  step=label, exit_code=code, duration_seconds=duration,
                  operation_id=operation_id)
    completed = len(results) == len(jobs) and all(x['exit_code'] == 0 for x in results)
    summary = {'schema_version': 1, 'run_id': run_id, 'operation_id': operation_id,
               'domain': args.domain, 'mode': 'apply' if args.apply else 'plan',
               'parallel': True, 'completed': completed, 'steps': results}
    if args.json:
        print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    else:
        print('Parallel-Batch:', 'abgeschlossen' if completed else 'fehlgeschlagen',
              '| Schritte:', sum(x['exit_code'] == 0 for x in results), '/', len(jobs))
    log_event(logfile, run_id, 'completed' if completed else 'failed',
              section='parallel_batch', domain=args.domain, completed=completed,
              operation_id=operation_id)
    return 0 if completed else 3
