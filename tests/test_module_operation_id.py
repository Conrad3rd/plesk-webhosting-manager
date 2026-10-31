"""Prueft operation_id auf echten Untermodul-Logereignissen aus Threads."""
import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

from plesk_webhosting import shared_parallel
from plesk_webhosting.core import correlation_context, log_event


class ModuleOperationIdTests(unittest.TestCase):
    def test_shared_workers_inherit_operation_id_in_php_and_ssl_events(self):
        class Worker:
            _write_consumed = False
            def close(self): pass
            def retire_writes(self): pass
        class Client:
            def fork_authenticated_worker(self): return Worker()

        args = Namespace(domain='example.org', domain_id=None, php_version='8.5',
                         https_redirect=True, ssl_install=False, basedir='WEBSPACEROOT',
                         plan=True, apply=False, yes=False, json=True,
                         operation_id='project_corr_123', _cli_run_id='abc123def456',
                         verify_attempts=1, verify_interval=0)
        with tempfile.TemporaryDirectory() as folder:
            logfile = Path(folder) / 'events.jsonl'
            def fake_php(options, worker, domain_id, path, run_id):
                log_event(path, run_id, 'status_ok', section='php')
                return 0
            def fake_ssl(options, worker, domain_id, path, run_id):
                log_event(path, run_id, 'status_ok', section='ssl')
                return 0
            with (patch.object(shared_parallel, 'domain_id_from_view', return_value=123),
                  patch.object(shared_parallel.php, 'run', side_effect=fake_php),
                  patch.object(shared_parallel.ssl, 'run', side_effect=fake_ssl),
                  patch('builtins.print')):
                with correlation_context('project_corr_123'):
                    result = shared_parallel.run(args, Client(), None, 'account', 'example.org', logfile)
            self.assertEqual(result, 0)
            events = [json.loads(line) for line in logfile.read_text().splitlines()]
            self.assertEqual({e['section'] for e in events if e['event'] == 'status_ok'}, {'php', 'ssl'})
            self.assertTrue(all(e.get('operation_id') == 'project_corr_123' for e in events))
            self.assertEqual({e['run_id'] for e in events}, {'abc123def456'})

    def test_context_isolation_between_workers_and_sequential_calls(self):
        from concurrent.futures import ThreadPoolExecutor
        def emit(label):
            with correlation_context(label):
                with tempfile.TemporaryDirectory() as folder:
                    path = Path(folder) / 'events.jsonl'
                    log_event(path, 'sample', 'status_ok', section='php')
                    return json.loads(path.read_text())['operation_id']
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(list(pool.map(emit, ['one', 'two'])), ['one', 'two'])


if __name__ == '__main__':
    unittest.main()
