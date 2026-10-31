import json
import unittest
from argparse import Namespace
from unittest.mock import patch
from tempfile import TemporaryDirectory
from pathlib import Path
from io import StringIO
from contextlib import redirect_stdout

from plesk_webhosting import inspect
from plesk_webhosting.cli import build_parser


class InspectTests(unittest.TestCase):
    def test_cli_read_only(self):
        args = build_parser().parse_args(['--domain', 'example.test', 'inspect', '--json'])
        self.assertEqual(args.command, 'inspect')
        self.assertTrue(args.json)
        self.assertFalse(hasattr(args, 'apply'))

    def test_collect_one_session_no_writes(self):
        class Client:
            def __init__(self):
                self.read_paths = []
            def request(self, path, *, body=None):
                self.read_paths.append(path)
                assert body is None
                return 200, '<html/>', 'text/html'
        client = Client()
        with patch.object(inspect, 'domain_id_from_view', return_value=45), \
             patch.object(inspect.php, 'settings_data', return_value={
                 'php_enabled': True, 'version': '8.4', 'basedir': '{WEBSPACEROOT}'
             }), patch.object(inspect.ssl, 'ssl_data', return_value={'test': True}), \
             patch.object(inspect.ssl, 'ssl_status', return_value={
                 'certificate_assigned': True, 'https_redirect': False,
                 'pending_order': False, 'redirect_manageable': True
             }):
            result = inspect.collect(client, 'view', 'example.test')
        self.assertEqual(client.read_paths, ['/smb/web/php-settings/id/45'])
        self.assertEqual(result['php']['version'], '8.4')
        self.assertTrue(result['ssl']['certificate_assigned'])

    def test_run_json_and_logging(self):
        with TemporaryDirectory() as folder:
            logfile = Path(folder) / 'events.jsonl'
            with patch.object(inspect, 'collect', return_value={
                'schema_version': 1, 'domain': 'example.test', 'domain_id': 45,
                'php': {'enabled': True, 'version': '8.4', 'open_basedir': 'WEBSPACEROOT'},
                'ssl': {'certificate_assigned': False, 'https_redirect': False,
                        'pending_order': False, 'redirect_manageable': True}
            }), redirect_stdout(StringIO()) as out:
                code = inspect.run(Namespace(domain='example.test', domain_id=None, json=True),
                                   object(), '', 'test', 'host.example.test', logfile)
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out.getvalue())['account'], 'test')
            events = [json.loads(line) for line in logfile.read_text().splitlines()]
            self.assertEqual([e['event'] for e in events], ['started', 'completed'])
            self.assertEqual(events[0]['run_id'], events[1]['run_id'])


if __name__ == '__main__':
    unittest.main()
