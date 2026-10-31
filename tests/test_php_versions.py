import unittest
from unittest.mock import patch
from plesk_webhosting import php_versions, cli


class PhpVersionsTests(unittest.TestCase):
    def test_flags_and_labels_are_dynamic(self):
        self.assertTrue(php_versions._obsolete_metadata({'version': '8.1 (outdated)'}))
        self.assertTrue(php_versions._obsolete_metadata({'version': '8.2', 'isOutdated': True}))
        self.assertFalse(php_versions._obsolete_metadata({'version': '8.5', 'isOutdated': False}))
        self.assertIsNone(php_versions._obsolete_metadata({'version': '8.5'}))

    def test_cli_command(self):
        args = cli.build_parser().parse_args(['--account','demo','--domain','example.com','php-versions','--json'])
        self.assertEqual(args.command, 'php-versions')
        self.assertTrue(args.json)

    def test_collect_uses_server_choices(self):
        status = {'version':'8.4','versions':{'8.4':('a'*32,{'php84-fastcgi-nc':'FastCGI'}),
                   '8.2':('b'*32,{'php82-fastcgi-nc':'FastCGI'})},
                  'data':{'handlers':[{'id':'a'*32,'version':'8.4'},
                                      {'id':'b'*32,'version':'8.2 (outdated)'}]}}
        class Client:
            def request(self, path):
                self.path = path
                return 200, '<html/>', {}
        client = Client()
        with patch.object(php_versions, 'domain_id_from_view', return_value=12), patch.object(php_versions.php, 'settings_data', return_value=status):
            result = php_versions.collect(client, 'view', 'example.com')
        self.assertEqual([row['version'] for row in result['versions']], ['8.4','8.2'])
        self.assertEqual([row['outdated'] for row in result['versions']], [None, True])
        self.assertEqual(client.path, '/smb/web/php-settings/id/12')
