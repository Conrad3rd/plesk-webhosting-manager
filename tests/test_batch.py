import unittest
from argparse import Namespace
from unittest.mock import patch, MagicMock
from plesk_webhosting import batch, cli, ssl


class BatchTests(unittest.TestCase):
    def test_real_cli_batch_plan_reaches_dispatch_without_unboundlocalerror(self):
        fake_session = MagicMock()
        fake_session.login.return_value = 'domain-view'
        with patch.object(cli.accounts, 'find_profile', return_value=('test', {'host':'example.org', 'user':'tester'})), \
             patch.object(cli.accounts, 'get_password', return_value='example-secret'), \
             patch.object(cli, 'PleskSession', return_value=fake_session), \
             patch.object(cli.batch, 'run', return_value=0) as runner:
            code = cli.run(['--account','test','--domain','example.org','batch','--plan','--php-version','8.5'])
        self.assertEqual(code, 0)
        runner.assert_called_once()

    def test_plan_does_not_demand_target_state_or_submit_writes(self):
        client = type('Session', (), {'_write_consumed': False, 'retire_writes': lambda self: None})()
        args = Namespace(domain='example.org', domain_id=None, php_version='8.5', basedir='WEBSPACEROOT',
                         https_redirect=True, ssl_install=True, plan=True, apply=False, yes=False,
                         verify_attempts=2, verify_interval=1, json=False)
        with patch.object(batch, 'domain_id_from_view', return_value=123), \
             patch.object(batch.php, 'run', return_value=0), \
             patch.object(batch.ssl, 'run', return_value=0), \
             patch.object(batch.inspect, 'collect') as collect, \
             patch.object(batch, 'log_event'):
            code = batch.run(args, client, '', 'test', 'host', 'log')
        self.assertEqual(code, 0)
        collect.assert_not_called()

    def test_parser_requires_explicit_options(self):
        a = cli.build_parser().parse_args(['--domain', 'example.org', 'batch', '--plan', '--https-redirect'])
        self.assertTrue(a.plan)
        self.assertFalse(a.ssl_install)

    def test_step_order(self):
        args = Namespace(php_version='8.5', https_redirect=True, ssl_install=True)
        self.assertEqual(batch.choose_steps(args), [('php', None), ('https_redirect', 'redirect'), ('ssl_install', 'install')])

    def test_https_without_certificate_is_plannable(self):
        data = object()
        with patch.object(ssl, 'ssl_status', return_value={'certificate_assigned': False,
             'https_redirect': False, 'redirect_manageable': True, 'webmail_redirect_supported': False}):
            proposal, _ = ssl.proposal('redirect', data, 123)
        self.assertIsNotNone(proposal)

    def test_failed_step_stops_before_next_write(self):
        client = type('Session', (), {'_write_consumed': True, 'retire_writes': lambda self: None})()
        args = Namespace(domain='example.org', domain_id=None, php_version='8.5', basedir='WEBSPACEROOT',
                         https_redirect=True, ssl_install=False, plan=False, apply=True, yes=True,
                         verify_attempts=2, verify_interval=1, json=False)
        with patch.object(batch, 'domain_id_from_view', return_value=123), \
             patch.object(batch.php, 'run', return_value=3), \
             patch.object(batch.ssl, 'run') as ssl_run, \
             patch.object(batch, 'log_event'):
            code = batch.run(args, client, '', 'test', 'host', 'log')
        self.assertEqual(code, 3)
        ssl_run.assert_not_called()
