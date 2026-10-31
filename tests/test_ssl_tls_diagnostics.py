"""SSL assignment and edge TLS verification remain separate events."""
import unittest
from unittest.mock import patch
from plesk_webhosting import ssl


class SslEdgeDiagnosticsTests(unittest.TestCase):
    def test_existing_certificate_but_edge_tls_invalid(self):
        events=[]
        sample={'anything':True}
        with patch.object(ssl,'ssl_data',return_value=sample), patch.object(ssl,'ssl_status',return_value={
            'certificate_assigned':True,'https_redirect':False,'pending_order':False}), \
            patch.object(ssl,'tls_trusted',side_effect=[True,False,True,False]), \
            patch.object(ssl,'tls_diagnostics',return_value={'reason':'certificate_verification_failed'}), \
            patch.object(ssl,'log_event',side_effect=lambda *args,**kw:events.append((args,kw))):
            result=ssl.wait_for_verification(object(),'demo.example.org',100,'install',2,0,object(),'abc')
        self.assertFalse(result)
        verifies=[kw for args,kw in events if args[2]=='verify']
        self.assertEqual(len(verifies),2)
        self.assertTrue(verifies[-1]['certificate_assigned'])
        self.assertTrue(verifies[-1]['tls_domain_ok'])
        self.assertFalse(verifies[-1]['tls_www_ok'])
        self.assertEqual(sum(args[2]=='public_tls_diagnostic' for args,kw in events),2)
        self.assertEqual(sum(args[2]=='assigned_but_public_tls_unverified' for args,kw in events),1)

if __name__=='__main__':unittest.main()
