"""Schreibfreigaben pro verifiziertem Schritt bei einer Plesk-Anmeldung."""
import unittest
from plesk_webhosting.core import PleskSession, PleskError

PATH = '/modules/sslit/index.php/https-redirect/enable/'
BODY = b'{"id":"123"}'

class SessionLifecycleTests(unittest.TestCase):
    def session(self):
        client = PleskSession('example.test', 'user', 'password')
        client.csrf = 'csrf-token-placeholder-123456'
        return client

    def consumed(self, client):
        client.authorize_write_once(PATH, BODY, 'application/json')
        # Simuliert die Schutzfreigabe unmittelbar vor einer Netzwerkanfrage.
        client._write_grant = None
        client._write_consumed = True

    def test_second_write_only_after_positive_verification(self):
        c = self.session()
        self.consumed(c)
        with self.assertRaises(PleskError):
            c.authorize_write_once(PATH, BODY, 'application/json')
        c.finish_verified_write(verified=True)
        self.assertEqual(c._verified_writes, 1)
        c.authorize_write_once(PATH, BODY, 'application/json')

    def test_uncertain_write_permanently_locks_session(self):
        c = self.session()
        self.consumed(c)
        with self.assertRaises(PleskError):
            c.finish_verified_write(verified=False)
        with self.assertRaises(PleskError):
            c.authorize_write_once(PATH, BODY, 'application/json')

    def test_cannot_mark_unissued_write_verified(self):
        c = self.session()
        with self.assertRaises(PleskError):
            c.finish_verified_write(verified=True)

    def test_retire_prevents_new_writes(self):
        c = self.session()
        c.retire_writes()
        with self.assertRaises(PleskError):
            c.authorize_write_once(PATH, BODY, 'application/json')

    def test_boolean_required(self):
        c = self.session()
        self.consumed(c)
        with self.assertRaises(PleskError):
            c.finish_verified_write(verified=1)

if __name__ == '__main__':
    unittest.main()
