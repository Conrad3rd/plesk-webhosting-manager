# Shared-Session Logout: Abschlussreihenfolge korrigiert

Im experimentellen Batch `--parallel --shared-session` wurde der Elternclient
vor der zentralen CLI-Abschlussbehandlung durch `client.close()` lokal
beendet. Dadurch erschien `session_logout: not_authenticated` und der
serverseitige Logout wurde nicht ausgefuehrt.

Die CLI entfernt dieses vorzeitige `close()`. Die beiden HTTP-Worker beenden
zunaechst ihre eigene Arbeit und schliessen ihre lokalen Clients. Anschliessend
fuehrt der registrierte Elternclient genau einmal den zentralen Logout aus.
Dies gilt auch bei einem Fehler im Orchestrator (best effort).

Test:

    python3 -m unittest discover -s tests -v
    python3 plesk-webhosting.py self-test
    python3 plesk-webhosting.py --account hosting-1 --domain test.example.org batch --plan --parallel --shared-session --php-version 8.5 --basedir WEBSPACEROOT --https-redirect

Erwartet: ein `session_logout` mit `status: confirmed` und
`verification_path: /login_up.php` nach dem Batch.
