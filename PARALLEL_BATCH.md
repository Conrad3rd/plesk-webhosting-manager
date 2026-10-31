# Optionaler Parallel-Batch (experimentell)

Der eigenstaendige Plesk-Manager verwaltet `batch --parallel` selbst. Der normale
`batch`-Befehl bleibt standardmaessig sequenziell mit einer wiederverwendeten
Anmeldung. Der Parallelmodus startet zwei vollstaendig getrennte CLI-Prozesse
mit eigenen Plesk-Anmeldungen, Cookies und CSRF-Tokens. Beide verwenden dieselbe
operation_id in den Logs, haben aber unterschiedliche run_id-Werte.

Zuerst nur lesen:

    python3 plesk-webhosting.py --account hosting-1 \
      --domain test.example.org batch --plan --parallel \
      --php-version 8.5 --basedir WEBSPACEROOT --https-redirect

Nur fuer eine ausdruecklich freigegebene Testdomain, nach Kontrolle des Plans:

    python3 plesk-webhosting.py --account hosting-1 \
      --domain test.example.org batch --apply --yes --parallel \
      --php-version 8.5 --basedir WEBSPACEROOT --https-redirect

Die zwei Worker starten vor der Wartephase. Ein Fehler bricht den anderen
bereits gestarteten Worker NICHT ab. Es gibt keine automatischen POST-Retries.
Der Gesamtstatus ist nur bei beiden erfolgreichen Worker-Exitcodes erfolgreich.
Vor Wiederholungen nach unklarem Status zuerst `inspect --json` ausfuehren.

`--ssl-install` ist nur zusammen mit PHP parallel erlaubt, NICHT gleichzeitig
mit HTTPS-Umleitung, weil beide die SSL-It!-Einstellungen derselben Domain
bearbeiten. Gleichzeitige Schreibvorgaenge innerhalb einer geteilten Plesk-
Sitzung sind ausdruecklich NICHT implementiert.

`--json` liefert ausschliesslich die maschinenlesbare Zusammenfassung auf
stdout. Worker-Ausgaben stehen im zentralen JSONL-Protokoll und koennen bei
Fehlern ueber die jeweiligen run_id-Werte ausgewertet werden.

Der Parallelmodus ist ein experimenteller Performance-Test. Der produktive
Fallback ist der unveraenderte sequenzielle `batch`-Befehl.
