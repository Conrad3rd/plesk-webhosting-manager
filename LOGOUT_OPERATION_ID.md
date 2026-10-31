# operation_id im automatischen Plesk-Logout

Bei `batch --parallel` (mit und ohne `--shared-session`) wird eine fehlende
`operation_id` ab jetzt am Beginn des CLI-Aufrufs erzeugt, bevor die fachlichen
Ereignisse protokolliert und die Sitzungen registriert werden.

Der Korrelationskontext bleibt beim abschliessenden `session_logout` aktiv.
Damit besitzen Batch-Ereignisse und `session_logout` dieselbe `operation_id`
und `run_id`. Eine explizit gesetzte `--operation-id` wird beibehalten.
Nicht-parallele Befehle ohne `--operation-id` behalten weiterhin das bisherige
Verhalten und erhalten keine automatisch erzeugte Vorgangskennung.

Bei `batch --parallel` ohne gemeinsame Sitzung laufen Kindprozesse weiterhin
unter derselben `operation_id`, aber mit eigenen `run_id`-Werten. Jeder
Kindprozess protokolliert den Logout seiner eigenen Sitzung.

## Tests

```bash
python3 -m unittest discover -s tests -q
python3 plesk-webhosting.py self-test
```

## Live-Plan-Test

```bash
python3 plesk-webhosting.py --account hosting-1 \
  --domain test.example.org \
  batch --plan --parallel --shared-session \
  --php-version 8.5 --basedir WEBSPACEROOT --https-redirect
jq -c 'select(.section == "shared_parallel_batch" or .event == "session_logout") | {run_id,operation_id,section,event,status}' logs/events.jsonl | tail -8
```

Der Plan-Modus sendet keine Konfigurations-POSTs; der Logout beendet lediglich
die zuvor erzeugte Anmeldung. Dies ersetzt keinen Live-Test.
