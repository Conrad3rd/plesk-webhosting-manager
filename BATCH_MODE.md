# Plesk Batch-Modus

Der Plesk-Manager bleibt ein eigenstaendiges CLI-Tool. Der Befehl `batch` verwendet
innerhalb eines Prozessaufrufs eine authentifizierte Sitzung fuer PHP, HTTPS-Redirect
und optional SSL It! (in dieser Reihenfolge). Es finden **keine parallelen
Schreibzugriffe** in derselben Sitzung statt.

Beispiel, zuerst ohne Schreibzugriffe:

```bash
cd ~/Projects/plesk-webhosting-manager/repo
python3 plesk-webhosting.py --account hosting-1 --domain example.example.org \
  batch --plan --php-version 8.5 --basedir WEBSPACEROOT --https-redirect --ssl-install
```

Nach manueller Pruefung kann `--plan` durch `--apply --yes` ersetzt werden.
Nur benoetigte Aktionen auswaehlen. Bei `--json` erscheint die strukturierte
Zusammenfassung auf stdout, Detailausgaben laufen ueber stderr.

## Sicherheitsregeln

- Jede Schreibanfrage wird durch vorhandene Modulvalidierung und exakt einmaligen
  POST-Schutz abgesichert.
- Nach einem Schreibvorgang wird der erwartete Plesk-Zielzustand erneut abgefragt;
  nur bei bestaetigtem Ergebnis darf die naechste Aktion schreiben.
- Bei ungeklärtem Ergebnis wird der Batch abgebrochen. Keine automatischen POST-Retries.
- HTTPS-Redirect ist vom Vorhandensein eines Zertifikats entkoppelt, benoetigt aber
  eine in Plesk verwaltbare Redirect-Einstellung.
- SSL-Installation benutzt weiterhin die vorhandenen DNS- und Verifikationsregeln.
  Insbesondere kann der Altcode die SSL-Aktion nach fehlgeschlagener Edge-Pruefung
  als ungeklaert melden. Der Batch setzt dann keine weiteren Aktionen fort.
- `--plan` ist nur lesend; bei unverfuegbarer Aktion meldet das Modul die Ursache.
- Sitzung nur innerhalb **eines** CLI-Aufrufs wiederverwenden. Kein Speichern von
  Session-Cookies oder Passwoertern auf Datentraegern.

Der `project_manager` wird mit diesem Patch noch nicht angepasst. Die
Parallelisierung von GitHub, Plesk und netcup erfolgt in einem separaten Schritt.
