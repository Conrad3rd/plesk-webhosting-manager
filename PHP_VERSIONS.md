# PHP-Versionen aus Plesk abfragen

Der eigenstaendige CLI-Befehl `php-versions` liest die Auswahl aus dem PHP-Einstellungsformular der angegebenen Domain. Er fuehrt keine Schreibanfragen aus.

```bash
python3 plesk-webhosting.py --account hosting-1 --domain test.example.org php-versions --json
```

Das JSON enthaelt `default_version` (8.5), `current_version` und die dynamisch verfuegbaren Versionen mit `available`, `handler`, `selected`, `outdated` und `outdated_status`.

Wichtig: Nur ausdruecklich von Plesk im Handler-Datensatz gemeldete Kennzeichnungen `outdated`, `obsolete`, `deprecated` oder entsprechende Labels werden als ueberholt erfasst. Ohne ausdrueckliches Signal ist `outdated: null` und `outdated_status: unknown`, nicht `false`. Es wird bewusst keine Altersregel anhand einer festen Versionsliste erraten. Wenn die Kennzeichnung ausschliesslich ueber andere UI-Metadaten erfolgt, muss der Parser nach einem anonymisierten Seitenstrukturvergleich erweitert werden.

Die Verfuegbarkeit der vom aktuellen netcup-Hosting verwendeten FastCGI-Handler wird getrennt vom Altersstatus ermittelt. Der project_manager kann spaeter die Liste im Dropdown zeigen, `default_version` vorselektieren und unbekannte Alterskennzeichnungen neutral behandeln.
