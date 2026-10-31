# Plesk Webhosting Manager

Kommandozeilenprogramm für die Verwaltung von Plesk-Webhosting über HTTPS unter Linux.
Es bietet Kontoprofile im Linux-Schlüsselbund, Domain- und PHP-Statusabfragen,
Subdomain-Verwaltung, PHP-Konfiguration sowie SSL- und HTTPS-Verwaltung.

**Status:** Eigenständiges, nicht offizielles Projekt. Es nutzt teilweise interne
Plesk-Weboberflächen-Endpunkte, die sich zwischen Plesk-Versionen und Anbietern
unterscheiden können. Die bisherige Entwicklung wurde insbesondere mit
netcup-Webhosting geprüft. Es gibt keine Garantie für alle Plesk-Installationen.

## Voraussetzungen

- Linux mit Python 3.10 oder neuer
- `secret-tool` (beispielsweise Paket `libsecret-tools` unter Ubuntu/Debian)
- Ein nutzbarer und entsperrter Linux-Secret-Service-Schlüsselbund
- Zugang zu einem unterstützten Plesk-Webhosting-Konto

Es werden keine zusätzlichen Python-Pakete benötigt.

## Schnellstart

```bash
git clone https://github.com/Conrad3rd/plesk-webhosting-manager.git
cd plesk-webhosting-manager
python3 plesk-webhosting.py --help
python3 plesk-webhosting.py self-test
python3 -m unittest discover -s tests -q
```

Ein erstes Konto einrichten:

```bash
python3 plesk-webhosting.py account add \
  --name hosting-1 \
  --host panel.example.org \
  --user PLESK-BENUTZER
```

Der Host und Benutzername müssen durch die eigenen Plesk-Zugangsdaten ersetzt
werden. Das Passwort wird verdeckt abgefragt und im Linux-Schlüsselbund
abgelegt, nicht im Repository gespeichert.

Nur lesend überprüfen:

```bash
python3 plesk-webhosting.py --account hosting-1 --domain example.org inspect --json
```

Alle Beispiele und die weiteren Befehle sind in **[README.txt](README.txt)** beschrieben.

## Sicherheit und Einschränkungen

- Schreibende Aktionen benötigen eine ausdrückliche Freigabe. Vorher `--check`
  oder `--plan` ausführen.
- Die Subdomain-Löschfunktion wurde noch **nicht live durch einen vollständigen
  Löschvorgang bestätigt**. Sie ist besonders risikoreich und sollte erst an
  einer entbehrlichen Test-Subdomain mit Backup erprobt werden.
- Lokale Diagnosedateien in `logs/` können Hostnamen, Domainnamen und IDs enthalten.
  Sie werden durch `.gitignore` ausgeschlossen und dürfen nicht veröffentlicht werden.
- Dieses Projekt gehört nicht zum offiziellen Plesk-Produkt und ist nicht mit
  Plesk oder einem Hostinganbieter verbunden.

## Lizenz

[MIT-Lizenz](LICENSE). Für die Veröffentlichung wird die Git-Historie des
öffentlichen Repositories verwendet, nicht ein vollständiges lokales Diagnose-ZIP.
