# Sicherer GitHub-Start mit genau einem Arbeitsrepository

Die MIT-Lizenz liegt in `LICENSE`. Der Copyright-Hinweis verwendet bewusst
nur den Projektnamen und keine persoenlichen Angaben.

## Einmalige Umstellung

Nur das bisherige Entwicklungsverzeichnis als kuenftiges Arbeitsrepository
behalten. Vor einer oeffentlichen Veroeffentlichung die alte Git-Historie
getrennt und lokal sichern. Danach im **selben** Quellcode-Verzeichnis ein
neues Git-Repository initialisieren. Weder den alten Verlauf noch eine
alte `origin`-Verknuepfung blind zu GitHub uebertragen.

Sicherheitshinweise:

* Vorher `git status` und alle getrackten Dateien kontrollieren.
* Die alte `.git`-Datenbank nur **ausserhalb** des Arbeitsverzeichnisses
  gesichert aufbewahren, bevorzugt mit Dateiberechtigungen 0700.
* Neu initialisieren und ausschliesslich Quellcode, Dokumentation, Tests,
  `.gitignore`, `LICENSE` und dieses Exportskript versionieren.
* Eine GitHub-Noreply-Adresse als Autor konfigurieren, falls keine private
  E-Mail-Adresse in oeffentlichen Commits stehen soll.
* Fuer den ersten Push ein **neues, leeres** GitHub-Repository verwenden.
  Eine vorhandene remote-Historie wird dadurch nicht nachtraeglich bereinigt.
* Ab dann genau ein Arbeitsverzeichnis verwenden und normal committen/pushen.

## Vor jedem Push

    python3 -m unittest discover -s tests -q
    python3 plesk-webhosting.py self-test
    git status --short
    git ls-files
    ./scripts/build-public-zip.sh

Das Exportskript gibt ein ZIP ausschliesslich aus getrackten Commits aus.
Dabei werden `.git`, `__pycache__`, Logs und unversionierte lokale Daten
nicht in das ZIP uebernommen. Es ersetzt keine manuelle Pruefung aller
neuen Quellen und Commits auf echte Zugangsdaten oder persoenliche Angaben.

Interne Plesk-Endpunkte koennen sich jederzeit aendern. Schreibende Aktionen
vorher mit `--check` und `--plan` pruefen. Der Quellcode verwendet bewusst
keine echten Hostingdaten in Beispielen oder Tests.
