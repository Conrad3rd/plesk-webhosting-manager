PLESK WEBHOSTING MANAGER
=======================

Eigenstaendiges Kommandozeilenprogramm zur Verwaltung von Webhosting-Konten
mit Plesk unter Linux. Das Programm benoetigt keinen Browser und keine
zusaetzlichen Python-Pakete. Es nutzt Python 3.10+ und den Linux-Schluesselbund.

FUNKTIONEN
----------
* Mehrere Plesk-Konten als Profile verwalten.
* Auswaehlbare Hauptdomains eines Plesk-Kontos lesend als JSON abrufen.
* Subdomains und Dokumentenstaemme auslesen.
* Neue Subdomains mit einem angegebenen Dokumentenstamm erstellen.
* Ziel-Subdomain, Hauptdomain und Dokumentenstamm nach der Erstellung pruefen.
* Subdomains nach eindeutiger Bestaetigung kontrolliert loeschen.
* PHP-Version und open_basedir kontrollieren und aendern.
* SSL-Zertifikate zuweisen lassen und HTTPS-Umleitungen verwalten.

WICHTIG ZUR SUBDOMAIN-LOESCHUNG
-------------------------------
Die Loeschfunktion verwendet einen per Plesk-Browseraufzeichnung ermittelten,
privaten HTTP-Endpunkt: POST /smb/web/domain-delete-async/ mit JSON
{"ids":["domain:<ermittelte-id>"]}. Die Aufnahme wurde absichtlich vor dem
Versand abgefangen. Der HTTP-Loeschvorgang ist daher noch NICHT live erprobt.

Vor jedem Loeschversuch mit --apply zuerst --check und --plan verwenden.
--apply erfordert den exakten FQDN, die aktuelle Plesk-Domain-ID, den
vollstaendigen Dokumentenstamm und --yes. Der Manager kontrolliert vor dem
Schreib-POST den aktuellen Zustand erneut und sendet maximal einen POST.
Danach wird die Abwesenheit der Subdomain sowie der Verbleib aller anderen
Domain-IDs in einer vollstaendigen Plesk-Domainliste geprueft.

ACHTUNG: Eine Subdomain-Loeschung kann auch Webdateien, Verzeichnisse und
andere zugeordnete Einstellungen entfernen. Die Liste allein ist kein Beweis
fuer den Dateisystemzustand. Unbedingt zuvor eine Datensicherung erstellen!
Der erste Live-Test sollte nur eine entbehrliche Test-Subdomain betreffen.
Bei Netzwerk-/Antwortfehlern niemals blind erneut senden: zuerst --check.

SICHERHEIT
----------
* --check liest nur; --plan bereitet Aenderungen vor und sendet keinen POST.
* Schreibende Aktionen benoetigen --apply und die vorgeschriebenen
  Bestaetigungen.
* Erstellungs-, Loesch- und Speichervorgaenge autorisieren hoechstens einen Schreib-POST.
* Bei ungeklaertem Ergebnis nicht blind wiederholen, sondern --check nutzen.
* Die Plesk-Formulare und Schreibberechtigungen werden fuer das jeweilige Konto
  aktuell eingelesen und validiert.
* Plesk-interne Webendpunkte sind keine dauerhaft garantierte oeffentliche API.
  Hostingpakete und Plesk-Versionen koennen sich unterscheiden.
* Zugangsdaten bleiben im Linux-Schluesselbund. Keine Passwoerter, Session-Cookies
  oder CSRF-Tokens werden in Programmdateien oder Logs abgelegt.
* Der Host wird pro Konto gewaehlt; HTTPS-Zertifikate werden geprueft.

DATEISTRUKTUR
-------------
plesk-webhosting.py                Einziger Programmeinstieg
plesk_webhosting/cli.py           Kommandozeile
plesk_webhosting/core.py          HTTPS, Plesk-Anmeldung, CSRF, Logs
plesk_webhosting/accounts.py      Kontenprofile und Schluesselbund
plesk_webhosting/subdomain.py     Subdomains und Dokumentenstamm
plesk_webhosting/domains.py       Hauptdomain-Abfrage (nur GET)
plesk_webhosting/php.py           PHP-Verwaltung
plesk_webhosting/ssl.py           SSL-/HTTPS-Verwaltung
tests/                            Offline-Unittests
logs/events.jsonl                 Laufzeitprotokoll, automatisch angelegt
README.txt                        Diese Anleitung

VORAUSSETZUNGEN UND START
------------------------
Linux, Python >= 3.10 und `secret-tool` aus dem Paket libsecret-tools.

    python3 --version
    command -v secret-tool || sudo apt install libsecret-tools

Alle Dateien muessen ihre Verzeichnisstruktur beibehalten. Eine Installation
fremder Python-Pakete ist nicht erforderlich.

    cd /pfad/zum/plesk-webhosting-manager
    python3 plesk-webhosting.py --help
    python3 plesk-webhosting.py self-test
    python3 -m unittest discover -s tests -v

KONTEN UND ZUGANGSDATEN
----------------------
Profile werden unabhaengig und zentral durch dieses Programm verwaltet.
Die Profildatei enthaelt keine Passwoerter. Jedes Profil ist eindeutig durch
Profilname, Plesk-Host und Anmeldenamen gekennzeichnet.

Erstes Konto anlegen (Passwort verdeckt eingeben):

    python3 plesk-webhosting.py account add \
      --name hosting-1 \
      --host PLESK-HOST.webhosting.systems \
      --user PLESK-BENUTZER

Zweites Konto anlegen:

    python3 plesk-webhosting.py account add \
      --name hosting-2 \
      --host ZWEITER-PLESK-HOST.webhosting.systems \
      --user ZWEITER-BENUTZER

Konten anzeigen oder entfernen:

    python3 plesk-webhosting.py account list
    python3 plesk-webhosting.py account remove --name hosting-2 --yes

Konfiguration: ~/.config/plesk-webhosting/accounts.json (Dateimodus 0600)
Passwoerter:   Linux Secret Service / Schluesselbund

Wenn genau ein Konto eingerichtet ist, darf --account entfallen.
--account und --domain sind globale Optionen und stehen VOR dem Unterbefehl.

DOMAINLISTE FUER DEN PROJEKTMANAGER
---------------------------------
Auswaehlbare Hauptdomains eines Kontoprofils anzeigen (ohne --domain):

    python3 ~/Projects/plesk-webhosting-manager/plesk-webhosting.py \
      --account hosting-1 domains list

JSON-Ausgabe fuer Desktop-Tools/project_manager:

    python3 ~/Projects/plesk-webhosting-manager/plesk-webhosting.py \
      --account hosting-1 domains list --json

Beispiel (Domainnamen und IDs sind nur Beispielwerte):

    {"account":"hosting-1","domains":[{"id":100,"name":"example.org"}],
     "host":"host.webhosting.systems","schema_version":1,
     "scope":"subdomain_parent_domains","source":"plesk_subdomain_form"}

Das Programm meldet sich mit dem bestehenden Kontoprofil bei Plesk an und
liest per GET /smb/web/add-subdomain die auswaehlbaren Hauptdomains
(aus dem Subdomain-Auswahlfeld). Es werden keine Domains lokal gepflegt,
keine Passwoerter ausgegeben und keine Plesk-Konfiguration geaendert.

WICHTIG: Die Liste enthaelt die in diesem Formular angebotenen Hauptdomains,
nicht saemtliche vorhandenen Subdomains, Aliase oder zwingend jede im gesamten
Konto vorhandene Domain. Plesk ist fuer die Auswahl massgeblich. Wenn sich das
Formularformat aendert, bricht das Programm ab. JSON steht allein auf stdout;
Fehler erscheinen auf stderr mit Exitcode 1. Die Reihenfolge ist alphabetisch.
Bei mehreren Konten muss --account angegeben werden.

SUBDOMAIN-VERWALTUNG
-------------------
Als --domain wird bei Subdomains IMMER der vollstaendige Zielname uebergeben.
--parent-domain bezeichnet die unmittelbar uebergeordnete Hauptdomain.
--document-root ist ein RELATIVER Pfad innerhalb des Webspaces, niemals /var/www/...

Subdomain samt Dokumentenstamm pruefen:

    python3 plesk-webhosting.py \
      --account hosting-1 --domain test.example.org \
      subdomain --check --parent-domain example.org

Neue Subdomain nur simulieren:

    python3 plesk-webhosting.py \
      --account hosting-1 --domain test.example.org \
      subdomain --plan --operation create --parent-domain example.org \
      --document-root test.example.org/public

Neue Subdomain wirklich erstellen:

    python3 plesk-webhosting.py \
      --account hosting-1 --domain test.example.org \
      subdomain --apply --operation create --parent-domain example.org \
      --document-root test.example.org/public \
      --confirm-create test.example.org --yes

Nach dem Schreiben liest das Programm die Plesk-Domainliste erneut.
Erfolg wird nur gemeldet, wenn die Subdomain als Subdomain unter der korrekten
Hauptdomain erscheint UND webrootDir exakt dem vorgegebenen Dokumentenstamm
entspricht. Bei Abweichung nicht sofort erneut erstellen.

Die automatische Erstellung verlangt derzeit eine vollstaendige, ungefilterte
Plesk-Domainliste zur sicheren Abwesenheitskontrolle. Wird nur eine paginierte
Liste geliefert, bricht das Programm ab, statt die Domain doppelt anzulegen.

Subdomain-Loeschung vorpruefen (KEINE Loeschung):

    python3 plesk-webhosting.py \
      --account hosting-1 --domain test.example.org \
      subdomain --plan --operation delete --parent-domain example.org

Wenn die Simulation den erwarteten Domainnamen, Dokumentenstamm und die
Plesk-Domain-ID ausgibt, kannst du nach einer Datensicherung die Loeschung
explizit ausfuehren. Hierbei ist 120 eine BEISPIEL-ID; sie muss durch die
tatsaechlich angezeigte ID aus --check ersetzt werden.

    python3 plesk-webhosting.py \
      --account hosting-1 --domain test.example.org \
      subdomain --apply --operation delete --parent-domain example.org \
      --document-root test.example.org/public \
      --confirm-delete test.example.org --confirm-delete-id 120 --yes

Wenn die Domain nicht in einer vollstaendigen, ungefilterten Plesk-Liste
verifiziert werden kann, wird das Loeschen abgebrochen. Der Manager prueft,
dass die Hauptdomain und die anderen vorher vorhandenen Domains weiter in
Plesk aufgelistet sind. Keine zweite Loeschanfrage bei unklarem Ergebnis.

PHP-EINSTELLUNGEN
----------------
Status anzeigen:

    python3 plesk-webhosting.py \
      --account hosting-1 --domain test.example.org php --check --show-settings

PHP 8.5 und WEBSPACEROOT simulieren:

    python3 plesk-webhosting.py \
      --account hosting-1 --domain test.example.org php \
      --plan --php-version 8.5 --basedir WEBSPACEROOT

PHP-Version und open_basedir speichern:

    python3 plesk-webhosting.py \
      --account hosting-1 --domain test.example.org php \
      --apply --php-version 8.5 --basedir WEBSPACEROOT --yes

Weitere Option: --basedir DOCROOT. Nur von Plesk angebotene PHP-Handler und
open_basedir-Einstellungen werden akzeptiert. Die PHP-Unterstuetzung muss
aktiv bleiben und wird nach dem Speichern geprueft. Leistungseinstellungen
werden nicht unberechtigt veraendert. Die OPcache-Darstellung kann je nach
PHP-Version unterschiedlich sein.

SSL UND HTTPS
-------------
SSL-Status anzeigen:

    python3 plesk-webhosting.py \
      --account hosting-1 --domain test.example.org ssl --check

Kostenloses Let's-Encrypt-Zertifikat fuer Domain und www simulieren:

    python3 plesk-webhosting.py \
      --account hosting-1 --domain example.org ssl --plan --operation install

Zertifikat ausstellen (nur bei benoetigtem, neuem Zertifikat):

    python3 plesk-webhosting.py \
      --account hosting-1 --domain example.org ssl --apply --operation install --yes

HTTPS-Umleitung deaktivieren bzw. aktivieren:

    python3 plesk-webhosting.py \
      --account hosting-1 --domain example.org ssl \
      --apply --operation redirect-disable --yes

    python3 plesk-webhosting.py \
      --account hosting-1 --domain example.org ssl \
      --apply --operation redirect --yes

ZertifikatZUWEISUNG aufheben (kein Widerruf beim Zertifikatsanbieter):

    python3 plesk-webhosting.py \
      --account hosting-1 --domain example.org ssl \
      --apply --operation unassign --confirm-unassign example.org --yes

ACHTUNG: Neues Let's-Encrypt-Zertifikat nur bei Bedarf anfordern. Wiederholte
Testausstellungen koennen zu Rate-Limits fuehren.

PROTOKOLLE UND FEHLER
---------------------
Standard: <INSTALLATIONSORDNER>/logs/events.jsonl (Dateimodus 0600)
Der Pfad haengt nicht vom aktuellen Terminalverzeichnis ab.

    tail -n 30 logs/events.jsonl | jq .

Abweichenden Logpfad pro Aufruf setzen (globale Option vor dem Unterbefehl):

    python3 plesk-webhosting.py \
      --account hosting-1 --domain example.org \
      --log /tmp/plesk-test.jsonl ssl --check

Ein fehlgeschlagener oder ungepruefter Schreibvorgang darf NICHT blind
wiederholt werden. Zuerst den aktuellen Plesk-Zustand mit --check abfragen.

Hilfe fuer Unterbefehle:

    python3 plesk-webhosting.py domains list --help
    python3 plesk-webhosting.py subdomain --help
    python3 plesk-webhosting.py php --help
    python3 plesk-webhosting.py ssl --help
    python3 plesk-webhosting.py account --help

EXITCODES
---------
0 = erfolgreich oder keine Aenderung notwendig
1 = Fehler, Abbruch oder nicht eindeutig bestaetigtes Ergebnis
130 = vom Benutzer unterbrochen

HINWEIS
-------
Die hier eingebauten privaten Plesk-Webendpunkte koennen sich nach Updates
veraendern. Schreibfunktionen muessen in jeder neuen Hostingumgebung zunaechst
ueber --check und --plan verifiziert werden.

LIZENZ
------
Dieses Projekt steht unter der MIT-Lizenz. Die vollstaendigen Bedingungen
stehen in LICENSE. Die Lizenz betrifft den hier veroeffentlichten Code,
nicht die Software Plesk oder Dienste des jeweiligen Hostinganbieters.

OEFFENTLICHE VEROEFFENTLICHUNG
-----------------------------
Den Quellcode fuer ein ZIP ausschliesslich aus versionierten Dateien exportieren:

    ./scripts/build-public-zip.sh

Das Verfahren ignoriert .git, lokale Logs und Python-Caches. Hinweise zum
erstmaligen sicheren GitHub-Push stehen in PUBLIC_RELEASE.md.
