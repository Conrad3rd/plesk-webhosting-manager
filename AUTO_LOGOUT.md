# Automatischer Plesk-Logout

Der bereits mit `logout-check` live bestaetigte Endpunkt `/logout.php` wird
bei regulaeren CLI-Aufrufen vor dem lokalen Aufraeumen mit demselben
Python-HTTP-Client aufgerufen. Anschliessend wird ein Zugriff auf
`/smb/web/view` erwartet, der zur Login-Seite fuehrt.

Die zentrale Abschlussbehandlung registriert nur von der CLI angelegte
PleskSession-Instanzen. `batch --parallel` erzeugt getrennte Prozesse,
die jeweils selbst abmelden. `batch --parallel --shared-session` registriert
nur die urspruengliche Anmeldung; die Worker beenden zuerst ihre eigenen
HTTP-Clients und dann wird die gemeinsame serverseitige Sitzung abgemeldet.

Bei Fehlern wird nach Moeglichkeit ebenfalls abgemeldet. Ein fehlgeschlagener
Logout meldet eine Warnung und `session_logout` im JSONL-Protokoll, aendert
aber keinen bereits abgeschlossenen fachlichen Exit-Code. Bei einem noch
laufenden Schreib-POST wird kein Logout erzwungen.

Die bestehende Funktion `logout-check` bleibt erhalten. Sie verhindert durch
Markierung eines bereits verifizierten Logouts eine zweite Abmeldeanfrage.

Testbefehle:

    python3 -m unittest discover -s tests -v
    python3 plesk-webhosting.py self-test
    python3 plesk-webhosting.py --account hosting-1 --domain example.test inspect --json

Der letzte Befehl ist nur ein Platzhalter fuer eine dem Konto zugeordnete Domain.
