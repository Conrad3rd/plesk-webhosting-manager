# Einmaliger serverseitiger Logout-Regressionstest

Der neue CLI-Befehl ist eine **ausdruecklich gestartete Live-Pruefung**, kein
automatischer Logout fuer andere Befehle. Er verwendet eine echte authentifizierte
PleskSession und testet nach `GET /logout.php` mit demselben HTTP-Client die
Zugriffskontrolle auf `/smb/web/view`.

```bash
cd ~/Projects/plesk-webhosting-manager/repo
python3 plesk-webhosting.py --account hosting-1 logout-check
```

Exit-Code 0: Umleitung zum Login nach Logout bestaetigt. Exit-Code 2:
Sitzungsende nicht bestaetigt. Exit-Code 1: Fehler. Es gibt keinen
automatischen Wiederholungsversuch und keine Aenderung an Hosting-Einstellungen.
Lokale Cookies werden danach in allen Faellen geloescht. Die Pruefung beendet
eine eigens fuer den Test angemeldete Plesk-Sitzung.
