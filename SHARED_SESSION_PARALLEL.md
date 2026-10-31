# Experiment: parallele Plesk-Aktionen mit einer Anmeldung

`batch --parallel --shared-session` unterstuetzt zunaechst nur die Kombination
`--php-version` plus `--https-redirect`. `--ssl-install` ist damit gesperrt.

Der Elternclient meldet sich genau einmal an. Die Worker kopieren dessen
Authentifizierungs-Cookies in voneinander unabhaengige CookieJars/HTTP-Opener.
Jeder Worker besitzt einen separaten Einmal-POST-Schutz und verifiziert seine
Aenderung. Ungeklaerte POSTs werden niemals automatisch wiederholt.

Zuerst nur `--plan` verwenden. Live-`--apply` nur fuer ausdruecklich dafuer
vorgesehene Testdomains. Parallelmodus mit zwei separaten Logins bleibt der
Standard, wenn `--shared-session` fehlt. `--json` ist bei dieser experimentellen
Variante noch deaktiviert, damit keine Worker-Ausgabe JSON verunreinigt.

## Sitzungsende

Nach diesem Befehl werden alle lokalen CookieJars geleert und die
Schreibfreigaben verworfen. Das ist **kein** ausdrueckliches serverseitiges
Logout: Eine Sitzung kann bis zu ihrer serverseitigen Ablaufzeit weiterbestehen.
Es wird noch kein unbelegter Plesk-Logout-Endpunkt angesprochen.
