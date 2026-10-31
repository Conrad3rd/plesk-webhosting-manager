# Plesk-Sitzung: sichere Wiederverwendung (erste Ausbaustufe)

Die bestehende CLI bleibt unverändert. Ein Aufruf von `inspect --json` liest mehrere
Einstellungsbereiche mit nur einer Anmeldung. Eine Sitzung kann künftig für
mehrere **nacheinander ausgeführte und nachweislich bestätigte** Schreibaktionen
wiederverwendet werden. Die Anwendung ruft nach jedem POST erst eine Statusabfrage
auf. Nur wenn diese den gewünschten Zielzustand eindeutig bestätigt, wird
`client.finish_verified_write(verified=True)` aufgerufen und die nächste
Einmalfreigabe erlaubt. Bei ungeklärtem Status muss
`finish_verified_write(verified=False)` oder `retire_writes()` erfolgen.

Wichtig: Der Aufrufer darf `verified=True` niemals allein aus HTTP 200 oder
einer unbekannten HTML-Antwort ableiten. Es ist kein Retry-Mechanismus.
Die vorhandenen Endpunkt-, Payload-, CSRF- und Einmal-POST-Prüfungen bleiben
bestehen. Pro Sitzung ist stets höchstens **eine Schreibaktion gleichzeitig**
freigegeben. Die Einschränkung ist eine Sicherheitsvorgabe dieses Tools und
kein belegtes generelles Limit von Plesk. Ob Plesk echte gleichzeitige Writes
auf dieselbe Domain sicher unterstützt, ist bislang nicht live getestet.

Dies ist die vorbereitende API für einen späteren Batch-Orchestrator; die
bisherigen CLI-Schreibbefehle nutzen weiterhin je Aufruf eine neue Sitzung.
Aufgrund der neuen Verzeichnisstruktur befinden sich CLI und Tests in
`~/Projects/plesk-webhosting-manager/repo/`.
