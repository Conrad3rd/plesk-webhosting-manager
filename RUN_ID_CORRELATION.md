# Einheitliche run_id bei automatischem Logout

Jeder CLI-Prozess erzeugt einmalig beim Start eine `run_id` (12 Hex-Zeichen).
Die CLI uebergibt diese Kennung an alle fachlichen Modulaufzeichnungen
(`batch`, `inspect`, `domains`, `php-versions`, `shared_parallel`, `parallel`,
`php`, `ssl`, `subdomain`) und den abschliessenden `session_logout`.
So sind Start, Verifikation und Logout eines Prozesses eindeutig verbunden.

Bei `batch --parallel` mit zwei separaten Subprozessen besitzt jeder Worker
weiterhin eine eigene `run_id`. Die uebergeordnete `operation_id` verknuepft
weiterhin alle beteiligten Prozesse. Bei `--shared-session` gibt es nur einen
CLI-Prozess und eine gemeinsame `run_id` fuer dessen Aktionen und Logout.

Keine Aenderung an Login-/Logout-Protokoll, Schreibschutz, CLI-Ausgabeformat
oder Verhalten bei fehlgeschlagenem Logout. `run_id` ist ausschliesslich
Protokollmetadatum und wird nicht an Plesk gesendet.
