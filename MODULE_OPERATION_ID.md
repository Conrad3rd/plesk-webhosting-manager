# operation_id bei parallelen Fachereignissen

Das CLI setzt den Korrelationskontext pro Aufruf. `ContextVar`-Kontexte werden
von `ThreadPoolExecutor` jedoch **nicht automatisch** an Threads weitergegeben.
Die beiden Worker des Shared-Session-Batch betreten deshalb jeweils explizit
`correlation_context(operation_id)` vor ihrem Aufruf von `php.run` bzw. `ssl.run`.

Dadurch erhalten sämtliche über `core.log_event` geschriebenen Modulereignisse
(`php`, `ssl` sowie ihre Prüf- und Fehlermeldungen) die gleiche `operation_id`
wie Batch-Orchestrierung und anschließender Logout. Jeder Thread stellt seinen
vorherigen Kontext wieder her. An Authentifizierung, POST-Anzahl, Logout und
Schreibfreigaben ändert sich nichts.

Im getrennten Parallelmodus wird die `operation_id` bereits an beide
CLI-Unterprozesse übergeben; diese setzen ihren eigenen Korrelationskontext.
Einzelbefehle mit expliziter `--operation-id` verwenden den CLI-Kontext ebenso.
Ohne `--operation-id` bleibt sie bei Einzelbefehlen bewusst optional.
