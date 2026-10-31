#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ "$(git rev-parse --show-toplevel 2>/dev/null)" != "$ROOT" ]]; then
    echo "FEHLER: Das Projektverzeichnis ist kein eigenes Git-Repository." >&2
    exit 1
fi
if [[ -n "$(git status --porcelain)" ]]; then
    echo "FEHLER: Noch nicht commitete Aenderungen vorhanden." >&2
    git status --short >&2
    exit 1
fi

# Nur bereits versionierte Dateien koennen im Export landen.
while IFS= read -r -d '' file; do
    case "$file" in
        logs/*|*/logs/*|__pycache__/*|*/__pycache__/*|*.pyc|*.pyo|*.env|*.pem|*.key|*.har|*.jsonl|*.cookies|*.session|*.session.json|accounts.json|*/accounts.json)
            echo "FEHLER: Unerwuenschte getrackte Datei: $file" >&2
            exit 1
            ;;
    esac
done < <(git ls-files -z)

if git grep -I -n -E '/home/[[:alnum:]_.-]+/|/Users/[[:alnum:]_.-]+/' -- '*.py' '*.md' '*.txt' '*.sh' 2>/dev/null; then
    echo "FEHLER: Lokale Benutzerpfade in getrackten Quellen gefunden." >&2
    exit 1
fi

TARGET="${1:-"$ROOT/../public-export/plesk-webhosting-manager-public.zip"}"
mkdir -p "$(dirname "$TARGET")"
git archive --format=zip --prefix=plesk-webhosting-manager/ --output="$TARGET" HEAD
printf 'Bereinigter Git-Export: %s\n' "$TARGET"
printf 'Hinweis: Vor dem Push auch die Commit-Historie und Git-Autordaten pruefen.\n'
