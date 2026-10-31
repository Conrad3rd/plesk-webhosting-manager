"""Linux-Kontenprofile: nur Host und Benutzer in JSON; Passwoerter im Secret Service."""
from __future__ import annotations

import getpass
import json
import os
from pathlib import Path
import re
import subprocess

from .core import PleskError, valid_domain

APP_ID = 'plesk-webhosting-manager'
OLD_ATTRIBUTES = ['application', 'desktop-tools-project-manager', 'service', 'plesk-wcp']


def config_path():
    root = Path(os.environ.get('XDG_CONFIG_HOME') or (Path.home() / '.config')).expanduser()
    return root / 'plesk-webhosting' / 'accounts.json'


def name_ok(name):
    return isinstance(name, str) and bool(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', name))


def normalize_host(host):
    if not isinstance(host, str):
        raise PleskError('Ungueltiger Host')
    host = host.strip().lower()
    if host.startswith('https://'):
        host = host[8:]
    if not valid_domain(host):
        raise PleskError('Plesk-Host muss ein vollstaendiger DNS-Name ohne Port/Pfad sein')
    return host


def load_profiles():
    path = config_path()
    if not path.exists():
        return {}
    if path.is_symlink():
        raise PleskError('Kontendatei darf kein Symlink sein')
    if path.stat().st_mode & 0o077:
        raise PleskError('Kontendatei hat zu offene Berechtigungen (erwartet 0600)')
    try:
        profiles = json.loads(path.read_text(encoding='utf-8'))
    except (ValueError, OSError) as exc:
        raise PleskError('Kontendatei kann nicht gelesen werden') from exc
    if not isinstance(profiles, dict):
        raise PleskError('Kontendatei hat unbekanntes Format')
    for name, entry in profiles.items():
        if (not name_ok(name) or not isinstance(entry, dict) or set(entry) != {'host','user'} or
                not valid_domain(entry.get('host')) or not isinstance(entry.get('user'), str) or
                not entry['user'] or len(entry['user']) > 256):
            raise PleskError('Kontendatei enthaelt ungueltigen Profileintrag')
    return profiles


def save_profiles(profiles):
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise PleskError('Symlink als Kontendatei gesperrt')
    # Atomarer Dateiaustausch. Keine Geheimnisse in dieser Datei.
    import tempfile
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix='.accounts-', suffix='.tmp')
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as out:
            json.dump(profiles, out, ensure_ascii=False, indent=2, sort_keys=True)
            out.write('\n')
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def attrs(name, host, user):
    return ['application', APP_ID, 'profile', name, 'host', host, 'user', user]


def secret_process(command, *, input_text=None):
    try:
        result = subprocess.run(command, input=input_text, capture_output=True,
                                text=True, timeout=25, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PleskError('secret-tool nicht erreichbar. Paket libsecret-tools installieren.') from exc
    if result.returncode != 0:
        raise PleskError('Linux-Schluesselbund fehlgeschlagen: entsperrte Sitzung erforderlich')
    return result.stdout


def get_password(name, entry):
    password = secret_process(['secret-tool', 'lookup', *attrs(name,entry['host'],entry['user'])]).rstrip('\n')
    if not password:
        raise PleskError('Kein Passwort im Linux-Schluesselbund zu diesem Profil gefunden')
    return password


def find_profile(name):
    profiles = load_profiles()
    if name is None:
        if len(profiles) == 1:
            name = next(iter(profiles))
        elif not profiles:
            raise PleskError('Kein Konto eingerichtet. Zuerst: account add ...')
        else:
            raise PleskError('Mehrere Konten vorhanden: --account PROFIL angeben')
    if name not in profiles:
        raise PleskError('Unbekanntes Kontenprofil (account list zeigt vorhandene Konten)')
    return name, profiles[name]


def add_profile(name, host, user, from_legacy=False):
    if not name_ok(name):
        raise PleskError('Profilname: Buchstaben, Zahlen, Punkte, _ und - (max. 64)')
    host = normalize_host(host)
    if not isinstance(user, str) or not user.strip() or len(user) > 256:
        raise PleskError('Plesk-Benutzername fehlt')
    user = user.strip()
    profiles = load_profiles()
    if name in profiles:
        raise PleskError('Das Profil existiert bereits; vorhandene Zugangsdaten bleiben unveraendert')
    if from_legacy:
        raw = secret_process(['secret-tool','lookup',*OLD_ATTRIBUTES,'host',host])
        try:
            cred = json.loads(raw)
            if cred['user'] != user or not isinstance(cred['password'], str) or not cred['password']:
                raise ValueError
            password = cred['password']
        except (TypeError, ValueError, KeyError) as exc:
            raise PleskError('Alte Zugangsdaten fehlen oder Benutzername weicht ab') from exc
    else:
        password = getpass.getpass('Plesk-Passwort (unsichtbare Eingabe): ')
        if not password:
            raise PleskError('Leeres Passwort abgelehnt')
    # Erst Passwort schreiben, danach das reine Metadatenprofil hinterlegen.
    secret_process(['secret-tool', 'store', '--label=Plesk Webhosting Manager: ' + name,
                    *attrs(name, host, user)], input_text=password)
    profiles[name] = {'host': host, 'user': user}
    save_profiles(profiles)
    print('Profil eingerichtet:', name, '| Host:', host, '| Benutzer:', user)
    print('Passwort im Linux-Schluesselbund gespeichert, nicht in der Kontendatei.')


def remove_profile(name, yes):
    if not yes:
        raise PleskError('account remove erfordert --yes')
    profiles = load_profiles()
    if name not in profiles:
        raise PleskError('Profil nicht vorhanden')
    entry = profiles[name]
    secret_process(['secret-tool','clear',*attrs(name,entry['host'],entry['user'])])
    del profiles[name]
    save_profiles(profiles)
    print('Profil und Schluesselbund-Eintrag entfernt:', name)


def list_profiles():
    profiles = load_profiles()
    if not profiles:
        print('Keine Kontenprofile vorhanden.')
    for name, entry in sorted(profiles.items()):
        print(f'{name}: {entry["host"]} (Benutzer: {entry["user"]})')
