"""Web browser checks. Reads only extension manifests and safety preferences.
It never touches saved passwords, cookies or browsing history."""
import json
import re
from pathlib import Path

from .base import Result, read_text, short

PILLAR = 'endpoint-ide'
BROAD = {'<all_urls>', '*://*/*', 'http://*/*', 'https://*/*'}
SENSITIVE = {'cookies', 'webRequest', 'history', 'tabs', 'nativeMessaging', 'debugger',
             'clipboardRead', 'management', 'webRequestBlocking'}
BUILT_IN_IDS = {'ghbmnnjooekpmoecnnnilnnbdlolhkhi'}  # Google Docs Offline


def _json(path):
    try:
        return json.loads(read_text(path))
    except ValueError:
        return {}


def chromium_profiles(home, env):
    local = Path(env.get('LOCALAPPDATA') or home / 'AppData' / 'Local')
    mac = home / 'Library' / 'Application Support'
    roots = {
        'Chrome': [local / 'Google' / 'Chrome' / 'User Data', home / '.config' / 'google-chrome',
                   mac / 'Google' / 'Chrome'],
        'Edge': [local / 'Microsoft' / 'Edge' / 'User Data', home / '.config' / 'microsoft-edge',
                 mac / 'Microsoft Edge'],
        'Brave': [local / 'BraveSoftware' / 'Brave-Browser' / 'User Data',
                  home / '.config' / 'BraveSoftware' / 'Brave-Browser',
                  mac / 'BraveSoftware' / 'Brave-Browser'],
        'Chromium': [home / '.config' / 'chromium'],
    }
    for browser, paths in roots.items():
        for root in paths:
            if root.is_dir():
                for prof in sorted(root.iterdir()):
                    if prof.is_dir() and (prof.name == 'Default'
                                          or prof.name.startswith('Profile ')):
                        yield browser, prof


def firefox_profiles(home, env):
    appdata = Path(env.get('APPDATA') or home / 'AppData' / 'Roaming')
    roots = [appdata / 'Mozilla' / 'Firefox' / 'Profiles', home / '.mozilla' / 'firefox',
             home / 'Library' / 'Application Support' / 'Firefox' / 'Profiles']
    return [p for r in roots if r.is_dir() for p in sorted(r.iterdir()) if p.is_dir()]


def _ext_name(ext_dir, manifest, ext_id):
    name = str(manifest.get('name', ext_id))
    match = re.fullmatch(r'__MSG_(.+)__', name)
    if not match:
        return name
    key = match.group(1).lower()
    for messages in sorted(ext_dir.glob('_locales/*/messages.json')):
        data = {k.lower(): v for k, v in _json(messages).items()}
        if key in data and isinstance(data[key], dict):
            return str(data[key].get('message', ext_id))
    return ext_id


def _flat(items):
    return [i for i in items if isinstance(i, str)]


def check_extensions(ctx):
    results = []
    for browser, prof in chromium_profiles(ctx.home, ctx.env):
        broad, sensitive = [], False
        ext_root = prof / 'Extensions'
        if not ext_root.is_dir():
            continue
        for ext in sorted(ext_root.iterdir()):
            versions = sorted(d for d in ext.iterdir() if d.is_dir()) if ext.is_dir() else []
            if not versions or ext.name in BUILT_IN_IDS:
                continue
            manifest = _json(versions[-1] / 'manifest.json')
            perms = set(_flat(manifest.get('permissions', []))
                        + _flat(manifest.get('host_permissions', [])))
            for script in manifest.get('content_scripts', []):
                perms |= set(_flat(script.get('matches', [])))
            if perms & BROAD:
                broad.append(_ext_name(versions[-1], manifest, ext.name))
                sensitive = sensitive or bool(perms & SENSITIVE)
        if broad:
            results.append(Result(
                'browser-extensions', PILLAR, 'Medium' if sensitive else 'Low',
                f'{len(broad)} {browser} extension(s) can read data on every website',
                f'{browser} profile "{prof.name}"', ', '.join(broad[:8]),
                'Remove extensions you do not use. Keep only ones from publishers you trust.',
                'Malicious browser extension', key=f'{browser}:{prof.name}:' + ','.join(broad)))
    for prof in firefox_profiles(ctx.home, ctx.env):
        addons = _json(prof / 'extensions.json').get('addons', [])
        broad = []
        for addon in addons:
            origins = _flat(addon.get('userPermissions', {}).get('origins', []))
            if addon.get('type') == 'extension' and addon.get('location') == 'app-profile' \
                    and set(origins) & BROAD:
                broad.append(str(addon.get('defaultLocale', {}).get('name', addon.get('id'))))
        if broad:
            results.append(Result(
                'browser-extensions', PILLAR, 'Low',
                f'{len(broad)} Firefox add-on(s) can read data on every website',
                f'Firefox profile "{prof.name}"', ', '.join(broad[:8]),
                'Remove add-ons you do not use.', 'Malicious browser extension',
                key=f'Firefox:{prof.name}:' + ','.join(broad)))
    return results


def check_safe_browsing(ctx):
    results = []
    for browser, prof in chromium_profiles(ctx.home, ctx.env):
        prefs = _json(prof / 'Preferences')
        if prefs.get('safebrowsing', {}).get('enabled') is False:
            results.append(Result(
                'browser-safe-browsing-off', PILLAR, 'High',
                f'{browser} Safe Browsing is turned off', f'{browser} profile "{prof.name}"',
                'safebrowsing.enabled = false',
                'Turn Safe Browsing back on in the browser privacy and security settings.',
                'Malicious download / phishing', key=f'{browser}:{prof.name}'))
    for prof in firefox_profiles(ctx.home, ctx.env):
        text = read_text(prof / 'prefs.js')
        if re.search(r'browser\.safebrowsing\.(malware|phishing)\.enabled",\s*false', text):
            results.append(Result(
                'browser-safe-browsing-off', PILLAR, 'High',
                'Firefox Safe Browsing is turned off', short(prof, ctx.home),
                'browser.safebrowsing.*.enabled = false',
                'Turn protection back on in Firefox settings.', 'Malicious download / phishing',
                key=f'Firefox:{prof.name}'))
    return results