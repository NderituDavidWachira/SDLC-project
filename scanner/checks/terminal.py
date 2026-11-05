"""Endpoint checks: risky commands in shell history and secrets in the environment."""
import re
from pathlib import Path

from ..redact import find_secrets, scrub
from .base import Result, read_text, short

PILLAR = 'endpoint-ide'
HISTORY_LINES = 2000
MAX_PER_RULE = 5

RULES = [
    ('remote-exec', 'High', 'Remote script run straight from the internet', [
        re.compile(r'(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z)?sh\b', re.I),
        re.compile(r'(iwr|irm|invoke-webrequest|invoke-restmethod)\b.*\|\s*'
                   r'(iex|invoke-expression)\b', re.I),
        re.compile(r'(iex|invoke-expression)\b.*(iwr|irm|invoke-webrequest|'
                   r'invoke-restmethod|downloadstring)', re.I)],
     'Download the script, read it, then run it. Prefer signed packages.',
     'Malicious script execution'),
    ('exec-policy', 'Medium', 'PowerShell script protection switched off', [
        re.compile(r'set-executionpolicy\b.*\b(bypass|unrestricted)\b', re.I)],
     'Use RemoteSigned for your user only, and avoid Bypass/Unrestricted.',
     'Defence evasion on the workstation'),
    ('chmod-777', 'Medium', 'Files made writable by everyone', [
        re.compile(r'chmod\s+(-R\s+)?777')],
     'Grant only the permissions needed (for example 640 or 750).',
     'Over-permissive workstation files'),
    ('no-verify', 'Medium', 'Git safety hooks bypassed', [
        re.compile(r'git\s+(commit|push)\b.*--no-verify')],
     'Fix what the hook complains about instead of skipping it.',
     'Poisoned local Git hook'),
    ('tls-off', 'High', 'TLS certificate checking turned off', [
        re.compile(r'sslVerify\s+false', re.I), re.compile(r'--insecure\b'),
        re.compile(r'NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0')],
     'Keep certificate checks on. Install the missing CA certificate instead.',
     'Man-in-the-middle of developer traffic'),
    ('insecure-index', 'Medium', 'Packages installed from an extra or insecure index', [
        re.compile(r'pip3?\s+install\b.*(--extra-index-url|--trusted-host|'
                   r'--index-url\s+http://)')],
     'Install only from the official index or one private index you control.',
     'Dependency confusion'),
    ('force-push', 'Low', 'Git history force-pushed', [
        re.compile(r'git\s+push\b.*\s(--force(?!-with-lease)|-f)(\s|$)')],
     'Use --force-with-lease and protect important branches.',
     'Imposter commits / history rewriting'),
]


def history_files(home, env):
    appdata = Path(env.get('APPDATA') or home / 'AppData' / 'Roaming')
    return [
        home / '.bash_history', home / '.zsh_history',
        appdata / 'Microsoft' / 'Windows' / 'PowerShell' / 'PSReadLine'
        / 'ConsoleHost_history.txt',
        home / '.local' / 'share' / 'powershell' / 'PSReadLine' / 'ConsoleHost_history.txt',
    ]


def _commands(path):
    lines = read_text(path).splitlines()[-HISTORY_LINES:]
    return [re.sub(r'^: \d+:\d+;', '', ln).strip() for ln in lines if ln.strip()]


def check_history(ctx):
    results = []
    for path in history_files(ctx.home, ctx.env):
        if not path.is_file():
            continue
        where = short(path, ctx.home)
        commands = _commands(path)
        for rule_id, severity, title, patterns, fix, technique in RULES:
            hits = {}
            for cmd in commands:
                if any(p.search(cmd) for p in patterns):
                    hits.setdefault(scrub(cmd), 0)
                    hits[scrub(cmd)] += 1
            for text, count in list(hits.items())[:MAX_PER_RULE]:
                results.append(Result(
                    f'history-{rule_id}', PILLAR, severity,
                    title + (f' ({count} times)' if count > 1 else ''),
                    where, text, fix, technique, key=text))
        seen = set()
        for cmd in commands:
            labels = find_secrets(cmd)
            text = scrub(cmd)
            if labels and text not in seen and len(seen) < MAX_PER_RULE:
                seen.add(text)
                results.append(Result(
                    'history-secret', PILLAR, 'High',
                    'A credential was typed into a terminal command', where, text,
                    'Rotate that credential now. Use a prompt, a credential helper or '
                    'a secrets manager instead of typing it.',
                    'Credential theft from developer environment', key=text))
    return results


SECRET_NAME = re.compile(r'(?i)(token|secret|password|passwd|api[_-]?key|private[_-]?key)')


def check_environment(ctx):
    names = sorted(
        n for n, v in ctx.env.items()
        if SECRET_NAME.search(n) and len(v) >= 12
        and not n.upper().startswith(('DJANGO_', 'SDLCGUARD_')))
    if not names:
        return []
    return [Result(
        'env-secrets', PILLAR, 'Medium',
        f'{len(names)} secret(s) sit in this terminal\'s environment',
        'Environment variables of the terminal running SDLC Guard',
        'Variable names: ' + ', '.join(names[:8]),
        'Keep long-lived tokens out of shell profiles. Load them only when needed '
        'and use short-lived tokens.',
        'Credential theft from developer environment', key=','.join(names))]
