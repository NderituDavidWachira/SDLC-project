"""VS Code checks: risky settings, auto-run tasks and unfamiliar extensions."""
import re
from pathlib import Path

from .base import Result, read_text, rel, repo_files, short

PILLAR = 'endpoint-ide'
EXT_RE = re.compile(r'^([A-Za-z0-9_.-]+?)-\d+\.\d+')


def settings_files(home, env):
    appdata = Path(env.get('APPDATA') or home / 'AppData' / 'Roaming')
    return [appdata / 'Code' / 'User' / 'settings.json',
            home / '.config' / 'Code' / 'User' / 'settings.json',
            home / 'Library' / 'Application Support' / 'Code' / 'User' / 'settings.json']


def check_settings(ctx):
    results = []
    for path in settings_files(ctx.home, ctx.env):
        text = read_text(path) if path.is_file() else ''
        where = short(path, ctx.home)
        if re.search(r'"security\.workspace\.trust\.enabled"\s*:\s*false', text):
            results.append(Result(
                'vscode-trust-off', PILLAR, 'High', 'VS Code Workspace Trust is turned off',
                where, '"security.workspace.trust.enabled": false',
                'Turn Workspace Trust back on so untrusted folders cannot run code.',
                'Malicious IDE extension / workspace'))
        if re.search(r'"task\.allowAutomaticTasks"\s*:\s*"on"', text):
            results.append(Result(
                'vscode-auto-tasks', PILLAR, 'High',
                'VS Code runs automatic tasks without asking', where,
                '"task.allowAutomaticTasks": "on"',
                'Set it to "off" or "auto" so a cloned repo cannot start tasks silently.',
                'Malicious IDE extension / workspace'))
    return results


def check_extensions(ctx):
    ext_dir = ctx.home / '.vscode' / 'extensions'
    if not ext_dir.is_dir():
        return []
    unknown = []
    for entry in sorted(ext_dir.iterdir()):
        match = EXT_RE.match(entry.name)
        if entry.is_dir() and match:
            ext_id = match.group(1)
            if ext_id.split('.')[0].lower() not in ctx.trusted_publishers:
                unknown.append(ext_id)
    if not unknown:
        return []
    return [Result(
        'vscode-extensions', PILLAR, 'Low',
        f'{len(unknown)} extension(s) from publishers not on your trusted list',
        short(ext_dir, ctx.home), ', '.join(unknown[:8]),
        'Review each one. Remove what you do not use and install only from '
        'verified publishers.', 'Malicious IDE extension', key=','.join(unknown))]


def check_workspace_tasks(ctx):
    results = []
    for root in ctx.repo_paths:
        for path in repo_files(root):
            if path.name == 'tasks.json' and path.parent.name == '.vscode' \
                    and re.search(r'"runOn"\s*:\s*"folderOpen"', read_text(path)):
                results.append(Result(
                    'vscode-folder-open-task', PILLAR, 'Medium',
                    'A VS Code task starts automatically when the folder is opened',
                    rel(path, root), '"runOn": "folderOpen"',
                    'Remove it, or make sure you trust everything in this repository.',
                    'Malicious IDE extension / workspace'))
    return results
