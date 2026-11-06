"""Sublime Text checks: third-party packages (they run code) and risky build systems."""
import re
from pathlib import Path

from .base import Result, read_text, rel, repo_files, short

PILLAR = 'endpoint-ide'
BUILT_IN = {'Default', 'User', 'Package Control', 'Theme - Default'}
RISKY_BUILD = re.compile(
    r'(?i)((curl|wget)\b[^|"]*\|\s*(sudo\s+)?(ba|z)?sh\b|invoke-expression|\biex\b|'
    r'powershell[^"]*-enc)')


def sublime_dirs(home, env):
    appdata = Path(env.get('APPDATA') or home / 'AppData' / 'Roaming')
    mac = home / 'Library' / 'Application Support'
    names = ('Sublime Text', 'Sublime Text 3')
    dirs = [appdata / n for n in names] + [mac / n for n in names]
    dirs += [home / '.config' / 'sublime-text', home / '.config' / 'sublime-text-3']
    return [d for d in dirs if d.is_dir()]


def check_packages(ctx):
    results = []
    for base in sublime_dirs(ctx.home, ctx.env):
        names = set()
        installed = base / 'Installed Packages'
        if installed.is_dir():
            names |= {p.name.removesuffix('.sublime-package')
                      for p in installed.glob('*.sublime-package')}
        packages = base / 'Packages'
        if packages.is_dir():
            names |= {p.name for p in packages.iterdir() if p.is_dir()}
        extra = sorted(names - BUILT_IN)
        if extra:
            results.append(Result(
                'sublime-packages', PILLAR, 'Low',
                f'{len(extra)} third-party Sublime Text package(s) installed',
                short(base, ctx.home), ', '.join(extra[:8]),
                'Packages can run any code on your computer. Remove the ones you do '
                'not use and install only well-known ones.', 'Malicious IDE extension',
                key=','.join(extra)))
    return results


def check_builds(ctx):
    results = []
    for root in ctx.repo_paths:
        for path in repo_files(root):
            if path.suffix in ('.sublime-project', '.sublime-build') \
                    and RISKY_BUILD.search(read_text(path)):
                results.append(Result(
                    'sublime-risky-build', PILLAR, 'High',
                    'A Sublime build system downloads and runs code', rel(path, root),
                    'Build command pipes a download into a shell or uses encoded PowerShell',
                    'Read the build file. Remove it if you did not write it.',
                    'Malicious IDE extension / workspace'))
    return results