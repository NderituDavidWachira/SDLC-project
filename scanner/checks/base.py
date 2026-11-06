"""Shared helpers for all checks: result type, scan context, safe file listing."""
import hashlib
import os
import shutil
import subprocess  # nosec B404
from dataclasses import dataclass, field
from pathlib import Path

SKIP_DIRS = {'.git', 'venv', '.venv', 'node_modules', '__pycache__', 'staticfiles',
             '.tox', 'dist', 'build', '.mypy_cache'}
TEXT_SUFFIXES = {'.sublime-project', '.sublime-build', '.py', '.js', '.ts', '.json', '.yml',
                 '.yaml', '.toml', '.ini', '.cfg',
                 '.env', '.txt', '.md', '.sh', '.ps1', '.bat', '.html', '.xml',
                 '.properties', '.conf'}
TEXT_NAMES = {'Dockerfile', 'Jenkinsfile', '.env', '.npmrc', '.pypirc', '.netrc'}
MAX_FILE_BYTES = 1_000_000
MAX_FILES = 5000


@dataclass(frozen=True)
class Result:
    check_id: str
    pillar: str
    severity: str
    title: str
    location: str
    evidence: str
    fix: str
    technique: str
    key: str = ''
    source: str = ''

    @property
    def fingerprint(self):
        raw = f'{self.check_id}|{self.location}|{self.key or self.evidence}'
        return hashlib.sha256(raw.encode()).hexdigest()[:40]


@dataclass
class ScanContext:
    repo_paths: list = field(default_factory=list)
    home: Path = field(default_factory=Path.home)
    scan_machine: bool = True
    env: dict = field(default_factory=dict)
    github_repo: str = ''
    github_token: str = ''
    trusted_publishers: tuple = ()


def short(path, home):
    """Show a path with the home folder abbreviated to ~."""
    try:
        return '~/' + Path(path).relative_to(home).as_posix()
    except ValueError:
        return str(path)


def rel(path, root):
    try:
        return Path(path).relative_to(root).as_posix()
    except ValueError:
        return Path(path).as_posix()


def read_text(path):
    try:
        return Path(path).read_text(encoding='utf-8', errors='replace')
    except OSError:
        return ''


def git(path, *args, timeout=10):
    """Run a git command with fixed arguments (never through a shell)."""
    exe = shutil.which('git')
    if not exe:
        return None
    try:
        return subprocess.run(  # nosec B603
            [exe, '-C', str(path), *args], capture_output=True, text=True,
            encoding='utf-8', errors='replace', timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return None


def _scannable(path):
    if path.name in TEXT_NAMES or path.suffix.lower() in TEXT_SUFFIXES \
            or path.name.startswith('Dockerfile'):
        try:
            return path.is_file() and path.stat().st_size <= MAX_FILE_BYTES
        except OSError:
            return False
    return False


def repo_files(root):
    """Text files that are, or would be, committed (git aware), else a safe walk."""
    root = Path(root)
    proc = git(root, 'ls-files', '-z', '--cached', '--others', '--exclude-standard')
    if proc is not None and proc.returncode == 0:
        paths = (root / n for n in proc.stdout.split('\0') if n)
        return [p for p in paths if _scannable(p)][:MAX_FILES]
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            p = Path(dirpath) / name
            if _scannable(p):
                out.append(p)
                if len(out) >= MAX_FILES:
                    return out
    return out