"""GitHub / source-control checks, run on the local clone (plus optional GitHub API)."""
import json
import re
import urllib.error
import urllib.request

from ..redact import find_secrets, scrub
from .base import Result, git, read_text, rel, repo_files

PILLAR = 'vcs'
SKIP_SECRET_FILES = re.compile(r'(\.example|\.sample|\.lock|package-lock\.json)$')
TEST_FILE = re.compile(r'(^|/)(tests?(/|\.py$)|test_[^/]*\.py$)')
MAX_PER_FILE = 3
MAX_TOTAL = 40
REPO_RE = re.compile(r'^[\w.-]+/[\w.-]+$')


def check_secrets(ctx):
    results = []
    for root in ctx.repo_paths:
        for path in repo_files(root):
            name = rel(path, root)
            if SKIP_SECRET_FILES.search(name):
                continue
            is_test = bool(TEST_FILE.search(name))
            per_file = 0
            for lineno, line in enumerate(read_text(path).splitlines(), start=1):
                if 'sdlcguard:ignore' in line:
                    continue
                for label, severity in find_secrets(line):
                    if is_test and severity != 'Critical':
                        continue
                    results.append(Result(
                        'repo-secret', PILLAR, severity, f'{label} in {name}',
                        f'{name}:{lineno}', scrub(line),
                        'Remove it from the code, rotate the secret, and load it from '
                        'an environment variable or secrets manager.',
                        'Secrets leaked in repository'))
                    per_file += 1
                    break
                if per_file >= MAX_PER_FILE or len(results) >= MAX_TOTAL:
                    break
    return results[:MAX_TOTAL]


def check_env_file(ctx):
    results = []
    for root in ctx.repo_paths:
        if not (root / '.env').is_file():
            continue
        tracked = git(root, 'ls-files', '--error-unmatch', '.env')
        if tracked is not None and tracked.returncode == 0:
            results.append(Result(
                'repo-env-committed', PILLAR, 'High', 'A .env file is committed to Git',
                '.env', 'Tracked by git', 'Remove it from history, rotate every secret '
                'inside it and add .env to .gitignore.', 'Secrets leaked in repository'))
    return results


HOOK_BAD = re.compile(r'(?i)\b(curl|wget|nc|powershell|base64|invoke-webrequest|iex)\b')


def check_git_hooks(ctx):
    results = []
    for root in ctx.repo_paths:
        hooks = root / '.git' / 'hooks'
        if not hooks.is_dir():
            continue
        for hook in hooks.iterdir():
            if hook.is_file() and not hook.name.endswith('.sample') \
                    and HOOK_BAD.search(read_text(hook)):
                results.append(Result(
                    'repo-git-hook', 'endpoint-ide', 'High',
                    f'Git hook "{hook.name}" runs network or encoded commands',
                    rel(hook, root), 'Contains curl/wget/powershell/base64',
                    'Read the hook. Delete it if you did not write it.',
                    'Poisoned local Git hook'))
    return results


def check_unsigned_commits(ctx):
    results = []
    for root in ctx.repo_paths:
        proc = git(root, 'log', '-n', '20', '--format=%G?')
        if proc is None or proc.returncode != 0:
            continue
        flags = proc.stdout.split()
        unsigned = sum(1 for f in flags if f == 'N')
        if unsigned:
            results.append(Result(
                'repo-unsigned-commits', PILLAR, 'Low',
                'Recent commits are not signed',
                str(root.name), f'{unsigned} of the last {len(flags)} commits are unsigned',
                'Sign commits (git config commit.gpgsign true) and require signed '
                'commits on important branches.', 'Imposter commits', key='unsigned'))
    return results


def _github_get(path, token):
    """GET from api.github.com. Returns (status, json). Network use is optional."""
    request = urllib.request.Request(  # nosec B310
        'https://api.github.com' + path,
        headers={'Authorization': f'Bearer {token}', 'Accept': 'application/vnd.github+json',
                 'User-Agent': 'sdlcguard'})
    try:
        with urllib.request.urlopen(request, timeout=8) as resp:  # nosec B310
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as err:
        return err.code, {}
    except (urllib.error.URLError, OSError, ValueError):
        return 0, {}


def check_branch_protection(ctx):
    if not (ctx.github_repo and ctx.github_token) or not REPO_RE.match(ctx.github_repo):
        return []
    status, info = _github_get(f'/repos/{ctx.github_repo}', ctx.github_token)
    branch = info.get('default_branch') if status == 200 else None
    if not branch or not re.fullmatch(r'[\w./-]+', branch):
        return []
    status, _ = _github_get(f'/repos/{ctx.github_repo}/branches/{branch}/protection',
                            ctx.github_token)
    if status == 404:
        return [Result(
            'github-branch-unprotected', PILLAR, 'High',
            f'Default branch "{branch}" has no branch protection', ctx.github_repo,
            'GitHub reports no protection rules',
            'Require pull requests, reviews and status checks before merging.',
            'Branch protection bypass', key=branch)]
    return []
