"""CI/CD checks on GitHub Actions, CircleCI, Jenkins and GitLab configuration."""
import re

from .base import Result, read_text, rel, repo_files

PILLAR = 'ci-cd'
PIPELINE_FILE = re.compile(r'^(\.github/workflows/[^/]+\.ya?ml|\.circleci/config\.yml|'
                           r'Jenkinsfile|\.gitlab-ci\.yml)$')
USES = re.compile(r'uses:\s*([\w.-]+/[\w./-]+)@([\w.-]+)')
OFFICIAL = {'actions', 'github'}
REMOTE_EXEC = re.compile(r'(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z)?sh\b')
SECRET_ECHO = re.compile(r'echo\s+[^\n]*\$\{\{\s*secrets\.')
IMAGE = re.compile(r'^\s*-?\s*image:\s*(\S+)', re.M)


def check_pipelines(ctx):
    results = []
    for root in ctx.repo_paths:
        for path in repo_files(root):
            name = rel(path, root)
            if not PIPELINE_FILE.match(name):
                continue
            text = read_text(path)

            def add(check_id, severity, title, evidence, fix, technique, key=''):
                results.append(Result(check_id, PILLAR, severity, title, name, evidence,
                                      fix, technique, key=key))

            if 'pull_request_target' in text:
                add('ci-pr-target', 'High', 'Workflow runs on untrusted pull requests '
                    'with repository secrets', 'pull_request_target',
                    'Use the pull_request trigger, or never check out PR code here.',
                    'Untrusted workflow injection')
                if 'actions/cache' in text:
                    add('ci-cache-poison', 'High', 'Cache shared with untrusted pull '
                        'requests', 'actions/cache + pull_request_target',
                        'Do not restore or save caches in workflows that run PR code.',
                        'Action cache poisoning')
            unpinned = [f'{a}@{r}' for a, r in USES.findall(text)
                        if not re.fullmatch(r'[0-9a-f]{40}', r)]
            if unpinned:
                third_party = any(u.split('/')[0] not in OFFICIAL for u in unpinned)
                add('ci-unpinned-actions', 'Medium' if third_party else 'Low',
                    f'{len(unpinned)} action(s) not pinned to a commit', ', '.join(unpinned[:5]),
                    'Pin each action to a full 40-character commit SHA.',
                    'Imposter commits', key=','.join(unpinned))
            if SECRET_ECHO.search(text):
                add('ci-secret-echo', 'High', 'A pipeline prints a secret to the log',
                    'echo ${{ secrets... }}', 'Never echo secrets. Pass them as '
                    'environment variables to the step that needs them.',
                    'Pipeline secret exfiltration')
            if REMOTE_EXEC.search(text):
                add('ci-remote-exec', 'High', 'A pipeline runs a script piped from the internet',
                    'curl ... | sh', 'Download, verify a checksum, then run.',
                    'Compromised build runner')
            if re.search(r'permissions:\s*write-all', text):
                add('ci-write-all', 'Medium', 'Pipeline token has write access to everything',
                    'permissions: write-all', 'Grant only the permissions each job needs.',
                    'Over-privileged pipeline token')
            images = [i for i in IMAGE.findall(text)
                      if ':' not in i.rsplit('/', 1)[-1] or i.endswith(':latest')]
            if images:
                add('ci-unpinned-image', 'Medium', 'Build image has no fixed version',
                    ', '.join(images[:4]), 'Use an exact version tag, ideally a digest.',
                    'Compromised build runner', key=','.join(images))
    return results
