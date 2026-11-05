"""Registry checks: dependency pinning, risky package indexes and container images."""
import json
import re

from .base import Result, read_text, rel, repo_files

PILLAR = 'registry'
REQ_FILE = re.compile(r'(^|/)requirements[^/]*\.txt$')
FROM = re.compile(r'^FROM\s+(?:--platform=\S+\s+)?(\S+)', re.M | re.I)


def check_requirements(ctx):
    results = []
    for root in ctx.repo_paths:
        for path in repo_files(root):
            name = rel(path, root)
            if not REQ_FILE.search(name):
                continue
            unpinned, risky = [], []
            for line in read_text(path).splitlines():
                line = line.split('#')[0].strip()
                if not line:
                    continue
                if line.startswith('-'):
                    m = re.match(r'--(extra-index-url|index-url|trusted-host)[= ]\s*(\S+)', line)
                    if m and (m.group(1) != 'index-url' or m.group(2).startswith('http://')):
                        risky.append(line)
                elif '==' not in line and ' @ ' not in line:
                    unpinned.append(line)
            if risky:
                results.append(Result(
                    'reg-extra-index', PILLAR, 'High',
                    'Packages can come from an extra or insecure index', name,
                    risky[0], 'Use only the official index (or a single private one) and '
                    'HTTPS.', 'Dependency confusion'))
            if unpinned:
                results.append(Result(
                    'reg-unpinned', PILLAR, 'Medium',
                    f'{len(unpinned)} dependency(ies) are not pinned to an exact version',
                    name, ', '.join(unpinned[:5]),
                    'Pin exact versions (name==1.2.3) and review updates before upgrading.',
                    'Typosquatted / tampered package', key=','.join(unpinned)))
    return results


def check_node_packages(ctx):
    results = []
    for root in ctx.repo_paths:
        for path in repo_files(root):
            if path.name != 'package.json':
                continue
            try:
                data = json.loads(read_text(path))
            except ValueError:
                continue
            deps = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
            loose = [n for n, v in deps.items() if str(v).strip() in ('*', 'latest', '')]
            if loose:
                results.append(Result(
                    'reg-npm-loose', PILLAR, 'Medium',
                    f'{len(loose)} npm package(s) use "*" or "latest"', rel(path, root),
                    ', '.join(loose[:5]), 'Use exact versions and a lock file.',
                    'Typosquatted / tampered package', key=','.join(loose)))
    return results


def check_dockerfiles(ctx):
    results = []
    for root in ctx.repo_paths:
        for path in repo_files(root):
            if not path.name.startswith('Dockerfile'):
                continue
            name, text = rel(path, root), read_text(path)
            loose = []
            for image in FROM.findall(text):
                last = image.rsplit('/', 1)[-1]
                if image == 'scratch' or '$' in image or '@sha256:' in image:
                    continue
                if ':' not in last or image.endswith(':latest'):
                    loose.append(image)
            if loose:
                results.append(Result(
                    'reg-image-tag', PILLAR, 'Medium',
                    'Base image has no fixed version', name, ', '.join(loose),
                    'Use an exact tag or digest so the image cannot change under you.',
                    'Image tag overwrite', key=','.join(loose)))
            if not re.search(r'^USER\s+(?!root\b)\S+', text, re.M | re.I):
                results.append(Result(
                    'prod-container-root', 'production', 'Medium',
                    'Container runs as root', name, 'No non-root USER instruction',
                    'Add a USER instruction with an unprivileged account.',
                    'Over-privileged deploy credentials'))
    return results
