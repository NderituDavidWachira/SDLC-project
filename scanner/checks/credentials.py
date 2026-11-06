"""Keys and logins stored on the computer: SSH, cloud, registries, Git."""
import base64
import binascii
import json
import os
import re
import struct

from ..redact import mask, scrub
from .base import Result, read_text, short

PILLAR = 'endpoint-ide'
SKIP_SSH = {'known_hosts', 'known_hosts.old', 'config', 'authorized_keys'}
OPENSSH_MAGIC = b'openssh-key-v1\x00'


def _is_encrypted(text):
    if 'ENCRYPTED' in text:
        return True
    if 'BEGIN OPENSSH PRIVATE KEY' not in text:
        return False
    body = ''.join(ln for ln in text.splitlines() if ln and not ln.startswith('-----'))
    try:
        data = base64.b64decode(body)
        if not data.startswith(OPENSSH_MAGIC):
            return True  # unknown format: do not raise a false alarm
        size = struct.unpack('>I', data[15:19])[0]
        return data[19:19 + size] != b'none'
    except (binascii.Error, struct.error):
        return True


def check_ssh_keys(ctx):
    ssh = ctx.home / '.ssh'
    if not ssh.is_dir():
        return []
    results = []
    for key in sorted(ssh.iterdir()):
        if not key.is_file() or key.suffix == '.pub' or key.name in SKIP_SSH:
            continue
        try:
            if key.stat().st_size > 20000:
                continue
        except OSError:
            continue
        text = read_text(key)
        if 'PRIVATE KEY-----' not in text:
            continue
        where = short(key, ctx.home)
        if not _is_encrypted(text):
            results.append(Result(
                'cred-ssh-no-passphrase', PILLAR, 'Medium', 'An SSH private key has no passphrase',
                where, 'Key file is not encrypted',
                'Add a passphrase (ssh-keygen -p -f <key>) and use ssh-agent.',
                'Credential theft from developer environment'))
        if os.name != 'nt' and key.stat().st_mode & 0o077:
            results.append(Result(
                'cred-ssh-permissions', PILLAR, 'High',
                'An SSH private key can be read by other users', where,
                'File permissions allow group/other access', 'Run: chmod 600 on the key file.',
                'Credential theft from developer environment'))
    return results


def check_cloud_credentials(ctx):
    results = []
    aws = ctx.home / '.aws' / 'credentials'
    if aws.is_file():
        keys = re.findall(r'aws_access_key_id\s*=\s*(\S+)', read_text(aws))
        if keys:
            results.append(Result(
                'cred-aws-keys', PILLAR, 'Medium',
                'Long-lived AWS access keys are stored in a file', short(aws, ctx.home),
                f'{len(keys)} key(s), for example {mask(keys[0])}',
                'Use short-lived SSO or role credentials instead of permanent keys.',
                'Credential theft from developer environment', key=f'{len(keys)}'))
    kube = ctx.home / '.kube' / 'config'
    if kube.is_file() and re.search(r'client-key-data|\btoken:', read_text(kube)):
        results.append(Result(
            'cred-kube', PILLAR, 'Medium', 'Kubernetes credentials are stored in a file',
            short(kube, ctx.home), 'client key or token present',
            'Prefer short-lived tokens and restrict who can read this file.',
            'Credential theft from developer environment'))
    docker = ctx.home / '.docker' / 'config.json'
    if docker.is_file():
        try:
            data = json.loads(read_text(docker))
        except ValueError:
            data = {}
        plain = any(isinstance(v, dict) and v.get('auth') for v in data.get('auths', {}).values())
        if plain and not data.get('credsStore') and not data.get('credHelpers'):
            results.append(Result(
                'cred-docker', PILLAR, 'Medium',
                'Docker registry login is stored in plain text', short(docker, ctx.home),
                'auths entry has an "auth" value',
                'Use a Docker credential helper so logins are not stored in the file.',
                'Credential theft from developer environment'))
    return results


TOKEN_FILES = [
    ('.npmrc', 'cred-npmrc', 'An npm access token is stored in plain text',
     re.compile(r'_authToken\s*=\s*(?!\$\{)\S{8,}')),
    ('.pypirc', 'cred-pypirc', 'A PyPI password or token is stored in plain text',
     re.compile(r'(?i)password\s*[=:]\s*(?!<)\S{4,}')),
    ('.netrc', 'cred-netrc', 'A login password is stored in plain text (.netrc)',
     re.compile(r'(?i)\bpassword\s+\S{4,}')),
    ('.git-credentials', 'cred-git-credentials', 'Git passwords are stored in plain text',
     re.compile(r'https?://[^/\s:@]+:[^@\s]{3,}@')),
]


def check_token_files(ctx):
    results = []
    for name, check_id, title, pattern in TOKEN_FILES:
        path = ctx.home / name
        for line in read_text(path).splitlines() if path.is_file() else []:
            if pattern.search(line):
                results.append(Result(
                    check_id, PILLAR, 'High', title, short(path, ctx.home), scrub(line),
                    'Remove the secret from the file, revoke it, and use a credential '
                    'helper or environment variable instead.',
                    'Credential theft from developer environment'))
                break
    return results


def check_git_config(ctx):
    results = []
    for path in (ctx.home / '.gitconfig', ctx.home / '.config' / 'git' / 'config'):
        text = read_text(path) if path.is_file() else ''
        where = short(path, ctx.home)
        rules = [
            (r'helper\s*=\s*store\b', 'git-cred-store', 'High',
             'Git saves passwords in plain text', 'credential.helper = store',
             'Use the Git Credential Manager (helper = manager) instead.'),
            (r'sslVerify\s*=\s*false', 'git-ssl-off', 'High',
             'Git TLS certificate checking is turned off', 'http.sslVerify = false',
             'Turn it back on and install the missing certificate instead.'),
            (r'directory\s*=\s*\*', 'git-safe-all', 'Medium',
             'Git trusts every folder on this computer', 'safe.directory = *',
             'List only the specific folders you trust.'),
        ]
        for pattern, check_id, severity, title, evidence, fix in rules:
            if re.search(pattern, text):
                results.append(Result(check_id, PILLAR, severity, title, where, evidence, fix,
                                      'Credential theft from developer environment'))
    return results