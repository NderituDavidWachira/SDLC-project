"""Production checks: unsafe Django settings in the scanned projects."""
import re

from .base import Result, read_text, rel, repo_files

PILLAR = 'production'
RULES = [
    ('prod-debug', 'High', 'Django DEBUG is hard-coded to True',
     re.compile(r'^DEBUG\s*=\s*True\b', re.M),
     'Read DEBUG from an environment variable and default to False.'),
    ('prod-hosts', 'High', 'ALLOWED_HOSTS accepts any host',
     re.compile(r'^ALLOWED_HOSTS\s*=\s*\[\s*[\'"]\*[\'"]\s*\]', re.M),
     'List only your real host names.'),
    ('prod-secret-key', 'High', 'SECRET_KEY is written in the settings file',
     re.compile(r'^SECRET_KEY\s*=\s*[\'"][^\'"]+[\'"]', re.M),
     'Load it from the environment and rotate the exposed key.'),
    ('prod-insecure-cookie', 'Medium', 'Cookies or redirects are not HTTPS-only',
     re.compile(r'^(SESSION_COOKIE_SECURE|CSRF_COOKIE_SECURE|SECURE_SSL_REDIRECT)'
                r'\s*=\s*False', re.M),
     'Turn the secure setting on for production.'),
]


def check_django_settings(ctx):
    results = []
    for root in ctx.repo_paths:
        for path in repo_files(root):
            if path.name != 'settings.py':
                continue
            text = read_text(path)
            if 'INSTALLED_APPS' not in text:
                continue
            for check_id, severity, title, pattern, fix in RULES:
                match = pattern.search(text)
                if match:
                    results.append(Result(
                        check_id, PILLAR, severity, title, rel(path, root),
                        match.group(0).split('=')[0].strip() + ' = ...', fix,
                        'Unsafe production configuration'))
    return results
