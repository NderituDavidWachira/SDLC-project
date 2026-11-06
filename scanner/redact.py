"""Secret detection and redaction. Secrets are NEVER stored: only masked evidence."""
import re

TOKEN_PATTERNS = [
    ('GitHub token', re.compile(r'gh[pousr]_[A-Za-z0-9]{36,}')),
    ('AWS access key', re.compile(r'AKIA[0-9A-Z]{16}')),
    ('Slack token', re.compile(r'xox[baprs]-[A-Za-z0-9-]{10,}')),
]
PRIVATE_KEY = re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----')
GENERIC = re.compile(
    r'(?i)([A-Za-z0-9_.-]*(?:password|passwd|secret|token|api[_-]?key)[A-Za-z0-9_]*)'
    r'\s*[=:]\s*([\'"]?)([^\s\'"]{8,})')
FLAG_VALUE = re.compile(r'(?i)(--password|--token|-Password)(\s+)(\S{4,})')
URL_CREDS = re.compile(r'(://[^/\s:@]+:)([^@\s]{3,})(@)')
PLACEHOLDERS = ('os.', 'env', '${', '{{', '<', 'your', 'change', 'example', 'xxx',
                'todo', 'none', 'null', 'true', 'false', 'getenv', 'process.',
                'dev-only', 'ci-only', 'build-only', 'not-a-real')
CODE_CHARS = re.compile(r'[(){}\[\]$]')
DOTTED_NAME = re.compile(r'[A-Za-z_]\w*(\.[A-Za-z_]\w*)+,?')


def mask(value):
    return value[:4] + '****' if len(value) > 4 else '****'


def _generic_value_ok(value, quoted):
    """True when `value` looks like a real secret rather than a placeholder or code."""
    low = value.lower()
    if low.startswith(PLACEHOLDERS) or CODE_CHARS.search(value):
        return False
    return quoted or not DOTTED_NAME.fullmatch(value)  # e.g. settings.MY_TOKEN


def find_secrets(line):
    """Return a list of (label, severity) for secrets found in one line of text."""
    found = []
    for label, pattern in TOKEN_PATTERNS:
        if pattern.search(line):
            found.append((label, 'Critical'))
    if PRIVATE_KEY.search(line):
        found.append(('Private key', 'Critical'))
    for m in GENERIC.finditer(line):
        if _generic_value_ok(m.group(3), bool(m.group(2))):
            found.append(('Hard-coded password or token', 'High'))
            break
    for m in FLAG_VALUE.finditer(line):
        if _generic_value_ok(m.group(3).strip('\'"'), True):
            found.append(('Password or token passed on a command line', 'High'))
            break
    return found


def scrub(line, limit=120):
    """Mask every secret-looking value in `line` and shorten it for display."""
    text = ' '.join(line.split())
    for _label, pattern in TOKEN_PATTERNS:
        text = pattern.sub(lambda m: mask(m.group()), text)
    text = GENERIC.sub(
        lambda m: m.group(0).replace(m.group(3), mask(m.group(3)))
        if _generic_value_ok(m.group(3), bool(m.group(2))) else m.group(0), text)
    text = FLAG_VALUE.sub(lambda m: m.group(1) + m.group(2) + mask(m.group(3)), text)
    text = URL_CREDS.sub(lambda m: m.group(1) + '****' + m.group(3), text)
    return text[:limit] + ('...' if len(text) > limit else '')