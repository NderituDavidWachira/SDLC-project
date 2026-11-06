"""Known-vulnerability check using pip-audit (needs internet, slower)."""
import json
import re
import subprocess  # nosec B404
import sys
import tempfile
from pathlib import Path

from .base import Result, read_text, rel, repo_files

PILLAR = 'registry'
REQ_FILE = re.compile(r'(^|/)requirements[^/]*\.txt$')
MAX_RESULTS = 25


def _run_pip_audit(requirements_text):
    """Audit pinned requirements. Returns pip-audit's JSON as a dict."""
    with tempfile.TemporaryDirectory() as tmp:
        req = Path(tmp) / 'requirements.txt'
        req.write_text(requirements_text, encoding='utf-8')
        try:
            proc = subprocess.run(  # nosec B603
                [sys.executable, '-m', 'pip_audit', '-r', str(req), '--no-deps',
                 '--disable-pip', '--format', 'json', '--progress-spinner', 'off'],
                capture_output=True, text=True, encoding='utf-8', errors='replace',
                timeout=120, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError(f'pip-audit could not run ({type(exc).__name__})') from exc
    if 'No module named' in proc.stderr:
        raise RuntimeError('pip-audit is not installed (pip install pip-audit)')
    try:
        return json.loads(proc.stdout)
    except ValueError as exc:
        raise RuntimeError('pip-audit gave no result (are you online?)') from exc


def check_dependency_vulns(ctx):
    results = []
    for root in ctx.repo_paths:
        for path in repo_files(root):
            name = rel(path, root)
            if not REQ_FILE.search(name):
                continue
            pinned = [ln.split('#')[0].strip() for ln in read_text(path).splitlines()
                      if '==' in ln.split('#')[0] and not ln.strip().startswith('-')]
            if not pinned:
                continue
            report = _run_pip_audit('\n'.join(pinned) + '\n')
            for dep in report.get('dependencies', []):
                for vuln in dep.get('vulns', []):
                    fixes = ', '.join(vuln.get('fix_versions', [])) or 'no fix published yet'
                    results.append(Result(
                        'vuln-package', PILLAR, 'High',
                        f'{dep["name"]} {dep["version"]} has a known vulnerability '
                        f'({vuln["id"]})', name, f'Fixed in: {fixes}',
                        'Upgrade to a patched version and re-run the tests.',
                        'Vulnerable dependency', key=f'{dep["name"]}{dep["version"]}{vuln["id"]}'))
    return results[:MAX_RESULTS]