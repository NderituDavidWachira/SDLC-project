"""Find out which programs are running, so only open apps are scanned."""
import csv
import io
import os
import shutil
import subprocess  # nosec B404
import time
from pathlib import Path

_cache = {'at': 0.0, 'value': None}


def parse_tasklist(text):
    """Windows `tasklist /FO CSV /NH` output -> set of lower-case image names."""
    return {row[0].strip().lower() for row in csv.reader(io.StringIO(text)) if row}


def parse_ps(text):
    """`ps -A -o comm=` output -> set of lower-case program names (paths reduced)."""
    return {Path(line.strip()).name.lower() for line in text.splitlines() if line.strip()}


def _run(args):
    return subprocess.run(  # nosec B603
        args, capture_output=True, text=True, encoding='utf-8', errors='replace',
        timeout=15, check=False).stdout


def list_programs():
    """Set of running program names (lower case), or None if the list cannot be read."""
    try:
        if os.name == 'nt':
            exe = shutil.which('tasklist')
            names = parse_tasklist(_run([exe, '/FO', 'CSV', '/NH'])) if exe else set()
        else:
            exe = shutil.which('ps')
            names = parse_ps(_run([exe, '-A', '-o', 'comm='])) if exe else set()
    except (OSError, subprocess.SubprocessError):
        return None
    return names or None


def running_programs(ttl=5):
    """Cached for a few seconds so loading the dashboard stays fast."""
    now = time.monotonic()
    if _cache['at'] and now - _cache['at'] < ttl:
        return _cache['value']
    _cache['at'], _cache['value'] = now, list_programs()
    return _cache['value']