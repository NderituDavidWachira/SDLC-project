"""Run every check, then sync the results into the database."""
import os
from dataclasses import replace
from pathlib import Path

from django.conf import settings
from django.utils import timezone

from .checks import AREA_LABELS, CHECKS, DEFAULT_AREAS
from .checks.base import ScanContext
from .models import Finding, Scan


def build_context():
    return ScanContext(
        repo_paths=[Path(p) for p in settings.SDLCGUARD_SCAN_PATHS],
        home=Path.home(),
        scan_machine=settings.SDLCGUARD_SCAN_MACHINE,
        env=dict(os.environ),
        github_repo=settings.SDLCGUARD_GITHUB_REPO,
        github_token=settings.SDLCGUARD_GITHUB_TOKEN,
        trusted_publishers=tuple(settings.SDLCGUARD_TRUSTED_VSCODE_PUBLISHERS),
    )


def clean_areas(areas):
    """Keep only known area slugs, in registry order. None means the default set."""
    if areas is None:
        return list(DEFAULT_AREAS)
    wanted = set(areas)
    return [slug for slug in AREA_LABELS if slug in wanted]


def collect(ctx, areas):
    """Run the checks in `areas`. Returns (results, ids of checks not run, errors)."""
    results, not_run, errors = {}, set(), []
    for check in CHECKS:
        if check.area not in areas or (check.machine and not ctx.scan_machine):
            not_run.add(check.id)
            continue
        try:
            for r in check.run(ctx):
                r = replace(r, source=check.id)
                results[r.fingerprint] = r
        except Exception as exc:  # one broken check must not stop the whole scan
            not_run.add(check.id)
            errors.append(f'{check.id}: {type(exc).__name__}')
    return results, not_run, errors


def run_scan(user=None, ctx=None, areas=None):
    """Scan the chosen areas. Findings from areas that were not scanned stay untouched."""
    ctx = ctx or build_context()
    areas = clean_areas(areas)
    scan = Scan.objects.create(started_by=user if getattr(user, 'pk', None) else None,
                               areas=','.join(areas))
    results, not_run, errors = collect(ctx, areas)
    now = timezone.now()
    new = 0
    for fp, r in results.items():
        obj, created = Finding.objects.get_or_create(fingerprint=fp, defaults={
            'source': r.source, 'check_id': r.check_id, 'pillar': r.pillar,
            'severity': r.severity, 'title': r.title, 'location': r.location,
            'evidence': r.evidence, 'fix': r.fix, 'technique': r.technique})
        if created:
            new += 1
            continue
        obj.last_seen, obj.evidence, obj.severity = now, r.evidence, r.severity
        if obj.status == Finding.Status.RESOLVED:  # it came back
            obj.status, obj.resolved_at = Finding.Status.OPEN, None
            new += 1
        obj.save()
    gone = (Finding.objects.filter(status=Finding.Status.OPEN)
            .exclude(fingerprint__in=results.keys()).exclude(source__in=not_run))
    fixed = gone.update(status=Finding.Status.RESOLVED, resolved_at=now)
    scan.finished_at = timezone.now()
    scan.new_count, scan.fixed_count = new, fixed
    scan.open_count = Finding.objects.filter(status=Finding.Status.OPEN).count()
    scan.errors = '; '.join(errors)
    scan.save()
    return scan