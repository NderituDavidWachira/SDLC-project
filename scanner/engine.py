"""Run every check, then sync the results into the database."""
import logging
import os
from dataclasses import replace
from pathlib import Path

from django.conf import settings
from django.utils import timezone

from .checks import AREA_BY_SLUG, AREA_LABELS, CHECKS, DEFAULT_AREAS
from .checks.base import ScanContext, repo_files
from .models import Finding, Scan
from .processes import running_programs

log = logging.getLogger(__name__)


def build_context():
    return ScanContext(
        repo_paths=[Path(p) for p in settings.SDLCGUARD_SCAN_PATHS],
        home=Path.home(),
        scan_machine=settings.SDLCGUARD_SCAN_MACHINE,
        env=dict(os.environ),
        github_repo=settings.SDLCGUARD_GITHUB_REPO,
        github_token=settings.SDLCGUARD_GITHUB_TOKEN,
        trusted_publishers=tuple(settings.SDLCGUARD_TRUSTED_VSCODE_PUBLISHERS),
        running=running_programs() if settings.SDLCGUARD_ONLY_OPEN_APPS else None,
    )


def clean_areas(areas):
    """Keep only known area slugs, in registry order. None means the default set."""
    if areas is None:
        return list(DEFAULT_AREAS)
    wanted = set(areas)
    return [slug for slug in AREA_LABELS if slug in wanted]


def app_is_open(area, running):
    """True if the area has no app, the program list is unavailable, or its app is running."""
    return not area.apps or running is None or bool(set(area.apps) & running)


def collect(ctx, areas):
    """Run the checks in `areas`. Returns (results, ids of checks not run, errors, skipped)."""
    results, not_run, errors, reasons, ran = {}, set(), [], {}, set()
    for check in CHECKS:
        area = AREA_BY_SLUG[check.area]
        if check.area not in areas:
            not_run.add(check.id)
            continue
        if check.machine and not ctx.scan_machine:
            not_run.add(check.id)
            reasons[check.area] = 'computer scanning is switched off'
            continue
        if not app_is_open(area, ctx.running):
            not_run.add(check.id)
            reasons[check.area] = f'{area.label} is not open'
            continue
        ran.add(check.area)
        try:
            for r in check.run(ctx):
                r = replace(r, source=check.id)
                results[r.fingerprint] = r
        except Exception as exc:  # one broken check must not stop the whole scan
            not_run.add(check.id)
            log.exception('Scan check %s failed', check.id)
            errors.append(f'{check.id}: {type(exc).__name__}: {str(exc)[:100]}')
    skipped = {slug: why for slug, why in reasons.items() if slug not in ran}
    return results, not_run, errors, skipped


def describe(ctx, areas, results, skipped):
    """Plain-English lines explaining what this scan looked at."""
    area_of = {c.id: c.area for c in CHECKS}
    lines = []
    for slug in areas:
        if slug in skipped:
            lines.append(f'{AREA_LABELS[slug]}: SKIPPED ({skipped[slug]})')
        else:
            n = sum(1 for r in results.values() if area_of.get(r.source) == slug)
            lines.append(f'{AREA_LABELS[slug]}: checked, {n} finding(s)')
    for root in ctx.repo_paths:
        if not Path(root).is_dir():
            lines.append(f'Folder NOT FOUND: {root}')
        else:
            lines.append(f'Folder scanned: {root} ({len(repo_files(root))} files read)')
    if ctx.running is None and settings.SDLCGUARD_ONLY_OPEN_APPS:
        lines.append('Could not list running programs, so no app was treated as closed.')
    return lines


def run_scan(user=None, ctx=None, areas=None):
    """Scan the chosen areas. Findings from areas that were not scanned stay untouched."""
    ctx = ctx or build_context()
    areas = clean_areas(areas)
    scan = Scan.objects.create(started_by=user if getattr(user, 'pk', None) else None,
                               areas=','.join(areas))
    results, not_run, errors, skipped = collect(ctx, areas)
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
    scan.skipped = ','.join(s for s in areas if s in skipped)
    scan.details = '\n'.join(describe(ctx, areas, results, skipped))
    scan.save()
    return scan