from urllib.parse import urlencode

from django.conf import settings
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Count
from django.views.generic import TemplateView

from scanner.checks import AREA_LABELS, AREAS, CHECKS, DEFAULT_AREAS
from scanner.constants import PILLAR_NAMES, PILLARS, SEVERITIES
from scanner.models import Finding, Scan
from scanner.risk import risk_level, risk_score

from . import charts

MAX_ROWS = 100
RANK = {s: i for i, s in enumerate(SEVERITIES)}


def pillar_summaries():
    open_qs = Finding.objects.filter(status=Finding.Status.OPEN)
    data = {slug: dict.fromkeys(SEVERITIES, 0) for slug, _ in PILLARS}
    for row in open_qs.values('pillar', 'severity').annotate(n=Count('id')):
        data[row['pillar']][row['severity']] = row['n']
    out = []
    for slug, name in PILLARS:
        counts = data[slug]
        score = risk_score([s for s, n in counts.items() for _ in range(n)])
        out.append({'slug': slug, 'name': name, 'counts': counts, 'open': sum(counts.values()),
                    'score': score, 'level': risk_level(score)})
    return out


class DashboardView(LoginRequiredMixin, TemplateView):
    template_name = 'dashboard/dashboard.html'

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        user = self.request.user
        summaries = pillar_summaries()
        totals = dict.fromkeys(SEVERITIES, 0)
        for s in summaries:
            for sev, n in s['counts'].items():
                totals[sev] += n
        pillar = self.request.GET.get('pillar')
        pillar = pillar if pillar in PILLAR_NAMES else ''
        show_all = self.request.GET.get('show') == 'all'
        area = self.request.GET.get('area', '')
        area = area if area in AREA_LABELS else ''
        only_last = self.request.GET.get('scan') == 'last'
        last_scan = Scan.objects.filter(finished_at__isnull=False).first()
        qs = Finding.objects.all()
        if pillar:
            qs = qs.filter(pillar=pillar)
        if not show_all:
            qs = qs.filter(status=Finding.Status.OPEN)
        if area:
            qs = qs.filter(source__in=[c.id for c in CHECKS if c.area == area])
        if only_last and last_scan:
            qs = qs.filter(last_seen__gte=last_scan.started_at)
        keep = {k: v for k, v in (('area', area), ('scan', 'last' if only_last else ''),
                                  ('show', 'all' if show_all else '')) if v}
        chosen = set(self.request.session.get('scan_areas', DEFAULT_AREAS))
        machine_on = settings.SDLCGUARD_SCAN_MACHINE
        groups = [
            ('Your computer', [{'a': a, 'on': a.slug in chosen and machine_on,
                                'disabled': not machine_on}
                               for a in AREAS if a.group == 'computer']),
            ('Your projects', [{'a': a, 'on': a.slug in chosen, 'disabled': False}
                               for a in AREAS if a.group == 'project']),
        ]
        selected = sum(1 for _title, items in groups for it in items if it['on'])
        last_found, last_areas = 0, ''
        if last_scan:
            last_found = Finding.objects.filter(last_seen__gte=last_scan.started_at).count()
            last_areas = ', '.join(AREA_LABELS[a] for a in last_scan.areas.split(',')
                                   if a in AREA_LABELS) or 'all areas'
        rows = sorted(qs[:500], key=lambda f: (RANK[f.severity], -f.last_seen.timestamp()))
        ctx.update(
            summaries=summaries, totals=totals, open_total=sum(totals.values()),
            findings=rows[:MAX_ROWS], pillar=pillar, pillar_name=PILLAR_NAMES.get(pillar, ''),
            show_all=show_all, area_groups=groups, machine_on=machine_on,
            area=area, only_last=only_last, area_options=AREAS, selected=selected,
            total_areas=len(AREAS), last_found=last_found, last_areas=last_areas,
            keep_qs=urlencode(keep), last_scan=last_scan,
            can_scan=user.has_role('admin', 'analyst'),
            can_change=user.has_role('admin', 'analyst', 'devops'),
            chart_pillar=charts.findings_by_pillar(
                [s['name'] for s in summaries],
                {sev: [s['counts'][sev] for s in summaries] for sev in SEVERITIES}),
            chart_severity=charts.severity_donut(totals),
        )
        return ctx