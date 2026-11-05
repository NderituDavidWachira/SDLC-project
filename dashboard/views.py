from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Count
from django.views.generic import TemplateView

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
        qs = Finding.objects.all()
        if pillar:
            qs = qs.filter(pillar=pillar)
        if not show_all:
            qs = qs.filter(status=Finding.Status.OPEN)
        rows = sorted(qs[:500], key=lambda f: (RANK[f.severity], -f.last_seen.timestamp()))
        ctx.update(
            summaries=summaries, totals=totals, open_total=sum(totals.values()),
            findings=rows[:MAX_ROWS], pillar=pillar, pillar_name=PILLAR_NAMES.get(pillar, ''),
            show_all=show_all, last_scan=Scan.objects.filter(finished_at__isnull=False).first(),
            can_scan=user.has_role('admin', 'analyst'),
            can_change=user.has_role('admin', 'analyst', 'devops'),
            chart_pillar=charts.findings_by_pillar(
                [s['name'] for s in summaries],
                {sev: [s['counts'][sev] for s in summaries] for sev in SEVERITIES}),
            chart_severity=charts.severity_donut(totals),
        )
        return ctx
