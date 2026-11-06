from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.views import View

from accounts.mixins import RoleRequiredMixin
from audit.utils import record

from .checks import AREA_LABELS
from .engine import clean_areas, run_scan
from .models import Finding


class RunScanView(RoleRequiredMixin, View):
    allowed_roles = ('admin', 'analyst')

    def post(self, request):
        areas = clean_areas(request.POST.getlist('areas'))
        if not areas:
            messages.error(request, 'Pick at least one area to scan.')
            return redirect(reverse('dashboard'))
        request.session['scan_areas'] = areas
        scan = run_scan(user=request.user, areas=areas)
        record(request, 'scan_run', f'{len(areas)} areas: {scan.new_count} new, '
                                    f'{scan.fixed_count} fixed')
        names = ', '.join(AREA_LABELS[a] for a in areas)
        found = Finding.objects.filter(last_seen__gte=scan.started_at).count()
        messages.success(request, f'Scan finished ({names}): {found} found, '
                                  f'{scan.new_count} new, {scan.fixed_count} fixed.')
        if scan.errors:
            messages.error(request, 'Some checks could not run: ' + scan.errors)
        return redirect(reverse('dashboard') + '?scan=last')  # show what THIS scan found


class FindingStatusView(RoleRequiredMixin, View):
    allowed_roles = ('admin', 'analyst', 'devops')

    def post(self, request, pk):
        finding = get_object_or_404(Finding, pk=pk)
        status = request.POST.get('status')
        if status in Finding.Status.values:
            finding.status = status
            finding.save(update_fields=['status'])
            record(request, 'finding_status', f'finding {pk} -> {status}')
        target = request.POST.get('next', '')
        if not url_has_allowed_host_and_scheme(target, allowed_hosts={request.get_host()}):
            target = reverse('dashboard')
        return redirect(target)