from django.contrib import messages
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.views import View

from accounts.mixins import RoleRequiredMixin
from audit.utils import record

from .checks import AREA_LABELS
from .engine import clean_areas, run_scan
from .models import Finding, Scan


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
        skipped = [a for a in scan.skipped.split(',') if a]
        ran = [a for a in areas if a not in skipped]
        if skipped:
            messages.warning(request, 'Not scanned because the app is not open: '
                             + ', '.join(AREA_LABELS[a] for a in skipped)
                             + '. Open it and scan again.')
        if 'NOT FOUND' in scan.details:
            messages.error(request, 'A scan folder does not exist. See "What was checked".')
        if scan.errors:
            messages.error(request, 'Some checks could not run: ' + scan.errors)
        if not ran:
            return redirect(reverse('dashboard'))
        names = ', '.join(AREA_LABELS[a] for a in ran)
        found = Finding.objects.filter(last_seen__gte=scan.started_at).count()
        messages.success(request, f'Scan finished ({names}): {found} found, '
                                  f'{scan.new_count} new, {scan.fixed_count} fixed.')
        return redirect(reverse('dashboard') + '?scan=last')  # show what THIS scan found


class ClearDataView(RoleRequiredMixin, View):
    """Start fresh: delete all findings and scan history. POST only, so that simply
    reloading a page can never delete anything. The audit log is kept."""
    allowed_roles = ('admin', 'analyst')
    http_method_names = ['post']

    def post(self, request):
        with transaction.atomic():
            findings, scans = Finding.objects.count(), Scan.objects.count()
            Finding.objects.all().delete()
            Scan.objects.all().delete()
        record(request, 'data_cleared', f'{findings} findings, {scans} scans')
        messages.success(request, 'All findings and scan history were cleared. '
                                  'Choose what to scan and press Run scan.')
        return redirect(reverse('dashboard'))


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