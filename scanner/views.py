from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.views import View

from accounts.mixins import RoleRequiredMixin
from audit.utils import record

from .engine import run_scan
from .models import Finding


class RunScanView(RoleRequiredMixin, View):
    allowed_roles = ('admin', 'analyst')

    def post(self, request):
        scan = run_scan(user=request.user)
        record(request, 'scan_run', f'{scan.new_count} new, {scan.fixed_count} fixed')
        messages.success(request, f'Scan finished: {scan.new_count} new, '
                                  f'{scan.fixed_count} fixed, {scan.open_count} open.')
        if scan.errors:
            messages.error(request, 'Some checks could not run: ' + scan.errors)
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
