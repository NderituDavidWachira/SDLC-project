from django.views.generic import ListView

from accounts.mixins import RoleRequiredMixin

from .models import AuditLog


class AuditLogView(RoleRequiredMixin, ListView):
    allowed_roles = ('admin', 'auditor')
    model = AuditLog
    paginate_by = 30
    template_name = 'audit/auditlog_list.html'
