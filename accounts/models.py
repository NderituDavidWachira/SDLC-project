from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    """Custom user with a role for role-based access control (RBAC)."""

    class Role(models.TextChoices):
        ADMIN = 'admin', 'Admin'
        ANALYST = 'analyst', 'Security Analyst'
        DEVOPS = 'devops', 'DevOps Engineer'
        AUDITOR = 'auditor', 'Auditor'

    # Least privilege by default: new accounts are read-only auditors.
    role = models.CharField(max_length=10, choices=Role.choices, default=Role.AUDITOR)
    mfa_enabled = models.BooleanField(default=False)  # reserved for future MFA

    def has_role(self, *roles):
        return self.is_superuser or self.role in roles

    def __str__(self):
        return self.username
