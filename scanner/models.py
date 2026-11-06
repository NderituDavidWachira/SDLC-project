from django.conf import settings
from django.db import models
from django.utils import timezone

from .constants import PILLARS, SEVERITIES


class Scan(models.Model):
    started_at = models.DateTimeField(default=timezone.now)
    finished_at = models.DateTimeField(null=True, blank=True)
    started_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
                                   null=True, blank=True)
    new_count = models.PositiveIntegerField(default=0)
    fixed_count = models.PositiveIntegerField(default=0)
    open_count = models.PositiveIntegerField(default=0)
    areas = models.CharField(max_length=300, blank=True)
    errors = models.TextField(blank=True)

    class Meta:
        ordering = ['-started_at']


class Finding(models.Model):
    """A security problem found by the scanner. Evidence is always redacted."""

    class Status(models.TextChoices):
        OPEN = 'open', 'Open'
        RESOLVED = 'resolved', 'Fixed'
        IGNORED = 'ignored', 'Ignored'

    fingerprint = models.CharField(max_length=40, unique=True)
    source = models.CharField(max_length=40)
    check_id = models.CharField(max_length=40)
    pillar = models.CharField(max_length=20, choices=PILLARS)
    severity = models.CharField(max_length=10, choices=[(s, s) for s in SEVERITIES])
    title = models.CharField(max_length=200)
    location = models.CharField(max_length=260)
    evidence = models.CharField(max_length=300, blank=True)
    fix = models.CharField(max_length=300, blank=True)
    technique = models.CharField(max_length=100, blank=True)
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.OPEN)
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-last_seen']

    @property
    def area_label(self):
        from .checks import AREA_LABELS, CHECKS
        area = {c.id: c.area for c in CHECKS}.get(self.source, '')
        return AREA_LABELS.get(area, '')

    def __str__(self):
        return f'{self.severity}: {self.title}'