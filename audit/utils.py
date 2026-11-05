from .models import AuditLog


def record(request, action, detail='', username=None):
    """Write an audit entry. Never pass passwords or tokens in `detail`."""
    user = getattr(request, 'user', None)
    authed = bool(user and user.is_authenticated)
    AuditLog.objects.create(
        user=user if authed else None,
        username=username if username is not None else (user.username if authed else ''),
        action=action,
        detail=detail[:300],
        ip_address=request.META.get('REMOTE_ADDR') or None,
    )
