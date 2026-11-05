from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver

from .utils import record


@receiver(user_logged_in)
def on_login(sender, request, user, **kwargs):
    record(request, 'login', username=user.username)


@receiver(user_logged_out)
def on_logout(sender, request, user, **kwargs):
    if user:
        record(request, 'logout', username=user.username)


@receiver(user_login_failed)
def on_login_failed(sender, credentials, request=None, **kwargs):
    if request is not None:
        record(request, 'login_failed', username=str(credentials.get('username', ''))[:150])
