import secrets

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand

USERS = [('admin1', 'admin'), ('analyst1', 'analyst'), ('devops1', 'devops'),
         ('auditor1', 'auditor')]


class Command(BaseCommand):
    help = 'Create the four demo users (Admin, Analyst, DevOps, Auditor).'

    def add_arguments(self, parser):
        parser.add_argument('--password', help='Password for the demo users (random if omitted)')

    def handle(self, *args, **opts):
        password = opts['password'] or secrets.token_urlsafe(12)
        User = get_user_model()
        for username, role in USERS:
            user, created = User.objects.get_or_create(
                username=username, defaults={'role': role, 'is_staff': role == 'admin',
                                             'email': f'{username}@example.com'})
            if created:
                user.set_password(password)
                user.save()
        self.stdout.write(self.style.SUCCESS('Users ready: admin1, analyst1, devops1, auditor1'))
        if not opts['password']:
            self.stdout.write(f'Password: {password}')
