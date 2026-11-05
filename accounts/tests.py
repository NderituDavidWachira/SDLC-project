from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase
from django.urls import reverse

from audit.models import AuditLog


class LoginTests(TestCase):
    def setUp(self):
        cache.clear()
        get_user_model().objects.create_user('ana', password='Str0ng!pass', role='analyst')

    def test_valid_login_redirects_to_dashboard_and_is_audited(self):
        r = self.client.post(reverse('login'), {'username': 'ana', 'password': 'Str0ng!pass'})
        self.assertRedirects(r, reverse('dashboard'), fetch_redirect_response=False)
        self.assertTrue(AuditLog.objects.filter(username='ana', action='login').exists())

    def test_wrong_password_rejected_and_logged(self):
        r = self.client.post(reverse('login'), {'username': 'ana', 'password': 'nope'})
        self.assertEqual(r.status_code, 200)
        self.assertNotIn('_auth_user_id', self.client.session)
        self.assertTrue(AuditLog.objects.filter(action='login_failed').exists())

    def test_lockout_after_repeated_failures(self):
        for _ in range(5):
            self.client.post(reverse('login'), {'username': 'ana', 'password': 'bad'})
        r = self.client.post(reverse('login'), {'username': 'ana', 'password': 'Str0ng!pass'})
        self.assertEqual(r.status_code, 429)

    def test_default_role_is_least_privilege(self):
        user = get_user_model().objects.create_user('new', password='Str0ng!pass')
        self.assertEqual(user.role, 'auditor')
