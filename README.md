# SDLC Guard (simple version)

One dashboard that **scans for security threats itself** across the five SITF pillars of the
code factory. No data entry: press **Run scan now** and it looks at the computer and projects.

## What it checks

| Pillar | Checks |
|---|---|
| Endpoint/IDE | Terminal history (curl-pipe-bash, TLS off, `--no-verify`, credentials typed in commands, extra package indexes, force-push), secrets in environment variables, VS Code settings (Workspace Trust off, automatic tasks), unfamiliar VS Code extensions, tasks that auto-run on folder open, suspicious Git hooks |
| VCS (GitHub) | Secrets in files (tokens, private keys, passwords), `.env` committed, unsigned commits, optional GitHub API check for an unprotected default branch |
| CI/CD | GitHub Actions / CircleCI / Jenkins / GitLab files: `pull_request_target`, cache poisoning pattern, unpinned actions, secrets echoed, curl-pipe-bash, unpinned images |
| Registry | Unpinned Python/npm dependencies, extra or insecure package index (dependency confusion), Docker base image without a fixed version |
| Production | Django `DEBUG=True`, `ALLOWED_HOSTS=["*"]`, hard-coded `SECRET_KEY`, non-HTTPS cookies, containers running as root |

Each finding shows severity, where it is, how to fix it and masked evidence. Findings that
disappear on the next scan are marked **Fixed** automatically.

## Run it (Windows PowerShell)

```powershell
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
$env:DJANGO_DEBUG = "1"
python manage.py migrate
python manage.py seed_users --password "Demo#Pass2026x"
python manage.py runserver
```

Open http://127.0.0.1:8000, sign in (`admin1`, `analyst1`, `devops1`, `auditor1`) and press
**Run scan now**. Restart later with only the `$env:DJANGO_DEBUG` and `runserver` lines.
Command-line scan: `python manage.py run_scan`.

## Demo without exposing your real machine

```powershell
python manage.py create_demo_lab            # makes ..\sdlcguard_demo_lab with FAKE insecure files
$env:SDLCGUARD_SCAN_PATHS = "C:\full\path\to\sdlcguard_demo_lab"
$env:SDLCGUARD_SCAN_MACHINE = "0"           # skip your own history/VS Code for the demo
python manage.py runserver
```

## Roles

| Role | Can do |
|---|---|
| Admin | Run scans, change finding status, audit log |
| Analyst | Run scans, change finding status |
| DevOps | Change finding status (Fixed / Ignore / Reopen) |
| Auditor | Read-only, audit log |

## Privacy and safety rules built in

* Everything is local. The only network call is the optional GitHub check (needs
  `SDLCGUARD_GITHUB_TOKEN`, use a read-only token).
* Secrets are **never stored**: evidence is masked (for example `ghp_****`).
* Scans only the folders in `SDLCGUARD_SCAN_PATHS` (default: this project) plus your own
  home-folder history/VS Code files. Scan **only computers and repositories you own or are
  authorised to check**, and tell your team that shell history is read.
* Add `# sdlcguard:ignore` to a line to suppress a known false positive.

## Developer commands

```bash
python manage.py test                     # 31 tests
coverage run manage.py test && coverage report
flake8 .
bandit -r accounts audit config dashboard scanner -x '*/tests.py' -q
pip-audit -r requirements.txt
```

CI/CD: `.circleci/config.yml`, `Dockerfile`, `scripts/deploy_staging.sh`.

## Not implemented

MFA (the `mfa_enabled` field is reserved), real-time monitoring (scans run when you press the
button or run `run_scan`), malware detection, and a live deploy target.
