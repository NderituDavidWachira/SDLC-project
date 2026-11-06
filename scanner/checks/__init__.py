"""Registry of scan areas and the checks inside them."""
from dataclasses import dataclass
from typing import Callable

from . import (credentials, dependencies, pipelines, production, repo, sublime, terminal,
               vscode, vulns, browser)


@dataclass(frozen=True)
class Area:
    slug: str
    label: str
    group: str  # 'computer' or 'project'
    description: str
    default: bool = True


@dataclass(frozen=True)
class Check:
    id: str
    label: str
    area: str
    machine: bool
    run: Callable


AREAS = [
    Area('terminal', 'Terminal', 'computer',
         'Risky commands in shell history, secrets in the environment'),
    Area('vscode', 'VS Code', 'computer', 'Settings, extensions, tasks that auto-run'),
    Area('sublime', 'Sublime Text', 'computer', 'Installed packages, risky build systems'),
    Area('browser', 'Web browser', 'computer',
         'Chrome, Edge, Brave, Firefox: broad extensions, Safe Browsing'),
    Area('credentials', 'Keys and logins', 'computer',
         'SSH keys, AWS/Kubernetes/Docker logins, npm and PyPI tokens, Git password storage'),
    Area('git', 'Git and GitHub', 'project',
         'Hooks, signed commits, .env in Git, GitHub branch protection'),
    Area('secrets', 'Secrets in code', 'project',
         'Tokens, passwords and private keys in project files'),
    Area('pipelines', 'CI/CD pipelines', 'project',
         'GitHub Actions, CircleCI, Jenkins, GitLab files'),
    Area('dependencies', 'Dependencies', 'project',
         'Unpinned packages, risky package indexes'),
    Area('containers', 'Containers', 'project', 'Dockerfile base images, running as root'),
    Area('production', 'Production settings', 'project',
         'Django DEBUG, allowed hosts, secret key, cookies'),
    Area('vulns', 'Known vulnerabilities', 'project',
         'Checks pinned Python packages against a public database (needs internet, slower)',
         default=False),
]
AREA_LABELS = {a.slug: a.label for a in AREAS}
DEFAULT_AREAS = [a.slug for a in AREAS if a.default]

CHECKS = [
    Check('terminal-history', 'Terminal history', 'terminal', True, terminal.check_history),
    Check('terminal-env', 'Terminal environment', 'terminal', True, terminal.check_environment),
    Check('vscode-settings', 'VS Code settings', 'vscode', True, vscode.check_settings),
    Check('vscode-extensions', 'VS Code extensions', 'vscode', True, vscode.check_extensions),
    Check('vscode-tasks', 'VS Code workspace tasks', 'vscode', False, vscode.check_workspace_tasks),
    Check('sublime-packages', 'Sublime packages', 'sublime', True, sublime.check_packages),
    Check('sublime-builds', 'Sublime build systems', 'sublime', False, sublime.check_builds),
    Check('browser-extensions', 'Browser extensions', 'browser', True, browser.check_extensions),
    Check('browser-safe', 'Browser Safe Browsing', 'browser', True, browser.check_safe_browsing),
    Check('ssh-keys', 'SSH keys', 'credentials', True, credentials.check_ssh_keys),
    Check('cloud-logins', 'Cloud logins', 'credentials', True, credentials.check_cloud_credentials),
    Check('token-files', 'Token files', 'credentials', True, credentials.check_token_files),
    Check('git-config', 'Git settings', 'credentials', True, credentials.check_git_config),
    Check('repo-env', '.env file in Git', 'git', False, repo.check_env_file),
    Check('repo-hooks', 'Git hooks', 'git', False, repo.check_git_hooks),
    Check('repo-commits', 'Commit signing', 'git', False, repo.check_unsigned_commits),
    Check('github-protection', 'GitHub branch protection', 'git', False,
          repo.check_branch_protection),
    Check('repo-secrets', 'Secrets in the repository', 'secrets', False, repo.check_secrets),
    Check('pipelines', 'CI/CD pipeline files', 'pipelines', False, pipelines.check_pipelines),
    Check('requirements', 'Python dependencies', 'dependencies', False,
          dependencies.check_requirements),
    Check('npm', 'npm dependencies', 'dependencies', False, dependencies.check_node_packages),
    Check('docker', 'Dockerfiles', 'containers', False, dependencies.check_dockerfiles),
    Check('django-settings', 'Django settings', 'production', False,
          production.check_django_settings),
    Check('dependency-vulns', 'Known vulnerabilities', 'vulns', False,
          vulns.check_dependency_vulns),
]