"""Registry of all checks. `machine` checks look at the developer's own computer."""
from dataclasses import dataclass
from typing import Callable

from . import dependencies, pipelines, production, repo, terminal, vscode


@dataclass(frozen=True)
class Check:
    id: str
    label: str
    machine: bool
    run: Callable


CHECKS = [
    Check('terminal-history', 'Terminal history', True, terminal.check_history),
    Check('terminal-env', 'Terminal environment', True, terminal.check_environment),
    Check('vscode-settings', 'VS Code settings', True, vscode.check_settings),
    Check('vscode-extensions', 'VS Code extensions', True, vscode.check_extensions),
    Check('vscode-tasks', 'VS Code workspace tasks', False, vscode.check_workspace_tasks),
    Check('repo-secrets', 'Secrets in the repository', False, repo.check_secrets),
    Check('repo-env', '.env file in Git', False, repo.check_env_file),
    Check('repo-hooks', 'Git hooks', False, repo.check_git_hooks),
    Check('repo-commits', 'Commit signing', False, repo.check_unsigned_commits),
    Check('github-protection', 'GitHub branch protection', False, repo.check_branch_protection),
    Check('pipelines', 'CI/CD pipeline files', False, pipelines.check_pipelines),
    Check('requirements', 'Python dependencies', False, dependencies.check_requirements),
    Check('npm', 'npm dependencies', False, dependencies.check_node_packages),
    Check('docker', 'Dockerfiles', False, dependencies.check_dockerfiles),
    Check('django-settings', 'Django settings', False, production.check_django_settings),
]
