from __future__ import annotations

from vpsdeploy.core.runtime import DeploymentContext, run, section
from vpsdeploy.tasks.certificates import CertificateTask
from vpsdeploy.tasks.diagnostics import DiagnosticsTask
from vpsdeploy.tasks.fail2ban import Fail2BanTask
from vpsdeploy.tasks.prerequisites import PrerequisitesTask
from vpsdeploy.tasks.proxy_stack import ProxyStackTask
from vpsdeploy.tasks.ssh_hardening import SSHHardeningTask
from vpsdeploy.tasks.system_hardening import SystemHardeningTask
from vpsdeploy.tasks.unattended_upgrades import UnattendedUpgradesTask


DEPLOY_TASKS = [
    PrerequisitesTask(),
    CertificateTask(),
    ProxyStackTask(),
    SSHHardeningTask(),
    Fail2BanTask(),
    UnattendedUpgradesTask(),
    SystemHardeningTask(),
]


def deploy(context: DeploymentContext, selected: set[str] | None = None) -> None:
    for task in DEPLOY_TASKS:
        if selected and task.name not in selected:
            continue
        task.execute(context)


def status(context: DeploymentContext) -> None:
    DiagnosticsTask().execute(context)


def update(context: DeploymentContext) -> None:
    stack = context.stack_dir
    run(['docker', 'compose', 'pull'], cwd=stack)
    run(['docker', 'compose', 'up', '-d', '--remove-orphans'], cwd=stack)
    if bool(section(context.config, 'stack').get('prune_dangling_images', True)):
        run(['docker', 'image', 'prune', '-f'])
