from __future__ import annotations

from vpsdeploy.core.runtime import DeploymentContext, run, section
from vpsdeploy.tasks.certificates import CertificateTask
from vpsdeploy.tasks.diagnostics import DiagnosticsTask
from vpsdeploy.tasks.dns_records import DNSRecordsTask
from vpsdeploy.tasks.fail2ban import Fail2BanTask
from vpsdeploy.tasks.prerequisites import PrerequisitesTask
from vpsdeploy.tasks.ipv6_connectivity import IPv6ConnectivityTask
from vpsdeploy.tasks.proxy_stack_recreate import ProxyStackTask
from vpsdeploy.tasks.node_config import NodeConfigTask, NodeVerifyTask
from vpsdeploy.tasks.wg_easy import WgEasyTask
from vpsdeploy.tasks.ssh_hardening import SSHHardeningTask
from vpsdeploy.tasks.ufw import UFWTask
from vpsdeploy.tasks.sub2api import Sub2APITask
from vpsdeploy.tasks.system_hardening import SystemHardeningTask
from vpsdeploy.tasks.unattended_upgrades import UnattendedUpgradesTask


DEPLOY_TASKS = [
    PrerequisitesTask(),
    IPv6ConnectivityTask(),
    DNSRecordsTask(),
    CertificateTask(),
    ProxyStackTask(),
    NodeConfigTask(),
    NodeVerifyTask(),
    WgEasyTask(),
    Sub2APITask(),
    SSHHardeningTask(),
    UFWTask(),
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
    run(["docker", "compose", "pull"], cwd=stack)
    run(["docker", "compose", "up", "-d", "--remove-orphans"], cwd=stack)
    sub2api = context.config.get('sub2api', {})
    if isinstance(sub2api, dict) and bool(sub2api.get('enabled', False)):
        from pathlib import Path
        sub_dir = Path(str(sub2api.get('install_dir', '/opt/sub2api'))).resolve()
        if (sub_dir / 'docker-compose.yml').is_file():
            run(["docker", "compose", "pull"], cwd=sub_dir)
            run(["docker", "compose", "up", "-d", "--remove-orphans"], cwd=sub_dir)
    if bool(section(context.config, "stack").get("prune_dangling_images", True)):
        run(["docker", "image", "prune", "-f"])
    NodeConfigTask().execute(context)
    NodeVerifyTask().execute(context)
    WgEasyTask().execute(context)
