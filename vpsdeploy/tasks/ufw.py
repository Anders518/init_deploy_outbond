from __future__ import annotations

from typing import Any

from pathlib import Path
import re
import shutil

from vpsdeploy.core.runtime import DeployError, DeploymentContext, FileSnapshot, Task, run, section


def _ufw_config(context: DeploymentContext) -> dict[str, Any]:
    value = section(context.config, 'hardening').get('ufw', {})
    if not isinstance(value, dict):
        raise DeployError('hardening.ufw must be a TOML table')
    return value


def _has_rule(output: str, rule: str) -> bool:
    return re.search(rf'(?<!\d){re.escape(rule)}(?!\d)', output) is not None


class UFWTask(Task):
    name = 'ufw'

    def enabled(self, context: DeploymentContext) -> bool:
        hardening = section(context.config, 'hardening')
        return bool(hardening.get('enabled', False)) and bool(_ufw_config(context).get('enabled', False))

    def validate(self, context: DeploymentContext) -> None:
        cfg = _ufw_config(context)
        for key in ('default_incoming', 'default_outgoing'):
            value = str(cfg.get(key, 'deny' if key == 'default_incoming' else 'allow')).lower()
            if value not in {'allow', 'deny', 'reject'}:
                raise DeployError(f'hardening.ufw.{key} must be allow, deny, or reject')

    def prepare_rollback(self, context: DeploymentContext) -> dict[str, Any]:
        installed = shutil.which('ufw') is not None
        active = run(['ufw', 'status'], check=False, capture=True) if installed else None
        return {
            'installed': installed,
            'active': active is not None and 'Status: active' in active.stdout,
            'files': [FileSnapshot.capture(Path(path)) for path in (
                '/etc/default/ufw', '/etc/ufw/user.rules', '/etc/ufw/user6.rules',
                '/etc/ufw/before.rules', '/etc/ufw/before6.rules',
                '/etc/ufw/after.rules', '/etc/ufw/after6.rules',
            )],
        }

    def rollback(self, context: DeploymentContext, snapshot: dict[str, Any]) -> None:
        if snapshot['installed'] and snapshot['active']:
            for item in snapshot['files']:
                item.restore()
            run(['ufw', '--force', 'reload'])
        elif snapshot['installed']:
            run(['ufw', '--force', 'disable'], check=False)
            for item in snapshot['files']:
                item.restore()
        else:
            run(['ufw', '--force', 'disable'], check=False)
            run(['apt-get', 'remove', '-y', 'ufw'], check=False)
            for item in snapshot['files']:
                item.restore()

    def apply(self, context: DeploymentContext) -> None:
        cfg = _ufw_config(context)
        ports = section(context.config, 'ports')
        ssh = section(context.config, 'hardening.ssh')
        ssh_port = int(ssh['new_port'] if ssh.get('enabled', False) else ssh.get('current_port', 22))
        rules: list[tuple[int, str, str]] = [
            (ssh_port, 'tcp', 'vpsdeploy SSH'),
            (int(ports['proxy']), 'tcp', 'vpsdeploy proxy'),
            (int(ports['panel_public']), 'tcp', 'vpsdeploy panel and subscription'),
        ]
        current_ssh_port = int(ssh.get('current_port', 22))
        if bool(ssh.get('enabled', False)) and bool(ssh.get('keep_current_port', True)) and current_ssh_port != ssh_port:
            rules.append((current_ssh_port, 'tcp', 'vpsdeploy SSH transition'))
        if bool(ports.get('publish_proxy_udp', False)):
            rules.append((int(ports['proxy']), 'udp', 'vpsdeploy proxy UDP'))
        wg_easy = context.config.get('wg_easy', {})
        if (
            isinstance(wg_easy, dict)
            and bool(wg_easy.get('enabled', False))
            and str(wg_easy.get('transport', 'anytls')).strip().lower() == 'direct'
        ):
            rules.append((int(wg_easy.get('wireguard_port', 51820)), 'udp', 'vpsdeploy wg-easy WireGuard'))
        sub2api = context.config.get('sub2api', {})
        if isinstance(sub2api, dict) and bool(sub2api.get('enabled', False)) and bool(sub2api.get('publish_port', False)):
            rules.append((int(sub2api.get('published_port', 8080)), 'tcp', 'vpsdeploy Sub2API'))

        # A prior rollback may have removed UFW while dpkg still records its
        # conffiles as deliberately deleted. Restore any such missing files so
        # repeated deployment attempts remain self-healing and idempotent.
        run(['apt-get', '-o', 'Dpkg::Options::=--force-confmiss', 'install', '-y', 'ufw'])
        run(['ufw', 'default', str(cfg.get('default_incoming', 'deny')).lower(), 'incoming'])
        run(['ufw', 'default', str(cfg.get('default_outgoing', 'allow')).lower(), 'outgoing'])
        for port, protocol, comment in dict.fromkeys(rules):
            run(['ufw', 'allow', f'{port}/{protocol}', 'comment', comment])
        if (bool(ssh.get('enabled', False)) and not bool(ssh.get('keep_current_port', True))
                and current_ssh_port != ssh_port):
            # Allow the replacement port first, then retire the transition
            # port. This ordering prevents locking out the active SSH session.
            run(['ufw', '--force', 'delete', 'allow', f'{current_ssh_port}/tcp'], check=False)
        if bool(cfg.get('logging', True)):
            run(['ufw', 'logging', str(cfg.get('logging_level', 'low')).lower()])

        before = run(['ufw', 'show', 'added'], capture=True)
        if f'{ssh_port}/tcp' not in before.stdout:
            raise DeployError(f'Refusing to enable UFW because SSH port {ssh_port}/tcp is not allowed')
        run(['ufw', '--force', 'enable'])

    def verify(self, context: DeploymentContext) -> None:
        result = run(['ufw', 'status', 'verbose'], capture=True)
        if 'Status: active' not in result.stdout:
            raise DeployError('UFW did not become active')
        ports = section(context.config, 'ports')
        required = [f"{int(ports['proxy'])}/tcp", f"{int(ports['panel_public'])}/tcp"]
        ssh = section(context.config, 'hardening.ssh')
        required.append(f"{int(ssh['new_port'] if ssh.get('enabled', False) else ssh.get('current_port', 22))}/tcp")
        if bool(ssh.get('enabled', False)) and bool(ssh.get('keep_current_port', True)):
            required.append(f"{int(ssh.get('current_port', 22))}/tcp")
        wg_easy = context.config.get('wg_easy', {})
        if (
            isinstance(wg_easy, dict)
            and bool(wg_easy.get('enabled', False))
            and str(wg_easy.get('transport', 'anytls')).strip().lower() == 'direct'
        ):
            required.append(f"{int(wg_easy.get('wireguard_port', 51820))}/udp")
        missing = [rule for rule in required if not _has_rule(result.stdout, rule)]
        if missing:
            raise DeployError(f'UFW is missing required rules: {", ".join(missing)}')
        if (bool(ssh.get('enabled', False)) and not bool(ssh.get('keep_current_port', True))
                and int(ssh.get('current_port', 22)) != int(ssh['new_port'])
                and _has_rule(result.stdout, f"{int(ssh.get('current_port', 22))}/tcp")):
            raise DeployError('UFW still allows the retired SSH port')
