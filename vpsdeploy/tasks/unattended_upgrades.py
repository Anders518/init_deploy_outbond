from __future__ import annotations

from pathlib import Path

from vpsdeploy.core.runtime import DeploymentContext, FileSnapshot, Task, run, section, write_file


class UnattendedUpgradesTask(Task):
    name = 'unattended-upgrades'

    def enabled(self, context: DeploymentContext) -> bool:
        return bool(section(context.config, 'hardening').get('enabled') and section(context.config, 'hardening.unattended_upgrades').get('enabled'))

    def apply(self, context: DeploymentContext) -> None:
        cfg = section(context.config, 'hardening.unattended_upgrades')
        run(['apt-get', 'install', '-y', 'unattended-upgrades', 'apt-listchanges'])
        write_file(Path('/etc/apt/apt.conf.d/20auto-upgrades'),
                   'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\nAPT::Periodic::AutocleanInterval "7";', 0o644)
        reboot = 'true' if cfg.get('automatic_reboot') else 'false'
        write_file(Path('/etc/apt/apt.conf.d/52proxy-stack-unattended'),
                   f'Unattended-Upgrade::Automatic-Reboot "{reboot}";\nUnattended-Upgrade::Automatic-Reboot-Time "{cfg.get("reboot_time", "04:30")}";\nUnattended-Upgrade::Remove-Unused-Kernel-Packages "true";\nUnattended-Upgrade::Remove-Unused-Dependencies "true";', 0o644)
        run(['systemctl', 'enable', '--now', 'unattended-upgrades.service'], check=False)

    def prepare_rollback(self, context: DeploymentContext) -> dict:
        active = run(['systemctl', 'is-active', '--quiet', 'unattended-upgrades.service'], check=False)
        enabled = run(['systemctl', 'is-enabled', '--quiet', 'unattended-upgrades.service'], check=False)
        return {'active': active.returncode == 0, 'enabled': enabled.returncode == 0, 'files': [
            FileSnapshot.capture(Path('/etc/apt/apt.conf.d/20auto-upgrades')),
            FileSnapshot.capture(Path('/etc/apt/apt.conf.d/52proxy-stack-unattended')),
        ]}

    def rollback(self, context: DeploymentContext, snapshot: dict) -> None:
        for item in snapshot['files']:
            item.restore()
        action = 'enable' if snapshot['enabled'] else 'disable'
        run(['systemctl', action, 'unattended-upgrades.service'], check=False)
        action = 'start' if snapshot['active'] else 'stop'
        run(['systemctl', action, 'unattended-upgrades.service'], check=False)
