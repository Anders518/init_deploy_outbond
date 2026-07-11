from __future__ import annotations

from pathlib import Path

from vpsdeploy.core.runtime import DeploymentContext, Task, run, section, write_file


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
