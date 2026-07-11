from __future__ import annotations

from pathlib import Path

from vpsdeploy.core.runtime import DeploymentContext, Task, run, section, write_file


class Fail2BanTask(Task):
    name = 'fail2ban'

    def enabled(self, context: DeploymentContext) -> bool:
        return bool(section(context.config, 'hardening').get('enabled') and section(context.config, 'hardening.fail2ban').get('enabled'))

    def apply(self, context: DeploymentContext) -> None:
        cfg = section(context.config, 'hardening.fail2ban')
        ssh = section(context.config, 'hardening.ssh')
        ignore = ' '.join(['127.0.0.1/8', '::1', *map(str, cfg.get('ignore_ips', []))])
        run(['apt-get', 'install', '-y', 'fail2ban'])
        write_file(Path('/etc/fail2ban/jail.d/sshd-hardening.local'), f'''[sshd]
enabled = true
port = {ssh['new_port']}
backend = systemd
maxretry = {cfg.get('max_retry', 5)}
findtime = {cfg.get('find_time', '10m')}
bantime = {cfg.get('ban_time', '1h')}
ignoreip = {ignore}
''', 0o644)
        run(['fail2ban-client', '-t'])
        run(['systemctl', 'enable', '--now', 'fail2ban'])
        run(['systemctl', 'restart', 'fail2ban'])

    def verify(self, context: DeploymentContext) -> None:
        run(['fail2ban-client', 'status', 'sshd'])
