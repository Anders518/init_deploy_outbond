from __future__ import annotations

import time
from pathlib import Path

from vpsdeploy.core.runtime import (
    DeployError,
    DeploymentContext,
    Task,
    run,
    section,
    write_file,
    FileSnapshot,
)


class Fail2BanTask(Task):
    name = 'fail2ban'

    def enabled(self, context: DeploymentContext) -> bool:
        return bool(
            section(context.config, 'hardening').get('enabled')
            and section(context.config, 'hardening.fail2ban').get('enabled')
        )

    def apply(self, context: DeploymentContext) -> None:
        cfg = section(context.config, 'hardening.fail2ban')
        ssh = section(context.config, 'hardening.ssh')
        ssh_port = str(ssh['new_port'] if ssh.get('enabled', False) else ssh.get('current_port', 22))
        if ssh.get('enabled', False) and ssh.get('keep_current_port', True):
            current_port = str(ssh.get('current_port', 22))
            if current_port != ssh_port:
                ssh_port = f'{current_port},{ssh_port}'
        ignore = ' '.join(
            ['127.0.0.1/8', '::1', *map(str, cfg.get('ignore_ips', []))]
        )

        run(['apt-get', 'install', '-y', 'fail2ban', 'python3-systemd'])
        write_file(
            Path('/etc/fail2ban/jail.d/sshd-hardening.local'),
            f'''[sshd]
enabled = true
port = {ssh_port}
backend = systemd
maxretry = {cfg.get('max_retry', 5)}
findtime = {cfg.get('find_time', '10m')}
bantime = {cfg.get('ban_time', '1h')}
ignoreip = {ignore}
''',
            0o644,
        )

        # Validate the complete configuration before touching the running service.
        run(['fail2ban-client', '-t'])
        run(['systemctl', 'enable', 'fail2ban'])
        run(['systemctl', 'restart', 'fail2ban'])
        self._wait_until_ready(context)

    def prepare_rollback(self, context: DeploymentContext) -> dict:
        active = run(['systemctl', 'is-active', '--quiet', 'fail2ban'], check=False)
        enabled = run(['systemctl', 'is-enabled', '--quiet', 'fail2ban'], check=False)
        return {'active': active.returncode == 0, 'enabled': enabled.returncode == 0,
                'file': FileSnapshot.capture(Path('/etc/fail2ban/jail.d/sshd-hardening.local'))}

    def rollback(self, context: DeploymentContext, snapshot: dict) -> None:
        snapshot['file'].restore()
        if snapshot['enabled']:
            run(['systemctl', 'enable', 'fail2ban'], check=False)
        else:
            run(['systemctl', 'disable', 'fail2ban'], check=False)
        if snapshot['active']:
            run(['systemctl', 'restart', 'fail2ban'])
        else:
            run(['systemctl', 'stop', 'fail2ban'], check=False)

    def verify(self, context: DeploymentContext) -> None:
        self._wait_until_ready(context)
        run(['systemctl', 'is-active', '--quiet', 'fail2ban'])
        run(['fail2ban-client', 'status'])
        run(['fail2ban-client', 'status', 'sshd'])

    @staticmethod
    def _wait_until_ready(context: DeploymentContext) -> None:
        cfg = section(context.config, 'hardening.fail2ban')
        timeout = int(cfg.get('readiness_timeout', 15))
        interval = float(cfg.get('readiness_interval', 1))
        deadline = time.monotonic() + timeout
        last_error = ''

        while time.monotonic() < deadline:
            active = run(
                ['systemctl', 'is-active', '--quiet', 'fail2ban'],
                check=False,
            )
            ping = run(
                ['fail2ban-client', 'ping'],
                check=False,
                capture=True,
            )
            if active.returncode == 0 and ping.returncode == 0:
                output = f'{ping.stdout}\n{ping.stderr}'.lower()
                if 'pong' in output:
                    return

            last_error = (ping.stderr or ping.stdout or '').strip()
            time.sleep(max(interval, 0.1))

        # Emit actionable diagnostics instead of reporting only a missing socket.
        run(
            ['systemctl', 'status', 'fail2ban', '--no-pager', '-l'],
            check=False,
        )
        run(
            [
                'journalctl',
                '-u',
                'fail2ban',
                '-b',
                '--no-pager',
                '-n',
                '100',
            ],
            check=False,
        )
        suffix = f' Last client error: {last_error}' if last_error else ''
        raise DeployError(
            f'Fail2Ban did not become ready within {timeout} seconds.{suffix}'
        )
