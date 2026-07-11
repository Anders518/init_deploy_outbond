from __future__ import annotations

import getpass
import os
import pwd
import re
import secrets
import shutil
import string
from pathlib import Path

from vpsdeploy.core.runtime import DeployError, DeploymentContext, Task, run, section, write_file


class SSHHardeningTask(Task):
    name = 'ssh-hardening'

    def enabled(self, context: DeploymentContext) -> bool:
        return bool(
            section(context.config, 'hardening').get('enabled')
            and section(context.config, 'hardening.ssh').get('enabled')
        )

    def validate(self, context: DeploymentContext) -> None:
        cfg = section(context.config, 'hardening.ssh')
        port = int(cfg['new_port'])
        if not 1 <= port <= 65535:
            raise DeployError('Invalid SSH port')
        if cfg.get('disable_root_login') and not cfg.get('allow_users'):
            raise DeployError('allow_users is required before disabling root login')

        mode = str(cfg.get('admin_password_mode', 'prompt')).strip().lower()
        if mode not in {'prompt', 'generate', 'hash'}:
            raise DeployError('admin_password_mode must be prompt, generate, or hash')
        if cfg.get('create_admin_user') and cfg.get('grant_sudo', True) and mode == 'hash':
            password_hash = (
                os.environ.get('VPSDEPLOY_ADMIN_PASSWORD_HASH', '').strip()
                or str(cfg.get('admin_password_hash', '')).strip()
            )
            if not password_hash:
                raise DeployError(
                    'admin_password_mode=hash requires VPSDEPLOY_ADMIN_PASSWORD_HASH '
                    'or hardening.ssh.admin_password_hash'
                )

    def _password(self, context: DeploymentContext, username: str) -> tuple[str | None, str | None]:
        cfg = section(context.config, 'hardening.ssh')
        mode = str(cfg.get('admin_password_mode', 'prompt')).strip().lower()

        if mode == 'hash':
            password_hash = (
                os.environ.get('VPSDEPLOY_ADMIN_PASSWORD_HASH', '').strip()
                or str(cfg.get('admin_password_hash', '')).strip()
            )
            return None, password_hash

        env_password = os.environ.get('VPSDEPLOY_ADMIN_PASSWORD', '')
        if env_password:
            return env_password, None

        if mode == 'generate':
            alphabet = string.ascii_letters + string.digits + '!@#%^*-_=+'
            password = ''.join(secrets.choice(alphabet) for _ in range(24))
            context.state['generated_admin_password'] = password
            context.state['generated_admin_user'] = username
            return password, None

        first = getpass.getpass(f'Password for sudo user {username}: ')
        second = getpass.getpass('Confirm password: ')
        if not first:
            raise DeployError('Admin password cannot be empty')
        if first != second:
            raise DeployError('Admin password confirmation does not match')
        return first, None

    def apply(self, context: DeploymentContext) -> None:
        cfg = section(context.config, 'hardening.ssh')
        username = str(cfg.get('admin_user', 'deploy'))

        if cfg.get('create_admin_user'):
            if not re.fullmatch(r'[a-z_][a-z0-9_-]*[$]?', username):
                raise DeployError('Invalid admin username')
            try:
                user = pwd.getpwnam(username)
            except KeyError:
                run(['useradd', '--create-home', '--shell', '/bin/bash', username])
                user = pwd.getpwnam(username)

            if cfg.get('grant_sudo', True):
                run(['usermod', '-aG', 'sudo', username])
                write_file(
                    Path(f'/etc/sudoers.d/90-{username}'),
                    f'{username} ALL=(ALL:ALL) ALL',
                    0o440,
                )
                run(['visudo', '-cf', f'/etc/sudoers.d/90-{username}'])

                password, password_hash = self._password(context, username)
                if password_hash:
                    run(['usermod', '--password', password_hash, username])
                else:
                    run(['chpasswd'], input_text=f'{username}:{password}\n')

            if cfg.get('copy_root_authorized_keys', True):
                source = Path('/root/.ssh/authorized_keys')
                if not source.is_file() or not source.stat().st_size:
                    raise DeployError('root authorized_keys is empty')
                target_dir = Path(user.pw_dir) / '.ssh'
                target_dir.mkdir(parents=True, exist_ok=True)
                target = target_dir / 'authorized_keys'
                shutil.copy2(source, target)
                os.chown(target_dir, user.pw_uid, user.pw_gid)
                os.chown(target, user.pw_uid, user.pw_gid)
                target_dir.chmod(0o700)
                target.chmod(0o600)

        port = int(cfg['new_port'])
        lines = [
            f'Port {port}',
            'PubkeyAuthentication yes',
            'PermitEmptyPasswords no',
            'PasswordAuthentication no' if cfg.get('disable_password_auth', True) else 'PasswordAuthentication yes',
            'KbdInteractiveAuthentication no',
            'PermitRootLogin no' if cfg.get('disable_root_login') else 'PermitRootLogin prohibit-password',
        ]
        if cfg.get('allow_users'):
            lines.append('AllowUsers ' + ' '.join(map(str, cfg['allow_users'])))
        if cfg.get('disable_tcp_forwarding'):
            lines += ['AllowTcpForwarding no', 'PermitTunnel no', 'GatewayPorts no']
        if cfg.get('disable_agent_forwarding', True):
            lines.append('AllowAgentForwarding no')
        if cfg.get('disable_x11_forwarding', True):
            lines.append('X11Forwarding no')
        write_file(Path('/etc/ssh/sshd_config.d/99-vps-hardening.conf'), '\n'.join(lines), 0o600)
        run(['sshd', '-t'])
        if run(['systemctl', 'reload', 'ssh'], check=False).returncode != 0:
            run(['systemctl', 'reload', 'sshd'])

    def verify(self, context: DeploymentContext) -> None:
        cfg = section(context.config, 'hardening.ssh')
        port = str(cfg['new_port'])
        result = run(['ss', '-H', '-ltn', f'sport = :{port}'], check=False, capture=True)
        if not result.stdout.strip():
            raise DeployError(f'SSH is not listening on {port}; keep current session open')

        if cfg.get('create_admin_user') and cfg.get('grant_sudo', True):
            username = str(cfg.get('admin_user', 'deploy'))
            result = run(['passwd', '-S', username], check=False, capture=True)
            fields = result.stdout.split()
            if result.returncode != 0 or len(fields) < 2 or fields[1] in {'L', 'LK'}:
                raise DeployError(f'Admin password for {username} is locked; sudo would be unusable')
