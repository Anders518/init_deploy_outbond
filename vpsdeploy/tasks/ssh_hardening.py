from __future__ import annotations

import getpass
import os
import pwd
import re
import secrets
import shutil
import string
from pathlib import Path

from vpsdeploy.core.runtime import DeployError, DeploymentContext, FileSnapshot, Task, run, section, write_file


class SSHHardeningTask(Task):
    name = 'ssh-hardening'
    _managed_config = Path('/etc/ssh/sshd_config.d/99-vps-hardening.conf')

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

    def prepare_rollback(self, context: DeploymentContext) -> dict:
        cfg = section(context.config, 'hardening.ssh')
        candidates = [
            Path('/etc/ssh/sshd_config'), self._managed_config,
            Path('/etc/passwd'), Path('/etc/shadow'), Path('/etc/group'), Path('/etc/gshadow'),
        ]
        dropin_dir = Path('/etc/ssh/sshd_config.d')
        if dropin_dir.is_dir():
            candidates.extend(sorted(dropin_dir.glob('*.conf')))
        username = str(cfg.get('admin_user', 'deploy'))
        candidates.append(Path(f'/etc/sudoers.d/90-{username}'))
        try:
            user = pwd.getpwnam(username)
        except KeyError:
            user = None
        if user is not None:
            candidates.append(Path(user.pw_dir) / '.ssh/authorized_keys')
        return {
            'files': [FileSnapshot.capture(path) for path in dict.fromkeys(candidates)],
            'user_existed': user is not None,
            'username': username,
        }

    def rollback(self, context: DeploymentContext, snapshot: dict) -> None:
        if not snapshot['user_existed'] and re.fullmatch(r'[a-z_][a-z0-9_-]*[$]?', snapshot['username']):
            run(['userdel', '--remove', snapshot['username']], check=False)
        for item in snapshot['files']:
            item.restore()
        run(['sshd', '-t'])
        if run(['systemctl', 'reload', 'ssh'], check=False).returncode != 0:
            run(['systemctl', 'reload', 'sshd'])

    @classmethod
    def _neutralize_conflicting_directive(cls, directive: str) -> None:
        """Comment active copies so the managed drop-in becomes the first effective value."""
        candidates = [Path('/etc/ssh/sshd_config')]
        dropin_dir = Path('/etc/ssh/sshd_config.d')
        if dropin_dir.is_dir():
            candidates.extend(sorted(dropin_dir.glob('*.conf')))

        pattern = re.compile(rf'^(\s*){re.escape(directive)}\s+(.+?)\s*$', re.IGNORECASE)
        marker = '# disabled by vpsdeploy; managed in 99-vps-hardening.conf: '

        for path in candidates:
            if path == cls._managed_config or not path.is_file():
                continue
            try:
                original = path.read_text(encoding='utf-8')
            except OSError as exc:
                raise DeployError(f'Unable to read SSH configuration {path}: {exc}') from exc

            changed = False
            output: list[str] = []
            for line in original.splitlines():
                if pattern.match(line) and not line.lstrip().startswith('#'):
                    output.append(marker + line.strip())
                    changed = True
                else:
                    output.append(line)

            if not changed:
                continue

            backup = path.with_name(path.name + '.vpsdeploy.bak')
            if not backup.exists():
                shutil.copy2(path, backup)
            mode = path.stat().st_mode & 0o777
            write_file(path, '\n'.join(output), mode)

    def apply(self, context: DeploymentContext) -> None:
        cfg = section(context.config, 'hardening.ssh')
        username = str(cfg.get('admin_user', 'deploy'))

        if cfg.get('create_admin_user'):
            if not re.fullmatch(r'[a-z_][a-z0-9_-]*[$]?', username):
                raise DeployError('Invalid admin username')
            try:
                user = pwd.getpwnam(username)
                user_created = False
            except KeyError:
                run(['useradd', '--create-home', '--shell', '/bin/bash', username])
                user = pwd.getpwnam(username)
                user_created = True

            if cfg.get('grant_sudo', True):
                run(['usermod', '-aG', 'sudo', username])
                write_file(
                    Path(f'/etc/sudoers.d/90-{username}'),
                    f'{username} ALL=(ALL:ALL) ALL',
                    0o440,
                )
                run(['visudo', '-cf', f'/etc/sudoers.d/90-{username}'])

                # Password provisioning is a user-creation concern. Re-running
                # SSH hardening must never reset an existing administrator's
                # password or prompt for it merely to update sshd settings.
                if user_created:
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

        # OpenSSH uses the first obtained value for most global directives. Provider
        # images often define PermitRootLogin before the Include statement, so merely
        # writing a late drop-in does not override it. Neutralize active copies first.
        self._neutralize_conflicting_directive('PermitRootLogin')

        port = int(cfg['new_port'])
        lines = [
            f'Port {port}',
            'PubkeyAuthentication yes',
            'PermitEmptyPasswords no',
            'PasswordAuthentication no' if cfg.get('disable_password_auth', True) else 'PasswordAuthentication yes',
            'KbdInteractiveAuthentication no',
            'PermitRootLogin no' if cfg.get('disable_root_login') else 'PermitRootLogin prohibit-password',
        ]
        current_port = int(cfg.get('current_port', 22))
        if bool(cfg.get('keep_current_port', True)) and current_port != port:
            lines.insert(1, f'Port {current_port}')
        if cfg.get('allow_users'):
            lines.append('AllowUsers ' + ' '.join(map(str, cfg['allow_users'])))
        if cfg.get('disable_tcp_forwarding'):
            lines += ['AllowTcpForwarding no', 'PermitTunnel no', 'GatewayPorts no']
        if cfg.get('disable_agent_forwarding', True):
            lines.append('AllowAgentForwarding no')
        if cfg.get('disable_x11_forwarding', True):
            lines.append('X11Forwarding no')
        write_file(self._managed_config, '\n'.join(lines), 0o600)
        run(['sshd', '-t'])
        if run(['systemctl', 'reload', 'ssh'], check=False).returncode != 0:
            run(['systemctl', 'reload', 'sshd'])

    def verify(self, context: DeploymentContext) -> None:
        cfg = section(context.config, 'hardening.ssh')
        port = str(cfg['new_port'])
        result = run(['ss', '-H', '-ltn', f'sport = :{port}'], check=False, capture=True)
        if not result.stdout.strip():
            raise DeployError(f'SSH is not listening on {port}; keep current session open')
        if bool(cfg.get('keep_current_port', True)):
            current_port = str(cfg.get('current_port', 22))
            current = run(['ss', '-H', '-ltn', f'sport = :{current_port}'], check=False, capture=True)
            if not current.stdout.strip():
                raise DeployError(f'SSH transition port {current_port} is not listening')

        effective = run(['sshd', '-T'], capture=True).stdout
        settings: dict[str, str] = {}
        for line in effective.splitlines():
            key, _, value = line.partition(' ')
            if key and value:
                settings[key.strip().lower()] = value.strip().lower()
        actual_root = settings.get('permitrootlogin', '')
        if actual_root == 'without-password':
            actual_root = 'prohibit-password'
        expected_root = 'no' if cfg.get('disable_root_login') else 'prohibit-password'
        if actual_root != expected_root:
            raise DeployError(
                'Effective PermitRootLogin mismatch: '
                f'expected {expected_root}, got {actual_root or "unknown"}'
            )

        if cfg.get('create_admin_user') and cfg.get('grant_sudo', True):
            username = str(cfg.get('admin_user', 'deploy'))
            result = run(['passwd', '-S', username], check=False, capture=True)
            fields = result.stdout.split()
            if result.returncode != 0 or len(fields) < 2 or fields[1] in {'L', 'LK'}:
                raise DeployError(f'Admin password for {username} is locked; sudo would be unusable')
