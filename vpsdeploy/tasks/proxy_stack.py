from __future__ import annotations

import getpass
import json
import os
import secrets
import string
import time
from pathlib import Path
from typing import Any

from vpsdeploy.core.runtime import DeployError, DeploymentContext, Task, run, section, write_file
from vpsdeploy.templates.render import render_caddy, render_compose


_PASSWORD_MODES = {'prompt', 'generate', 'config', 'environment'}


def _random_password(length: int = 28) -> str:
    alphabet = string.ascii_letters + string.digits + '-_@%+=' 
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def _read_credentials(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _resolve_password(*, label: str, mode: str, configured: str, env_name: str,
                      existing: str = '') -> tuple[str, bool]:
    if mode not in _PASSWORD_MODES:
        raise DeployError(f'{label} password mode must be one of: {sorted(_PASSWORD_MODES)}')
    if mode == 'prompt':
        first = getpass.getpass(f'{label} password: ')
        second = getpass.getpass(f'Confirm {label} password: ')
        if not first or first != second:
            raise DeployError(f'{label} passwords are empty or do not match')
        return first, False
    if mode == 'generate':
        return (existing or _random_password()), not bool(existing)
    if mode == 'config':
        if not configured:
            raise DeployError(f'{label} password is empty in config.toml')
        return configured, False
    value = os.environ.get(env_name, '')
    if not value:
        raise DeployError(f'Set {env_name} for {label}')
    return value, False


def _xui_config(panel: dict[str, Any]) -> dict[str, Any]:
    value = panel.get('xui', {})
    if not isinstance(value, dict):
        raise DeployError('panel.xui must be a TOML table')
    return value


class ProxyStackTask(Task):
    name = 'proxy-stack'

    def validate(self, context: DeploymentContext) -> None:
        panel = section(context.config, 'panel')
        xui = _xui_config(panel)
        for label, username in (
            ('Caddy BasicAuth', str(panel.get('basic_auth_user', 'admin')).strip()),
            ('3x-ui', str(xui.get('username', 'admin')).strip()),
        ):
            if not username or any(char.isspace() for char in username):
                raise DeployError(f'{label} username cannot be empty or contain whitespace')
        for label, mode in (
            ('Caddy BasicAuth', str(panel.get('basic_auth_password_mode', 'generate'))),
            ('3x-ui', str(xui.get('password_mode', 'generate'))),
        ):
            if mode not in _PASSWORD_MODES:
                raise DeployError(f'{label} password mode must be one of: {sorted(_PASSWORD_MODES)}')

    def apply(self, context: DeploymentContext) -> None:
        stack = context.stack_dir
        for rel in ('3x-ui/db', '3x-ui/cert', 'caddy/data', 'caddy/config', 'caddy-build', 'secrets', 'backups', 'state'):
            (stack / rel).mkdir(parents=True, exist_ok=True)

        tls = context.state['tls']
        panel = section(context.config, 'panel')
        xui = _xui_config(panel)
        ports = section(context.config, 'ports')
        docker = section(context.config, 'docker')
        stack_cfg = section(context.config, 'stack')
        credentials_path = stack / 'state' / 'credentials.json'
        existing = _read_credentials(credentials_path)

        existing_caddy = str(existing.get('caddy', {}).get('password', ''))
        caddy_password, caddy_generated = _resolve_password(
            label='Caddy BasicAuth',
            mode=str(panel.get('basic_auth_password_mode', 'generate')),
            configured=str(panel.get('basic_auth_password', '')),
            env_name=str(panel.get('basic_auth_password_env', 'VPSDEPLOY_CADDY_PASSWORD')),
            existing=existing_caddy,
        )
        hashed = run([
            'docker', 'run', '--rm', 'caddy:2-alpine', 'caddy',
            'hash-password', '--plaintext', caddy_password,
        ], capture=True).stdout.strip()
        if not hashed.startswith('$2'):
            raise DeployError('Failed to generate Caddy password hash')

        xui_password = ''
        xui_generated = False
        if bool(xui.get('enabled', True)):
            existing_xui = str(existing.get('xui', {}).get('password', ''))
            xui_password, xui_generated = _resolve_password(
                label='3x-ui',
                mode=str(xui.get('password_mode', 'generate')),
                configured=str(xui.get('password', '')),
                env_name=str(xui.get('password_env', 'VPSDEPLOY_XUI_PASSWORD')),
                existing=existing_xui,
            )

        env = [
            f"TZ={stack_cfg.get('timezone', 'UTC')}",
            f"XUI_IMAGE={docker['xui_image']}",
            f"CADDY_IMAGE={docker['caddy_image']}",
            f"PROXY_PORT={ports['proxy']}",
            f"PANEL_PUBLIC_PORT={ports['panel_public']}",
        ]
        for key, value in (tls.environment or {}).items():
            env.append(f'{key}={value}')
        write_file(stack / '.env', '\n'.join(env), 0o600)
        write_file(stack / 'docker-compose.yml', render_compose(context, tls), 0o600)
        write_file(stack / 'Caddyfile', render_caddy(context, tls, hashed), 0o600)

        if tls.requires_custom_caddy:
            write_file(
                stack / 'caddy-build/Dockerfile',
                'FROM caddy:2-builder-alpine AS builder\n'
                'RUN xcaddy build --with github.com/caddy-dns/cloudflare\n'
                'FROM caddy:2-alpine\n'
                'COPY --from=builder /usr/bin/caddy /usr/bin/caddy\n',
                0o644,
            )
            run(['docker', 'compose', 'build', '--pull', 'caddy'], cwd=stack)
        else:
            run(['docker', 'pull', str(docker['caddy_image'])])

        run(['docker', 'compose', 'pull', '3x-ui'], cwd=stack)
        run(['docker', 'compose', 'up', '-d', '--remove-orphans'], cwd=stack)

        # A bind-mounted Caddyfile can change without Compose recreating the
        # container. Explicitly validate and reload it so the running process
        # always uses the newly generated BasicAuth hash.
        self._reload_caddy()
        self._verify_basic_auth(context, str(panel.get('basic_auth_user', 'admin')), caddy_password)

        if bool(xui.get('enabled', True)):
            self._configure_xui(
                str(xui.get('username', 'admin')),
                xui_password,
                str(xui.get('cli', 'x-ui')),
            )

        credentials = {
            'panel_url': f"https://{section(context.config, 'domains')['panel']}:{ports['panel_public']}{panel.get('path', '/')}",
            'caddy': {
                'username': str(panel.get('basic_auth_user', 'admin')),
                'password': caddy_password,
            },
            'xui': {
                'enabled': bool(xui.get('enabled', True)),
                'username': str(xui.get('username', 'admin')),
                'password': xui_password if bool(xui.get('enabled', True)) else '',
            },
        }
        write_file(credentials_path, json.dumps(credentials, indent=2, ensure_ascii=False), 0o600)
        write_file(
            stack / 'secrets.txt',
            f"Credentials: {credentials_path}\n"
            f"Show securely: sudo python3 deploy.py credentials\n",
            0o600,
        )
        context.state['generated_credentials'] = {
            'caddy': caddy_generated,
            'xui': xui_generated,
            'path': str(credentials_path),
        }

    def _reload_caddy(self) -> None:
        timeout = 30
        for _ in range(timeout):
            result = run(
                ['docker', 'inspect', '-f', '{{.State.Running}}', 'caddy-panel'],
                check=False,
                capture=True,
            )
            if result.returncode == 0 and result.stdout.strip() == 'true':
                break
            time.sleep(1)
        else:
            raise DeployError('Caddy container did not become ready')

        run(['docker', 'exec', 'caddy-panel', 'caddy', 'validate', '--config', '/etc/caddy/Caddyfile'])
        run([
            'docker', 'exec', 'caddy-panel', 'caddy', 'reload',
            '--config', '/etc/caddy/Caddyfile', '--adapter', 'caddyfile',
        ])

    def _verify_basic_auth(self, context: DeploymentContext, username: str, password: str) -> None:
        domains = section(context.config, 'domains')
        ports = section(context.config, 'ports')
        panel = section(context.config, 'panel')
        hostname = str(domains['panel'])
        port = int(ports['panel_public'])
        path = str(panel.get('path', '/')) or '/'
        url = f'https://{hostname}:{port}{path}'
        resolve = f'{hostname}:{port}:127.0.0.1'

        unauthenticated = run([
            'curl', '--silent', '--show-error', '--insecure', '--resolve', resolve,
            '--output', '/dev/null', '--write-out', '%{http_code}', url,
        ], check=False, capture=True)
        if unauthenticated.stdout.strip() != '401':
            raise DeployError(
                'Caddy BasicAuth verification failed: an unauthenticated request '
                f'returned HTTP {unauthenticated.stdout.strip() or "unknown"}, expected 401'
            )

        authenticated = run([
            'curl', '--silent', '--show-error', '--insecure', '--resolve', resolve,
            '--user', f'{username}:{password}', '--output', '/dev/null',
            '--write-out', '%{http_code}', url,
        ], check=False, capture=True)
        status = authenticated.stdout.strip()
        if authenticated.returncode != 0 or status in {'', '401', '403'}:
            detail = (authenticated.stderr or '').strip()
            raise DeployError(
                'Caddy BasicAuth verification failed with the configured credentials: '
                f'HTTP {status or "unknown"}. {detail}'
            )

    def _configure_xui(self, username: str, password: str, cli: str) -> None:
        timeout = 30
        for _ in range(timeout):
            result = run(['docker', 'inspect', '-f', '{{.State.Running}}', '3x-ui'], check=False, capture=True)
            if result.returncode == 0 and result.stdout.strip() == 'true':
                break
            time.sleep(1)
        else:
            raise DeployError('3x-ui container did not become ready')

        result = run([
            'docker', 'exec', '3x-ui', cli, 'setting',
            '-username', username, '-password', password,
        ], check=False, capture=True)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            raise DeployError(
                f'Failed to configure 3x-ui credentials with {cli!r}: {detail}. '
                'Set panel.xui.cli to the executable available in the container.'
            )
        run(['docker', 'restart', '3x-ui'])

    def verify(self, context: DeploymentContext) -> None:
        run(['docker', 'compose', 'ps'], cwd=context.stack_dir)
        credentials = context.stack_dir / 'state' / 'credentials.json'
        if not credentials.is_file() or credentials.stat().st_mode & 0o077:
            raise DeployError('Credential state file is missing or has unsafe permissions')
