from __future__ import annotations

import getpass
import json
import os
import re
import secrets
import string
import time
from pathlib import Path
from typing import Any

from vpsdeploy.core.runtime import DeployError, DeploymentContext, Task, run, section, write_file
from vpsdeploy.templates.sub2api import render_sub2api_compose

_PASSWORD_MODES = {'prompt', 'generate', 'config', 'environment'}
_HEX_32_BYTES = re.compile(r'^[0-9a-fA-F]{64}$')


def _random_secret(length: int = 48) -> str:
    alphabet = string.ascii_letters + string.digits + '-_@%+='
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def _random_hex_secret(bytes_length: int = 32) -> str:
    return secrets.token_hex(bytes_length)


def _validate_secret(label: str, key: str, value: str) -> str:
    if not value:
        raise DeployError(f'{label} cannot be empty')
    if '\n' in value or '\r' in value:
        raise DeployError(f'{label} cannot contain newlines')
    if key == 'totp_key' and not _HEX_32_BYTES.fullmatch(value):
        raise DeployError(
            'Sub2API TOTP encryption key must be exactly 64 hexadecimal characters '
            '(32 bytes), for example: openssl rand -hex 32'
        )
    return value


def _resolve_secret(label: str, cfg: dict[str, Any], key: str, existing: str = '') -> tuple[str, bool]:
    mode = str(cfg.get(f'{key}_mode', 'generate'))
    if mode not in _PASSWORD_MODES:
        raise DeployError(f'{label} mode must be one of: {sorted(_PASSWORD_MODES)}')
    if mode == 'prompt':
        first = getpass.getpass(f'{label}: ')
        second = getpass.getpass(f'Confirm {label}: ')
        if first != second:
            raise DeployError(f'{label} values do not match')
        return _validate_secret(label, key, first), False
    if mode == 'generate':
        if existing:
            return _validate_secret(label, key, existing), False
        value = _random_hex_secret() if key == 'totp_key' else _random_secret()
        return _validate_secret(label, key, value), True
    if mode == 'config':
        value = str(cfg.get(key, ''))
        return _validate_secret(label, key, value), False
    env_name = str(cfg.get(f'{key}_env', f'VPSDEPLOY_{key.upper()}'))
    value = os.environ.get(env_name, '')
    if not value:
        raise DeployError(f'Set {env_name} for {label}')
    return _validate_secret(label, key, value), False


class Sub2APITask(Task):
    name = 'sub2api'

    def enabled(self, context: DeploymentContext) -> bool:
        cfg = context.config.get('sub2api', {})
        return isinstance(cfg, dict) and bool(cfg.get('enabled', False))

    def validate(self, context: DeploymentContext) -> None:
        cfg = section(context.config, 'sub2api')
        domain = str(cfg.get('domain', '')).strip().lower()
        if not domain or '.' not in domain:
            raise DeployError('sub2api.domain must be a fully qualified domain name')
        if int(cfg.get('internal_port', 8080)) != 8080:
            raise DeployError('Sub2API container currently listens on internal port 8080')
        if bool(cfg.get('publish_port', False)):
            port = int(cfg.get('published_port', 8080))
            if not 1 <= port <= 65535:
                raise DeployError('sub2api.published_port is invalid')
        for key in ('admin_password', 'postgres_password', 'redis_password', 'jwt_secret', 'totp_key'):
            mode = str(cfg.get(f'{key}_mode', 'generate'))
            if mode not in _PASSWORD_MODES:
                raise DeployError(f'sub2api.{key}_mode is invalid')
        if str(cfg.get('totp_key_mode', 'generate')) == 'config':
            _validate_secret('Sub2API TOTP encryption key', 'totp_key', str(cfg.get('totp_key', '')))

    def apply(self, context: DeploymentContext) -> None:
        cfg = section(context.config, 'sub2api')
        install_dir = Path(str(cfg.get('install_dir', '/opt/sub2api'))).resolve()
        for rel in ('data', 'postgres_data', 'redis_data', 'state', 'backups'):
            (install_dir / rel).mkdir(parents=True, exist_ok=True)

        credentials_path = install_dir / 'state' / 'credentials.json'
        existing: dict[str, Any] = {}
        if credentials_path.is_file():
            try:
                existing = json.loads(credentials_path.read_text(encoding='utf-8'))
            except (OSError, json.JSONDecodeError):
                existing = {}

        values: dict[str, str] = {}
        generated: list[str] = []
        for key, label in (
            ('admin_password', 'Sub2API admin password'),
            ('postgres_password', 'Sub2API PostgreSQL password'),
            ('redis_password', 'Sub2API Redis password'),
            ('jwt_secret', 'Sub2API JWT secret'),
            ('totp_key', 'Sub2API TOTP encryption key'),
        ):
            old = str(existing.get('secrets', {}).get(key, ''))
            value, was_generated = _resolve_secret(label, cfg, key, old)
            values[key] = value
            if was_generated:
                generated.append(key)

        env = {
            'SUB2API_IMAGE': str(cfg.get('image', 'weishaw/sub2api:latest')),
            'TZ': str(cfg.get('timezone', 'Asia/Shanghai')),
            'ADMIN_EMAIL': str(cfg.get('admin_email', 'admin@sub2api.local')),
            'ADMIN_PASSWORD': values['admin_password'],
            'POSTGRES_USER': str(cfg.get('postgres_user', 'sub2api')),
            'POSTGRES_DB': str(cfg.get('postgres_database', 'sub2api')),
            'POSTGRES_PASSWORD': values['postgres_password'],
            'REDIS_PASSWORD': values['redis_password'],
            'JWT_SECRET': values['jwt_secret'],
            'TOTP_ENCRYPTION_KEY': values['totp_key'],
            'PROXY_NETWORK': str(section(context.config, 'docker').get('network_name', 'proxy_stack')),
        }
        write_file(install_dir / '.env', '\n'.join(f'{k}={v}' for k, v in env.items()), 0o600)
        write_file(install_dir / 'docker-compose.yml', render_sub2api_compose(cfg), 0o600)

        run(['docker', 'compose', 'config', '--quiet'], cwd=install_dir)
        run(['docker', 'compose', 'pull'], cwd=install_dir)
        run(['docker', 'compose', 'up', '-d', '--remove-orphans'], cwd=install_dir)
        self._wait_healthy(int(cfg.get('readiness_timeout', 120)))

        # ProxyStackTask renders the extra Caddy site. Reload now that Sub2API is reachable.
        run(['docker', 'exec', 'caddy-panel', 'caddy', 'validate', '--config', '/etc/caddy/Caddyfile'])
        run(['docker', 'exec', 'caddy-panel', 'caddy', 'reload', '--config', '/etc/caddy/Caddyfile', '--adapter', 'caddyfile'])

        credentials = {
            'url': f"https://{cfg['domain']}:{int(section(context.config, 'ports')['panel_public'])}/",
            'admin_email': env['ADMIN_EMAIL'],
            'secrets': values,
        }
        write_file(credentials_path, json.dumps(credentials, indent=2, ensure_ascii=False), 0o600)
        context.state['generated_sub2api_credentials'] = {
            'path': str(credentials_path),
            'generated': generated,
        }

    @staticmethod
    def _wait_healthy(timeout: int) -> None:
        last_status = 'unknown'
        for _ in range(max(timeout, 1)):
            result = run(['docker', 'inspect', '-f', '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}', 'sub2api'], check=False, capture=True)
            last_status = result.stdout.strip() or last_status
            if result.returncode == 0 and last_status in {'healthy', 'running'}:
                return
            time.sleep(1)
        run(['docker', 'logs', '--tail', '100', 'sub2api'], check=False)
        raise DeployError(f'Sub2API did not become ready in time (last status: {last_status})')

    def verify(self, context: DeploymentContext) -> None:
        cfg = section(context.config, 'sub2api')
        install_dir = Path(str(cfg.get('install_dir', '/opt/sub2api'))).resolve()
        run(['docker', 'compose', 'ps'], cwd=install_dir)
        result = run(['docker', 'exec', 'sub2api', 'wget', '-q', '-T', '5', '-O', '/dev/null', 'http://127.0.0.1:8080/health'], check=False, capture=True)
        if result.returncode != 0:
            raise DeployError('Sub2API health endpoint verification failed')