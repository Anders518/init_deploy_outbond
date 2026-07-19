from __future__ import annotations

import getpass
import json
import os
import secrets
import string
import time
from pathlib import Path
from typing import Any

from vpsdeploy.core.runtime import DeployError, DeploymentContext, Task, run, run_retry, section, write_file
from vpsdeploy.providers.dns.cloudflare import CloudflareDNSProvider
from vpsdeploy.templates.render import render_caddy, render_compose


_PASSWORD_MODES = {'prompt', 'generate', 'config', 'environment'}
_XUI_CLI_CANDIDATES = ('/app/x-ui', 'x-ui')
_SUI_CLI_CANDIDATES = ('/app/sui', 'sui')


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


def _panel_backend(panel: dict[str, Any]) -> str:
    backend = str(panel.get('backend', '3x-ui')).strip().lower()
    if backend not in {'3x-ui', 's-ui'}:
        raise DeployError('panel.backend must be "3x-ui" or "s-ui"')
    return backend


def _backend_config(panel: dict[str, Any], backend: str) -> dict[str, Any]:
    key = 'xui' if backend == '3x-ui' else 'sui'
    value = panel.get(key, {})
    if not isinstance(value, dict):
        raise DeployError(f'panel.{key} must be a TOML table')
    return value


class ProxyStackTask(Task):
    name = 'proxy-stack'

    def validate(self, context: DeploymentContext) -> None:
        panel = section(context.config, 'panel')
        backend = _panel_backend(panel)
        backend_cfg = _backend_config(panel, backend)
        backend_label = '3x-ui' if backend == '3x-ui' else 'S-UI'
        for label, username in (
            ('Caddy BasicAuth', str(panel.get('basic_auth_user', 'admin')).strip()),
            (backend_label, str(backend_cfg.get('username', 'xui-admin' if backend == '3x-ui' else 'sui-admin')).strip()),
        ):
            if not username or any(char.isspace() for char in username):
                raise DeployError(f'{label} username cannot be empty or contain whitespace')
        for label, mode in (
            ('Caddy BasicAuth', str(panel.get('basic_auth_password_mode', 'generate'))),
            (backend_label, str(backend_cfg.get('password_mode', 'generate'))),
        ):
            if mode not in _PASSWORD_MODES:
                raise DeployError(f'{label} password mode must be one of: {sorted(_PASSWORD_MODES)}')
        if (
            str(backend_cfg.get('username', '')) == 'admin'
            and str(backend_cfg.get('password', '')) == 'admin'
            and not bool(backend_cfg.get('allow_default_credentials', False))
        ):
            raise DeployError(
                f'Refusing the default {backend_label} admin/admin credentials. '
                f'Choose another password or explicitly set panel.{"xui" if backend == "3x-ui" else "sui"}.allow_default_credentials=true.'
            )

    def apply(self, context: DeploymentContext) -> None:
        stack = context.stack_dir
        panel = section(context.config, 'panel')
        backend = _panel_backend(panel)
        backend_key = 'xui' if backend == '3x-ui' else 'sui'
        backend_label = '3x-ui' if backend == '3x-ui' else 'S-UI'
        for rel in (f'{backend}/db', f'{backend}/cert', 'caddy/data', 'caddy/config', 'caddy-build', 'secrets', 'backups', 'state'):
            (stack / rel).mkdir(parents=True, exist_ok=True)

        tls = context.state['tls']
        backend_cfg = _backend_config(panel, backend)
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
        ], capture=True, redact_values={caddy_password}).stdout.strip()
        if not hashed.startswith('$2'):
            raise DeployError('Failed to generate Caddy password hash')

        default_username = 'xui-admin' if backend == '3x-ui' else 'sui-admin'
        default_env = 'VPSDEPLOY_XUI_PASSWORD' if backend == '3x-ui' else 'VPSDEPLOY_SUI_PASSWORD'
        existing_backend = str(existing.get(backend_key, {}).get('password', ''))
        backend_password, backend_generated = _resolve_password(
            label=backend_label,
            mode=str(backend_cfg.get('password_mode', 'generate')),
            configured=str(backend_cfg.get('password', '')),
            env_name=str(backend_cfg.get('password_env', default_env)),
            existing=existing_backend,
        )
        if (
            str(backend_cfg.get('username', default_username)) == 'admin'
            and backend_password == 'admin'
            and not bool(backend_cfg.get('allow_default_credentials', False))
        ):
            raise DeployError(f'Refusing to configure insecure default {backend_label} credentials admin/admin')

        env = [
            f"TZ={stack_cfg.get('timezone', 'UTC')}",
            f"XUI_IMAGE={docker.get('xui_image', 'ghcr.io/mhsanaei/3x-ui:latest')}",
            f"SUI_IMAGE={docker.get('sui_image', 'alireza7/s-ui:v1.5.3')}",
            f"CADDY_IMAGE={docker['caddy_image']}",
            f"PROXY_PORT={ports['proxy']}",
            f"PANEL_PUBLIC_PORT={ports['panel_public']}",
            f"LOG_MAX_SIZE={docker.get('log_max_size', '10m')}",
            f"LOG_MAX_FILE={int(docker.get('log_max_file', 3))}",
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

        run(['docker', 'compose', 'pull', backend], cwd=stack)
        if tls.mode == 'acme_dns' and bool(section(context.config, 'panel.tls').get('cleanup_stale_challenges', True)):
            # Stop the existing issuer before deleting abandoned TXT records,
            # otherwise its retry loop may recreate the same record mid-cleanup.
            run(['docker', 'compose', 'stop', 'caddy'], cwd=stack, check=False)
            domains = section(context.config, 'domains')
            hostnames = [
                str(domains['panel']),
                str(domains.get('subscription', domains['panel'])),
                str(domains['node']),
            ]
            CloudflareDNSProvider().delete_acme_challenge_records(context, hostnames)
        run(['docker', 'compose', 'up', '-d', '--remove-orphans'], cwd=stack)

        if backend == '3x-ui':
            resolved_cli = self._configure_xui(
                str(backend_cfg.get('username', default_username)),
                backend_password,
                str(backend_cfg.get('cli', 'auto')),
                bool(backend_cfg.get('allow_default_credentials', False)),
            )
        else:
            resolved_cli = self._configure_sui(
                str(backend_cfg.get('username', default_username)),
                backend_password,
                str(backend_cfg.get('cli', 'auto')),
                bool(backend_cfg.get('allow_default_credentials', False)),
                int(ports['panel_internal']),
                str(panel.get('path', '/')),
                int(ports['subscription_internal']),
                str(panel.get('subscription_path', '/sub')),
            )

        self._reload_caddy()
        self._verify_basic_auth(context, str(panel.get('basic_auth_user', 'admin')), caddy_password)

        credentials = {
            'panel_url': f"https://{section(context.config, 'domains')['panel']}:{ports['panel_public']}{panel.get('path', '/')}",
            'backend': backend,
            'caddy': {
                'username': str(panel.get('basic_auth_user', 'admin')),
                'password': caddy_password,
            },
            backend_key: {
                'enabled': True,
                'username': str(backend_cfg.get('username', default_username)),
                'password': backend_password,
                'cli': resolved_cli,
            },
        }
        write_file(credentials_path, json.dumps(credentials, indent=2, ensure_ascii=False), 0o600)
        write_file(
            stack / 'secrets.txt',
            f"Credentials: {credentials_path}\n"
            f"Show securely: sudo uv run --no-dev --frozen python deploy.py credentials\n",
            0o600,
        )
        context.state['generated_credentials'] = {
            'caddy': caddy_generated,
            backend_key: backend_generated,
            'backend': backend,
            'path': str(credentials_path),
        }

    def _wait_container(self, name: str, timeout: int = 30) -> None:
        stable = 0
        for _ in range(timeout):
            result = run(
                ['docker', 'inspect', '-f', '{{.State.Running}} {{.State.Restarting}}', name],
                check=False,
                capture=True,
            )
            if result.returncode == 0 and result.stdout.strip() == 'true false':
                stable += 1
                if stable >= 2:
                    return
            else:
                stable = 0
            time.sleep(1)
        run(['docker', 'logs', '--tail', '100', name], check=False)
        raise DeployError(f'{name} container did not become stably ready')

    def _reload_caddy(self) -> None:
        self._wait_container('caddy-panel')
        run_retry(['docker', 'exec', 'caddy-panel', 'caddy', 'validate', '--config', '/etc/caddy/Caddyfile'])
        run_retry([
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

        last_status = ''
        last_detail = ''
        for attempt in range(60):
            unauthenticated = run([
                'curl', '--silent', '--show-error', '--insecure',
                '--connect-timeout', '3', '--max-time', '8',
                '--resolve', resolve, '--output', '/dev/null',
                '--write-out', '%{http_code}', url,
            ], check=False, capture=True)
            last_status = unauthenticated.stdout.strip()
            last_detail = (unauthenticated.stderr or '').strip()
            if unauthenticated.returncode == 0 and last_status == '401':
                break
            if attempt == 0:
                print('[caddy] waiting for TLS endpoint and ACME certificate readiness...')
            time.sleep(2)
        else:
            logs = run(
                ['docker', 'logs', '--tail', '80', 'caddy-panel'],
                check=False,
                capture=True,
            )
            log_detail = '\n'.join(part for part in (logs.stdout, logs.stderr) if part).strip()
            raise DeployError(
                'Caddy BasicAuth verification timed out after 120 seconds: '
                f'unauthenticated request returned HTTP {last_status or "000"}, expected 401. '
                f'{last_detail or "No curl error detail."}\nRecent Caddy logs:\n{log_detail}'
            )

        authenticated = run([
            'curl', '--silent', '--show-error', '--insecure',
            '--connect-timeout', '3', '--max-time', '8',
            '--resolve', resolve, '--user', f'{username}:{password}',
            '--output', '/dev/null', '--write-out', '%{http_code}', url,
        ], check=False, capture=True, redact_values={f'{username}:{password}'})
        status = authenticated.stdout.strip()
        if authenticated.returncode != 0 or status in {'', '401', '403'}:
            detail = (authenticated.stderr or '').strip()
            raise DeployError(
                'Caddy BasicAuth verification failed with the configured credentials: '
                f'HTTP {status or "unknown"}. {detail}'
            )

    def _resolve_xui_cli(self, configured: str) -> str:
        candidates = _XUI_CLI_CANDIDATES if configured in {'', 'auto'} else (configured,)
        for candidate in candidates:
            probe = run(
                ['docker', 'exec', '3x-ui', 'sh', '-c', f'test -x {candidate} || command -v {candidate} >/dev/null 2>&1'],
                check=False,
                capture=True,
            )
            if probe.returncode == 0:
                return candidate
        raise DeployError(
            'Unable to locate the 3x-ui CLI in the container. '
            f'Tried: {", ".join(candidates)}. Set panel.xui.cli explicitly.'
        )

    def _show_xui_settings(self, cli: str) -> str:
        result = run(
            ['docker', 'exec', '3x-ui', cli, 'setting', '-show'],
            check=False,
            capture=True,
        )
        output = '\n'.join(part for part in (result.stdout, result.stderr) if part).strip()
        if result.returncode != 0:
            raise DeployError(f'Failed to read 3x-ui settings with {cli!r}: {output}')
        return output

    def _configure_xui(self, username: str, password: str, configured_cli: str,
                       allow_default_credentials: bool) -> str:
        self._wait_container('3x-ui')
        cli = self._resolve_xui_cli(configured_cli)

        result = run([
            'docker', 'exec', '3x-ui', cli, 'setting',
            '-username', username, '-password', password,
        ], check=False, capture=True, redact_values={password})
        output = '\n'.join(part for part in (result.stdout, result.stderr) if part).strip()
        if result.returncode != 0 or 'Username and password updated successfully' not in output:
            raise DeployError(
                f'3x-ui rejected the credential update with {cli!r}: {output or "no output"}. '
                'The CLI may have returned success while the application-level update failed.'
            )

        before_restart = self._show_xui_settings(cli)
        if 'hasDefaultCredential: true' in before_restart and not allow_default_credentials:
            raise DeployError(
                '3x-ui still reports hasDefaultCredential=true after the credential update; '
                'credentials.json was not written. Check the mounted database and CLI path.'
            )

        run(['docker', 'restart', '3x-ui'])
        self._wait_container('3x-ui')
        time.sleep(2)
        after_restart = self._show_xui_settings(cli)
        if 'hasDefaultCredential: true' in after_restart and not allow_default_credentials:
            raise DeployError(
                '3x-ui reverted to the default admin/admin credentials after restart. '
                'Check /etc/x-ui volume persistence and database permissions.'
            )
        if 'port:' not in after_restart or 'webBasePath:' not in after_restart:
            raise DeployError(f'Unexpected 3x-ui setting output after restart: {after_restart}')

        print(f'[xui] credentials updated and verified with CLI {cli}')
        return cli

    def _resolve_sui_cli(self, configured: str) -> str:
        candidates = _SUI_CLI_CANDIDATES if configured in {'', 'auto'} else (configured,)
        for candidate in candidates:
            probe = run(
                ['docker', 'exec', 's-ui', 'sh', '-c', f'test -x {candidate} || command -v {candidate} >/dev/null 2>&1'],
                check=False,
                capture=True,
            )
            if probe.returncode == 0:
                return candidate
        raise DeployError(
            'Unable to locate the S-UI CLI in the container. '
            f'Tried: {", ".join(candidates)}. Set panel.sui.cli explicitly.'
        )

    def _run_sui(self, cli: str, *arguments: str, redact_values: set[str] | None = None) -> str:
        result = run(
            ['docker', 'exec', 's-ui', cli, *arguments],
            check=False,
            capture=True,
            redact_values=redact_values,
        )
        output = '\n'.join(part for part in (result.stdout, result.stderr) if part).strip()
        if result.returncode != 0:
            safe_arguments = [
                '********' if redact_values and value in redact_values else value
                for value in arguments
            ]
            raise DeployError(
                f'S-UI rejected {" ".join(safe_arguments)!r} with {cli!r}: {output or "no output"}'
            )
        return output

    def _configure_sui(self, username: str, password: str, configured_cli: str,
                       allow_default_credentials: bool, panel_port: int, panel_path: str,
                       subscription_port: int, subscription_path: str) -> str:
        self._wait_container('s-ui')
        cli = self._resolve_sui_cli(configured_cli)
        self._run_sui(
            cli, 'admin', '-username', username, '-password', password,
            redact_values={password},
        )
        self._run_sui(
            cli, 'setting',
            '-port', str(panel_port), '-path', panel_path,
            '-subPort', str(subscription_port), '-subPath', subscription_path,
        )

        run(['docker', 'restart', 's-ui'])
        self._wait_container('s-ui')
        time.sleep(2)
        admin = self._run_sui(cli, 'admin', '-show')
        settings = self._run_sui(cli, 'setting', '-show')
        if username not in admin and not allow_default_credentials:
            raise DeployError(
                'S-UI did not report the configured administrator after restart; '
                'check /app/db persistence and panel.sui.cli.'
            )
        for expected in (str(panel_port), str(subscription_port)):
            if expected not in settings:
                raise DeployError(
                    f'S-UI settings after restart do not contain expected port {expected}: {settings}'
                )
        print(f'[sui] credentials and endpoints updated and verified with CLI {cli}')
        return cli

    def verify(self, context: DeploymentContext) -> None:
        run(['docker', 'compose', 'ps'], cwd=context.stack_dir)
        credentials = context.stack_dir / 'state' / 'credentials.json'
        if not credentials.is_file() or credentials.stat().st_mode & 0o077:
            raise DeployError('Credential state file is missing or has unsafe permissions')
