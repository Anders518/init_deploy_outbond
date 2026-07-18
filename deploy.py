#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError as exc:
    raise SystemExit('Python 3.11 or newer is required') from exc

from vpsdeploy.application import deploy, status, update
from vpsdeploy.config import validate_config
from vpsdeploy.core.runtime import DeployError, DeploymentContext


def load_config(path: Path) -> dict:
    if not path.is_file():
        raise DeployError(f'Configuration file not found: {path}')
    with path.open('rb') as handle:
        return tomllib.load(handle)


def _read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw in path.read_text(encoding='utf-8').splitlines():
        line = raw.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        values[key.strip()] = value
    return values


def show_credentials(context: DeploymentContext) -> None:
    path = context.stack_dir / 'state' / 'credentials.json'
    found = False
    if path.is_file():
        found = True
        data = json.loads(path.read_text(encoding='utf-8'))
        print('Proxy stack credentials')
        print('=======================')
        print(f"Panel URL: {data.get('panel_url', '')}")
        caddy = data.get('caddy', {})
        print('\nCaddy BasicAuth')
        print(f"Username: {caddy.get('username', '')}")
        print(f"Password: {caddy.get('password', '')}")
        backend = str(data.get('backend', '3x-ui'))
        backend_key = 'sui' if backend == 's-ui' else 'xui'
        backend_data = data.get(backend_key, {})
        print(f'\n{backend}')
        print(f"Enabled: {backend_data.get('enabled', False)}")
        print(f"Username: {backend_data.get('username', '')}")
        print(f"Password: {backend_data.get('password', '')}")
        print(f'\nSource: {path}')

    sub2api_cfg = context.config.get('sub2api', {})
    if isinstance(sub2api_cfg, dict) and bool(sub2api_cfg.get('enabled', False)):
        install_dir = Path(str(sub2api_cfg.get('install_dir', '/opt/sub2api'))).resolve()
        sub_path = install_dir / 'state' / 'credentials.json'
        env_path = install_dir / '.env'
        if sub_path.is_file() or env_path.is_file():
            found = True
            data = json.loads(sub_path.read_text(encoding='utf-8')) if sub_path.is_file() else {}
            env = _read_env(env_path)
            print('\nSub2API credentials')
            print('===================')
            print(f"URL: {data.get('url', '')}")
            print(f"Admin email: {data.get('admin_email', env.get('ADMIN_EMAIL', ''))}")
            print(f"Admin password: {env.get('ADMIN_PASSWORD', '')}")
            print(f"PostgreSQL password: {env.get('POSTGRES_PASSWORD', '')}")
            print(f"Redis password: {env.get('REDIS_PASSWORD', '')}")
            print(f"JWT secret: {env.get('JWT_SECRET', '')}")
            print(f"TOTP key: {env.get('TOTP_ENCRYPTION_KEY', '')}")
            print(f'\nSecret source: {env_path}')
            if sub_path.is_file():
                print(f'Metadata source: {sub_path}')

    if not found:
        raise DeployError('No generated credential files were found')


def print_sensitive_results(context: DeploymentContext) -> None:
    sudo_password = context.state.get('generated_admin_password')
    sudo_user = context.state.get('generated_admin_user')
    if sudo_password and sudo_user:
        print('\n============================================================')
        print('Generated sudo password — shown once; store it securely')
        print('============================================================')
        print(f'User: {sudo_user}')
        print(f'Password: {sudo_password}')
        print('SSH password authentication remains disabled; this password is for sudo only.')

    generated = context.state.get('generated_credentials')
    generated_sub2api = context.state.get('generated_sub2api_credentials')
    if generated or generated_sub2api:
        print('\nDeployment completed.')
        if generated_sub2api:
            values = generated_sub2api.get('values', {})
            print('\nSub2API credentials — shown from the runtime .env source')
            print('========================================================')
            print(f"URL: {generated_sub2api.get('url', '')}")
            print(f"Admin email: {generated_sub2api.get('admin_email', '')}")
            print(f"Admin password: {values.get('admin_password', '')}")
            print(f"PostgreSQL password: {values.get('postgres_password', '')}")
            print(f"Redis password: {values.get('redis_password', '')}")
            print(f"JWT secret: {values.get('jwt_secret', '')}")
            print(f"TOTP key: {values.get('totp_key', '')}")
            print(f"Secret source: {generated_sub2api.get('path', '')}")
        if generated:
            print('\nView proxy credentials: sudo uv run --no-dev --frozen python deploy.py credentials')
            print(f"Credential file: {generated.get('path', context.stack_dir / 'state/credentials.json')}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='Task-oriented VPS proxy deployment')
    parser.add_argument('--config', type=Path, default=Path('config.toml'))
    parser.add_argument('--dry-run', action='store_true')
    sub = parser.add_subparsers(dest='command', required=True)
    deploy_parser = sub.add_parser('deploy')
    deploy_parser.add_argument('--task', action='append', dest='tasks', help='Run only the named task; repeatable')
    sub.add_parser('status')
    sub.add_parser('update')
    sub.add_parser('credentials')
    sub.add_parser('list-tasks')
    sub.add_parser('tui')
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        config = load_config(args.config)
        validate_config(config)
        context = DeploymentContext(config=config, dry_run=args.dry_run)
        if args.command == 'deploy':
            deploy(context, set(args.tasks or []))
            if not args.dry_run:
                print_sensitive_results(context)
        elif args.command == 'status':
            status(context)
        elif args.command == 'update':
            update(context)
        elif args.command == 'credentials':
            if os.geteuid() != 0:
                raise DeployError('Run credentials as root because credential files are root-readable only')
            show_credentials(context)
        elif args.command == 'tui':
            from vpsdeploy.tui import run_tui
            run_tui(args.config)
        else:
            from vpsdeploy.application import DEPLOY_TASKS
            for task in DEPLOY_TASKS:
                print(task.name)
        return 0
    except (DeployError, subprocess.CalledProcessError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f'\033[1;31m[-] {exc}\033[0m', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
