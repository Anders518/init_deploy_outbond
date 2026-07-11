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
from vpsdeploy.core.runtime import DeployError, DeploymentContext


def load_config(path: Path) -> dict:
    if not path.is_file():
        raise DeployError(f'Configuration file not found: {path}')
    with path.open('rb') as handle:
        return tomllib.load(handle)


def show_credentials(context: DeploymentContext) -> None:
    path = context.stack_dir / 'state' / 'credentials.json'
    if not path.is_file():
        raise DeployError(f'Credentials have not been generated yet: {path}')
    data = json.loads(path.read_text(encoding='utf-8'))
    print('Deployment credentials')
    print('======================')
    print(f"Panel URL: {data.get('panel_url', '')}")
    caddy = data.get('caddy', {})
    print('\nCaddy BasicAuth')
    print(f"Username: {caddy.get('username', '')}")
    print(f"Password: {caddy.get('password', '')}")
    xui = data.get('xui', {})
    print('\n3x-ui')
    print(f"Enabled: {xui.get('enabled', False)}")
    print(f"Username: {xui.get('username', '')}")
    print(f"Password: {xui.get('password', '')}")
    print(f'\nSource: {path}')


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
    if generated:
        print('\nDeployment completed.')
        print(f"Credentials file: {generated['path']}")
        print('View credentials: sudo python3 deploy.py credentials')
        if generated.get('caddy') or generated.get('xui'):
            print('One or more panel passwords were generated automatically; review and store them now.')
            show_credentials(context)


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
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        config = load_config(args.config)
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
                raise DeployError('Run credentials as root because the credential file is root-readable only')
            show_credentials(context)
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
