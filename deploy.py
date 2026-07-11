#!/usr/bin/env python3
from __future__ import annotations

import argparse
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='Task-oriented VPS proxy deployment')
    parser.add_argument('--config', type=Path, default=Path('config.toml'))
    parser.add_argument('--dry-run', action='store_true')
    sub = parser.add_subparsers(dest='command', required=True)
    deploy_parser = sub.add_parser('deploy')
    deploy_parser.add_argument('--task', action='append', dest='tasks', help='Run only the named task; repeatable')
    sub.add_parser('status')
    sub.add_parser('update')
    sub.add_parser('list-tasks')
    return parser


def print_sensitive_results(context: DeploymentContext) -> None:
    password = context.state.get('generated_admin_password')
    username = context.state.get('generated_admin_user')
    if password and username:
        print('\n============================================================')
        print('Generated sudo password — shown once; store it securely')
        print('============================================================')
        print(f'User: {username}')
        print(f'Password: {password}')
        print('SSH password authentication remains disabled; this password is for sudo only.')


def main() -> int:
    args = build_parser().parse_args()
    try:
        config = load_config(args.config)
        context = DeploymentContext(config=config, dry_run=args.dry_run)
        if args.command == 'deploy':
            deploy(context, set(args.tasks or []))
            print_sensitive_results(context)
        elif args.command == 'status':
            status(context)
        elif args.command == 'update':
            update(context)
        else:
            from vpsdeploy.application import DEPLOY_TASKS
            for task in DEPLOY_TASKS:
                print(task.name)
        return 0
    except (DeployError, subprocess.CalledProcessError, OSError, ValueError) as exc:
        print(f'\033[1;31m[-] {exc}\033[0m', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
