from __future__ import annotations

import secrets
import string

from vpsdeploy.core.runtime import DeployError, DeploymentContext, Task, run, section, write_file
from vpsdeploy.templates.render import render_caddy, render_compose


class ProxyStackTask(Task):
    name = 'proxy-stack'

    def apply(self, context: DeploymentContext) -> None:
        stack = context.stack_dir
        for rel in ('3x-ui/db', '3x-ui/cert', 'caddy/data', 'caddy/config', 'caddy-build', 'secrets', 'backups'):
            (stack / rel).mkdir(parents=True, exist_ok=True)
        tls = context.state['tls']
        panel, ports, docker, stack_cfg = (section(context.config, 'panel'), section(context.config, 'ports'),
                                            section(context.config, 'docker'), section(context.config, 'stack'))
        password = str(panel.get('basic_auth_password', '')).strip() or ''.join(
            secrets.choice(string.ascii_letters + string.digits) for _ in range(28))
        hashed = run(['docker', 'run', '--rm', 'caddy:2-alpine', 'caddy', 'hash-password', '--plaintext', password], capture=True).stdout.strip()
        if not hashed.startswith('$2'):
            raise DeployError('Failed to generate Caddy password hash')
        env = [f"TZ={stack_cfg.get('timezone', 'UTC')}", f"XUI_IMAGE={docker['xui_image']}",
               f"CADDY_IMAGE={docker['caddy_image']}", f"PROXY_PORT={ports['proxy']}",
               f"PANEL_PUBLIC_PORT={ports['panel_public']}"]
        for key, value in (tls.environment or {}).items():
            env.append(f'{key}={value}')
        write_file(stack / '.env', '\n'.join(env), 0o600)
        write_file(stack / 'docker-compose.yml', render_compose(context, tls), 0o600)
        write_file(stack / 'Caddyfile', render_caddy(context, tls, hashed), 0o600)
        if tls.requires_custom_caddy:
            write_file(stack / 'caddy-build/Dockerfile',
                       'FROM caddy:2-builder-alpine AS builder\nRUN xcaddy build --with github.com/caddy-dns/cloudflare\nFROM caddy:2-alpine\nCOPY --from=builder /usr/bin/caddy /usr/bin/caddy\n', 0o644)
            run(['docker', 'compose', 'build', '--pull', 'caddy'], cwd=stack)
        else:
            run(['docker', 'pull', str(docker['caddy_image'])])
        write_file(stack / 'secrets.txt', f'Caddy BasicAuth user: {panel["basic_auth_user"]}\nCaddy BasicAuth password: {password}', 0o600)
        run(['docker', 'compose', 'pull', '3x-ui'], cwd=stack)
        run(['docker', 'compose', 'up', '-d', '--remove-orphans'], cwd=stack)

    def verify(self, context: DeploymentContext) -> None:
        run(['docker', 'compose', 'ps'], cwd=context.stack_dir)
