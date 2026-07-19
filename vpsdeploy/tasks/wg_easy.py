from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from vpsdeploy.core.runtime import DeployError, DeploymentContext, Task, run, section, write_file


def _config(context: DeploymentContext) -> dict[str, Any]:
    value = context.config.get('wg_easy', {})
    if not isinstance(value, dict):
        raise DeployError('wg_easy must be a TOML table')
    return value


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


class WgEasyTask(Task):
    name = 'wg-easy'

    def enabled(self, context: DeploymentContext) -> bool:
        return bool(_config(context).get('enabled', False))

    def validate(self, context: DeploymentContext) -> None:
        cfg = _config(context)
        transport = str(cfg.get('transport', 'anytls')).strip().lower()
        if transport not in {'anytls', 'direct'}:
            raise DeployError('wg_easy.transport must be "anytls" or "direct"')
        for key, default in (('wireguard_port', 51820), ('ui_port', 51821), ('client_relay_port', 51820)):
            value = cfg.get(key, default)
            if not isinstance(value, int) or not 1 <= value <= 65535:
                raise DeployError(f'wg_easy.{key} must be an integer between 1 and 65535')
        if transport == 'anytls':
            backend = str(section(context.config, 'panel').get('backend', '3x-ui')).strip().lower()
            if backend != 's-ui':
                raise DeployError('wg_easy.transport="anytls" requires panel.backend="s-ui"')
            node = context.config.get('node', {})
            if not isinstance(node, dict) or not bool(node.get('enabled', True)):
                raise DeployError('wg_easy.transport="anytls" requires node.enabled=true')
        if bool(cfg.get('init_enabled', False)):
            env_name = str(cfg.get('init_password_env', 'VPSDEPLOY_WG_EASY_PASSWORD')).strip()
            if not env_name or not os.environ.get(env_name, ''):
                raise DeployError(f'Set {env_name} when wg_easy.init_enabled=true')

    def apply(self, context: DeploymentContext) -> None:
        cfg = _config(context)
        transport = str(cfg.get('transport', 'anytls')).strip().lower()
        install_dir = Path(str(cfg.get('install_dir', '/opt/wg-easy'))).resolve()
        data_dir = install_dir / 'data'
        state_dir = install_dir / 'state'
        data_dir.mkdir(parents=True, exist_ok=True)
        state_dir.mkdir(parents=True, exist_ok=True)

        image = str(cfg.get('image', 'ghcr.io/wg-easy/wg-easy:15')).strip()
        wireguard_port = int(cfg.get('wireguard_port', 51820))
        ui_port = int(cfg.get('ui_port', 51821))
        ui_bind = str(cfg.get('ui_bind', '127.0.0.1')).strip() or '127.0.0.1'
        network_name = str(section(context.config, 'docker').get('network_name', 'proxy_stack')).strip()

        if run(['docker', 'network', 'inspect', network_name], check=False, capture=True).returncode != 0:
            raise DeployError(
                f'Docker network {network_name!r} does not exist; run proxy-stack before wg-easy'
            )

        init_enabled = bool(cfg.get('init_enabled', False))
        env_lines = [
            f'WG_EASY_IMAGE={image}',
            f'WG_EASY_UI_PORT={ui_port}',
            f'WG_EASY_WG_PORT={wireguard_port}',
            f'WG_EASY_UI_BIND={ui_bind}',
        ]
        init_block = ''
        init_password = ''
        if init_enabled:
            env_name = str(cfg.get('init_password_env', 'VPSDEPLOY_WG_EASY_PASSWORD')).strip()
            init_password = os.environ[env_name]
            init_host_default = '127.0.0.1' if transport == 'anytls' else str(section(context.config, 'domains')['node'])
            init_host = str(cfg.get('init_host', init_host_default)).strip() or init_host_default
            init_username = str(cfg.get('init_username', 'admin')).strip() or 'admin'
            init_dns = str(cfg.get('init_dns', '1.1.1.1,8.8.8.8')).strip()
            init_ipv4 = str(cfg.get('init_ipv4_cidr', '10.8.0.0/24')).strip()
            init_ipv6 = str(cfg.get('init_ipv6_cidr', 'fd42:42:42::/64')).strip()
            env_lines.append(f'WG_EASY_INIT_PASSWORD={init_password}')
            init_block = f'''      INIT_ENABLED: "true"
      INIT_USERNAME: "{init_username}"
      INIT_PASSWORD: ${{WG_EASY_INIT_PASSWORD}}
      INIT_HOST: "{init_host}"
      INIT_PORT: "{wireguard_port}"
      INIT_DNS: "{init_dns}"
      INIT_IPV4_CIDR: "{init_ipv4}"
      INIT_IPV6_CIDR: "{init_ipv6}"
'''

        udp_publish = ''
        if transport == 'direct':
            udp_publish = '      - "${WG_EASY_WG_PORT}:${WG_EASY_WG_PORT}/udp"\n'

        compose = f'''services:
  wg-easy:
    image: ${{WG_EASY_IMAGE}}
    container_name: wg-easy
    restart: unless-stopped
    environment:
      PORT: "51821"
      HOST: "0.0.0.0"
      INSECURE: "true"
{init_block}    volumes:
      - ./data:/etc/wireguard
      - /lib/modules:/lib/modules:ro
    ports:
      - "${{WG_EASY_UI_BIND}}:${{WG_EASY_UI_PORT}}:51821/tcp"
{udp_publish}    expose:
      - "${{WG_EASY_WG_PORT}}/udp"
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    sysctls:
      net.ipv4.ip_forward: "1"
      net.ipv4.conf.all.src_valid_mark: "1"
      net.ipv6.conf.all.disable_ipv6: "0"
      net.ipv6.conf.all.forwarding: "1"
      net.ipv6.conf.default.forwarding: "1"
    networks:
      - proxy_stack

networks:
  proxy_stack:
    external: true
    name: {network_name}
'''
        write_file(install_dir / '.env', '\n'.join(env_lines) + '\n', 0o600)
        write_file(install_dir / 'docker-compose.yml', compose, 0o600)
        run(['docker', 'compose', 'pull'], cwd=install_dir)
        run(['docker', 'compose', 'up', '-d', '--remove-orphans'], cwd=install_dir)

        if init_enabled:
            # wg-easy only consumes INIT_* during first setup. Remove the plaintext
            # password from disk immediately after the initial container launch.
            clean_env = [line for line in env_lines if not line.startswith('WG_EASY_INIT_PASSWORD=')]
            write_file(install_dir / '.env', '\n'.join(clean_env) + '\n', 0o600)

        if transport == 'anytls':
            relay = self._render_anytls_relay(context, cfg, wireguard_port)
            write_file(state_dir / 'anytls-relay.json', json.dumps(relay, indent=2, ensure_ascii=False), 0o600)
            guide = (
                'Run this sing-box config on the WireGuard client device before enabling WireGuard:\n'
                f'  {state_dir / "anytls-relay.json"}\n\n'
                f'WireGuard Endpoint must be {cfg.get("client_relay_listen", "127.0.0.1")}:'
                f'{int(cfg.get("client_relay_port", 51820))}.\n'
                'The relay sends UDP through the managed AnyTLS node to wg-easy:51820 on the server Docker network.\n'
            )
            write_file(state_dir / 'README.txt', guide, 0o600)

        context.state['wg_easy'] = {
            'install_dir': str(install_dir),
            'transport': transport,
            'ui': f'http://{ui_bind}:{ui_port}',
            'relay_config': str(state_dir / 'anytls-relay.json') if transport == 'anytls' else '',
        }

    def _render_anytls_relay(
        self, context: DeploymentContext, cfg: dict[str, Any], wireguard_port: int
    ) -> dict[str, Any]:
        client = _read_json(context.stack_dir / 'state/anytls-client.json')
        if client.get('protocol') != 'anytls':
            raise DeployError('Managed AnyTLS client state is unavailable; run node-config before wg-easy')
        required = ('address', 'port', 'password', 'server_name')
        if any(not client.get(key) for key in required):
            raise DeployError('Managed AnyTLS client state is incomplete')
        relay_listen = str(cfg.get('client_relay_listen', '127.0.0.1')).strip() or '127.0.0.1'
        relay_port = int(cfg.get('client_relay_port', 51820))
        target = str(cfg.get('server_target', 'wg-easy')).strip() or 'wg-easy'
        return {
            'log': {'level': 'info', 'timestamp': True},
            'inbounds': [{
                'type': 'direct',
                'tag': 'wireguard-local',
                'listen': relay_listen,
                'listen_port': relay_port,
                'network': 'udp',
                'override_address': target,
                'override_port': wireguard_port,
            }],
            'outbounds': [{
                'type': 'anytls',
                'tag': 'managed-anytls',
                'server': client['address'],
                'server_port': int(client['port']),
                'password': client['password'],
                'tls': {
                    'enabled': True,
                    'server_name': client['server_name'],
                    'utls': {
                        'enabled': True,
                        'fingerprint': str(client.get('fingerprint', 'chrome')),
                    },
                },
            }],
            'route': {'final': 'managed-anytls'},
        }

    def verify(self, context: DeploymentContext) -> None:
        cfg = _config(context)
        result = run(
            ['docker', 'inspect', '-f', '{{.State.Running}}', 'wg-easy'],
            check=False,
            capture=True,
        )
        if result.returncode != 0 or result.stdout.strip() != 'true':
            run(['docker', 'logs', '--tail', '100', 'wg-easy'], check=False)
            raise DeployError('wg-easy container is not running')
        if str(cfg.get('transport', 'anytls')).strip().lower() == 'anytls':
            published = run(
                ['docker', 'port', 'wg-easy', f"{int(cfg.get('wireguard_port', 51820))}/udp"],
                check=False,
                capture=True,
            )
            if published.stdout.strip():
                raise DeployError('wg-easy WireGuard UDP port is unexpectedly published in anytls mode')
