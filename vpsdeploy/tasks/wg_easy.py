from __future__ import annotations

import getpass
import ipaddress
import json
import os
import secrets
import string
import time
from pathlib import Path
from typing import Any

from vpsdeploy.core.runtime import DeployError, DeploymentContext, FileSnapshot, Task, run, section, write_file
from vpsdeploy.templates.wg_easy import render_wg_easy_compose


def _cfg(context: DeploymentContext) -> dict[str, Any]:
    value = context.config.get('wg_easy', {})
    if not isinstance(value, dict):
        raise DeployError('wg_easy must be a TOML table')
    return value


def _random_password(length: int = 28) -> str:
    alphabet = string.ascii_letters + string.digits + '!@#%^*-_=+'
    return ''.join(secrets.choice(alphabet) for _ in range(length))


class WGEasyTask(Task):
    name = 'wg-easy'

    def enabled(self, context: DeploymentContext) -> bool:
        return bool(_cfg(context).get('enabled', False))

    def validate(self, context: DeploymentContext) -> None:
        cfg = _cfg(context)
        if str(cfg.get('web_bind', '127.0.0.1')) != '127.0.0.1':
            raise DeployError('wg_easy.web_bind must be loopback; the Web UI must not be public')
        for key, default in (('web_port', 51821), ('wireguard_port', 51820)):
            port = cfg.get(key, default)
            if not isinstance(port, int) or not 1 <= port <= 65535:
                raise DeployError(f'wg_easy.{key} must be an integer between 1 and 65535')
        ssh_port = cfg.get('ssh_forward_port', 4522)
        if bool(cfg.get('ssh_forward_enabled', False)) and (
            not isinstance(ssh_port, int) or not 1 <= ssh_port <= 65535
        ):
            raise DeployError('wg_easy.ssh_forward_port must be an integer between 1 and 65535')
        ipv4 = ipaddress.ip_network(str(cfg.get('ipv4_cidr', '10.66.66.0/24')), strict=False)
        ipv6 = ipaddress.ip_network(str(cfg.get('ipv6_cidr', 'fd42:66:66::/64')), strict=False)
        if ipv4.version != 4 or ipv6.version != 6:
            raise DeployError('wg_easy IPv4/IPv6 CIDRs have the wrong address family')
        if ipv4.num_addresses < 4:
            raise DeployError('wg_easy.ipv4_cidr must contain a usable server address')
        if str(cfg.get('admin_password_mode', 'generate')) not in {'generate', 'prompt', 'environment'}:
            raise DeployError('wg_easy.admin_password_mode must be generate, prompt, or environment')

    def prepare_rollback(self, context: DeploymentContext) -> dict[str, Any]:
        cfg = _cfg(context)
        install = Path(str(cfg.get('install_dir', '/opt/wg-easy'))).resolve()
        existed = run(['docker', 'inspect', 'wg-easy'], check=False, capture=True).returncode == 0
        running = run(['docker', 'inspect', '-f', '{{.State.Running}}', 'wg-easy'], check=False, capture=True)
        return {
            'existed': existed,
            'running': running.returncode == 0 and running.stdout.strip() == 'true',
            'files': [FileSnapshot.capture(install / name) for name in (
                'docker-compose.yml', '.env', 'state/credentials.json',
                'state/mihomo-route.yaml', 'state/mihomo-wg-gateway.yaml',
            )],
            'install': install,
        }

    def rollback(self, context: DeploymentContext, snapshot: dict[str, Any]) -> None:
        install = snapshot['install']
        if not snapshot['existed'] and (install / 'docker-compose.yml').is_file():
            run(['docker', 'compose', 'down'], cwd=install, check=False)
        for item in snapshot['files']:
            item.restore()
        if snapshot['existed'] and snapshot['running'] and (install / 'docker-compose.yml').is_file():
            run(['docker', 'compose', 'up', '-d', '--remove-orphans'], cwd=install, check=False)

    def _password(self, cfg: dict[str, Any], existing: str) -> tuple[str, bool]:
        if existing:
            return existing, False
        mode = str(cfg.get('admin_password_mode', 'generate'))
        if mode == 'generate':
            return _random_password(), True
        if mode == 'environment':
            value = os.environ.get(str(cfg.get('admin_password_env', 'VPSDEPLOY_WG_EASY_ADMIN_PASSWORD')), '')
            if not value:
                raise DeployError('Set VPSDEPLOY_WG_EASY_ADMIN_PASSWORD for wg-easy')
            return value, False
        first = getpass.getpass('wg-easy admin password: ')
        second = getpass.getpass('Confirm wg-easy admin password: ')
        if not first or first != second:
            raise DeployError('wg-easy admin passwords are empty or do not match')
        return first, False

    @staticmethod
    def _proxy_endpoint(network_name: str, existing: str) -> str:
        if existing:
            return str(ipaddress.ip_address(existing))
        result = run(['docker', 'network', 'inspect', network_name], capture=True)
        data = json.loads(result.stdout)[0]
        subnets = [row.get('Subnet', '') for row in data.get('IPAM', {}).get('Config', [])]
        networks = [ipaddress.ip_network(value) for value in subnets if value]
        network = next((item for item in networks if item.version == 4), None)
        if network is None or network.num_addresses < 32:
            raise DeployError(f'Docker network {network_name} has no usable IPv4 subnet')
        used = {
            ipaddress.ip_address(row['IPv4Address'].split('/')[0])
            for row in (data.get('Containers') or {}).values() if row.get('IPv4Address')
        }
        for offset in range(10, min(250, network.num_addresses - 2)):
            candidate = network.broadcast_address - offset
            if candidate not in used:
                return str(candidate)
        raise DeployError(f'Unable to allocate a private endpoint in Docker network {network_name}')

    def apply(self, context: DeploymentContext) -> None:
        cfg = _cfg(context)
        install = Path(str(cfg.get('install_dir', '/opt/wg-easy'))).resolve()
        for rel in ('data', 'state', 'backups'):
            (install / rel).mkdir(parents=True, exist_ok=True)
        credentials_path = install / 'state/credentials.json'
        existing = json.loads(credentials_path.read_text()) if credentials_path.is_file() else {}
        password, generated = self._password(cfg, str(existing.get('admin_password', '')))
        network_name = str(section(context.config, 'docker').get('network_name', 'proxy_stack'))
        endpoint = self._proxy_endpoint(network_name, str(existing.get('proxy_endpoint', '')))
        network_result = run(['docker', 'network', 'inspect', network_name], capture=True)
        network_data = json.loads(network_result.stdout)[0]
        network_rows = network_data.get('IPAM', {}).get('Config', [])
        gateway = next((str(row.get('Gateway', '')) for row in network_rows if row.get('Gateway') and ':' not in str(row.get('Gateway'))), '')
        if not gateway:
            raise DeployError(f'Docker network {network_name} has no IPv4 gateway')
        ipv4_network = ipaddress.ip_network(str(cfg.get('ipv4_cidr', '10.66.66.0/24')), strict=False)
        virtual_ssh_ip = str(next(ipv4_network.hosts()))
        admin = str(cfg.get('admin_username', 'admin'))
        env = {
            'WG_EASY_IMAGE': str(cfg.get('image', 'ghcr.io/wg-easy/wg-easy:15')),
            'WG_ADMIN_USERNAME': admin,
            'WG_ADMIN_PASSWORD': password,
            'WG_PROXY_ENDPOINT': endpoint,
            'WG_PORT': str(int(cfg.get('wireguard_port', 51820))),
            'WG_WEB_PORT': str(int(cfg.get('web_port', 51821))),
            'WG_DNS': str(cfg.get('dns', '1.1.1.1,8.8.8.8')),
            'WG_IPV4_CIDR': str(cfg.get('ipv4_cidr', '10.66.66.0/24')),
            'WG_IPV6_CIDR': str(cfg.get('ipv6_cidr', 'fd42:66:66::/64')),
            'WG_SSH_VIRTUAL_IP': virtual_ssh_ip,
            'WG_HOST_GATEWAY': gateway,
            'WG_SSH_PORT': str(int(cfg.get('ssh_forward_port', 4522))),
            'PROXY_NETWORK': network_name,
            'LOG_MAX_SIZE': str(section(context.config, 'docker').get('log_max_size', '10m')),
            'LOG_MAX_FILE': str(int(section(context.config, 'docker').get('log_max_file', 3))),
        }
        initialize = not any((install / 'data').iterdir())
        runtime_env = env if initialize else {
            key: value for key, value in env.items()
            if key not in {'WG_ADMIN_USERNAME', 'WG_ADMIN_PASSWORD'}
        }
        write_file(install / '.env', '\n'.join(f'{key}={value}' for key, value in runtime_env.items()), 0o600)
        write_file(install / 'docker-compose.yml', render_wg_easy_compose(cfg, initialize=initialize), 0o600)
        run(['docker', 'compose', 'config', '--quiet'], cwd=install)
        run(['docker', 'compose', 'pull'], cwd=install)
        run(['docker', 'compose', 'up', '-d', '--remove-orphans'], cwd=install)
        self._wait_ready(int(cfg.get('readiness_timeout', 120)))
        if initialize:
            # v15 bootstrap variables are one-shot. Remove the plaintext
            # password from Compose, .env, and the live container immediately
            # after the database has been initialized.
            steady_env = {
                key: value for key, value in env.items()
                if key not in {'WG_ADMIN_USERNAME', 'WG_ADMIN_PASSWORD'}
            }
            write_file(install / '.env', '\n'.join(f'{key}={value}' for key, value in steady_env.items()), 0o600)
            write_file(install / 'docker-compose.yml', render_wg_easy_compose(cfg, initialize=False), 0o600)
            run(['docker', 'compose', 'up', '-d', '--remove-orphans'], cwd=install)
            self._wait_ready(int(cfg.get('readiness_timeout', 120)))

        credentials = {
            'admin_username': admin, 'admin_password': password,
            'web_url': f"http://127.0.0.1:{int(cfg.get('web_port', 51821))}",
            'proxy_endpoint': endpoint, 'wireguard_port': int(cfg.get('wireguard_port', 51820)),
            'ssh_forward_enabled': bool(cfg.get('ssh_forward_enabled', False)),
            'ssh_endpoint': f'{virtual_ssh_ip}:{int(cfg.get("ssh_forward_port", 4522))}',
            'generated': generated,
        }
        write_file(credentials_path, json.dumps(credentials, indent=2), 0o600)
        route = f'''# Merge into the Mihomo profile that contains the AnyTLS node/group.
# The private endpoint is reachable only through the AnyTLS UDP relay.
proxies:
  # Ensure the imported AnyTLS proxy has: udp: true
rules:
  - IP-CIDR,{endpoint}/32,主代理,no-resolve
  - MATCH,主代理
tun:
  enable: true
  route-address:
    - {endpoint}/32
  strict-route: true
'''
        write_file(install / 'state/mihomo-route.yaml', route, 0o600)
        source_profile = context.stack_dir / 'state/mihomo-test.yaml'
        if not source_profile.is_file():
            raise DeployError('Mihomo AnyTLS profile is missing; run node-config before wg-easy')
        try:
            strict_profile = json.loads(source_profile.read_text(encoding='utf-8'))
        except json.JSONDecodeError as exc:
            raise DeployError('Unable to parse the generated Mihomo profile') from exc
        proxies = strict_profile.get('proxies') or []
        if not proxies or any(proxy.get('udp') is not True for proxy in proxies):
            raise DeployError('Refusing wg-easy deployment because the Mihomo node is not udp:true')
        strict_profile.update({
            'mode': 'rule',
            'ipv6': True,
            'rules': [
                f'IP-CIDR,{endpoint}/32,GLOBAL,no-resolve',
                'MATCH,GLOBAL',
            ],
            'tun': {
                'enable': True,
                'stack': 'mixed',
                'auto-route': True,
                'auto-detect-interface': True,
                'strict-route': True,
                'route-address': [f'{endpoint}/32'],
            },
        })
        write_file(
            install / 'state/mihomo-wg-gateway.yaml',
            json.dumps(strict_profile, indent=2, ensure_ascii=False), 0o600,
        )
        context.state['wg_easy_credentials'] = credentials

    @staticmethod
    def _wait_ready(timeout: int) -> None:
        for _ in range(max(timeout, 1)):
            running = run(['docker', 'inspect', '-f', '{{.State.Running}} {{.State.Restarting}}', 'wg-easy'], check=False, capture=True)
            wg = run(['docker', 'exec', 'wg-easy', 'wg', 'show'], check=False, capture=True)
            if running.returncode == 0 and running.stdout.strip() == 'true false' and wg.returncode == 0:
                return
            time.sleep(1)
        run(['docker', 'logs', '--tail', '100', 'wg-easy'], check=False)
        raise DeployError('wg-easy did not become ready')

    def verify(self, context: DeploymentContext) -> None:
        cfg = _cfg(context)
        inspect = run(['docker', 'inspect', 'wg-easy'], capture=True)
        data = json.loads(inspect.stdout)[0]
        bindings = data.get('HostConfig', {}).get('PortBindings') or {}
        if bindings.get(f"{int(cfg.get('wireguard_port', 51820))}/udp"):
            raise DeployError('Refusing public WireGuard: UDP port is bound on the host')
        web = bindings.get('51821/tcp') or []
        if not web or any(row.get('HostIp') not in {'127.0.0.1', '::1'} for row in web):
            raise DeployError('wg-easy Web UI is not restricted to loopback')
        credentials = context.state.get('wg_easy_credentials', {})
        endpoint = str(credentials.get('proxy_endpoint', ''))
        network_name = str(section(context.config, 'docker').get('network_name', 'proxy_stack'))
        network = data.get('NetworkSettings', {}).get('Networks', {}).get(network_name, {})
        if network.get('IPAddress') != endpoint:
            raise DeployError('wg-easy did not receive its fixed proxy-network endpoint')
        backend = str(section(context.config, 'panel').get('backend', '3x-ui')).strip().lower()
        proxy_container = 's-ui' if backend == 's-ui' else '3x-ui'
        proxy = run(['docker', 'inspect', '-f', f'{{{{index .NetworkSettings.Networks "{network_name}"}}}}', proxy_container], check=False, capture=True)
        if proxy.returncode != 0 or not proxy.stdout.strip():
            raise DeployError(f'{proxy_container} and wg-easy do not share the proxy network')
        if bool(cfg.get('ssh_forward_enabled', False)):
            ssh_port = int(cfg.get('ssh_forward_port', 4522))
            ipv4_network = ipaddress.ip_network(str(cfg.get('ipv4_cidr', '10.66.66.0/24')), strict=False)
            virtual_ip = str(next(ipv4_network.hosts()))
            network_rows = run(['docker', 'network', 'inspect', network_name], capture=True)
            network_data = json.loads(network_rows.stdout)[0]
            gateway = next((str(row.get('Gateway', '')) for row in network_data.get('IPAM', {}).get('Config', []) if row.get('Gateway') and ':' not in str(row.get('Gateway'))), '')
            for _ in range(15):
                helper = run(['docker', 'inspect', '-f', '{{.State.Running}}', 'wg-easy-ssh-forward'], check=False, capture=True)
                dnat = run([
                    'docker', 'exec', 'wg-easy', 'iptables', '-t', 'nat', '-C', 'PREROUTING',
                    '-i', 'wg0', '-s', str(ipv4_network), '-d', f'{virtual_ip}/32',
                    '-p', 'tcp', '--dport', str(ssh_port), '-j', 'DNAT',
                    '--to-destination', f'{gateway}:{ssh_port}',
                ], check=False, capture=True)
                if helper.returncode == 0 and helper.stdout.strip() == 'true' and dnat.returncode == 0:
                    break
                time.sleep(1)
            else:
                raise DeployError('wg-easy SSH forward helper or restricted DNAT rule is not ready')
            reachable = run([
                'docker', 'exec', 'wg-easy', 'nc', '-z', '-w', '2', gateway, str(ssh_port),
            ], check=False, capture=True)
            if reachable.returncode != 0:
                raise DeployError(f'Host SSH is not reachable from wg-easy at {gateway}:{ssh_port}')
        state_dir = Path(str(cfg.get('install_dir', '/opt/wg-easy'))) / 'state'
        route_path = state_dir / 'mihomo-route.yaml'
        gateway_path = state_dir / 'mihomo-wg-gateway.yaml'
        if not route_path.is_file() or endpoint not in route_path.read_text():
            raise DeployError('Mihomo forced-proxy route artifact is missing')
        gateway = json.loads(gateway_path.read_text(encoding='utf-8')) if gateway_path.is_file() else {}
        if not gateway or any(row.get('udp') is not True for row in gateway.get('proxies', [])):
            raise DeployError('Strict Mihomo WG gateway profile does not enforce udp:true')
        print(f'[wg-easy] private endpoint {endpoint}:{int(cfg.get("wireguard_port", 51820))}/udp; no public UDP binding')
        if bool(cfg.get('ssh_forward_enabled', False)):
            print(f'[wg-easy] host SSH available only inside WireGuard at {next(ipaddress.ip_network(str(cfg.get("ipv4_cidr", "10.66.66.0/24")), strict=False).hosts())}:{int(cfg.get("ssh_forward_port", 4522))}')
