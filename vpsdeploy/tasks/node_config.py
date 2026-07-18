from __future__ import annotations

import hashlib
import http.cookiejar
import ipaddress
import json
import re
import secrets
import shutil
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

from vpsdeploy.core.runtime import DeployError, DeploymentContext, Task, run, section, write_file
from vpsdeploy.providers.dns.cloudflare import CloudflareDNSProvider


_PADDING = [
    'stop=8', '0=30-30', '1=100-400',
    '2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000',
    '3=9-9,500-1000', '4=500-1000', '5=500-1000', '6=500-1000', '7=500-1000',
]


def _backend(context: DeploymentContext) -> str:
    return str(section(context.config, 'panel').get('backend', '3x-ui')).strip().lower()


def _node_config(context: DeploymentContext) -> dict[str, Any]:
    value = context.config.get('node', {})
    if not isinstance(value, dict):
        raise DeployError('node must be a TOML table')
    return value


def _anytls_subscription(context: DeploymentContext, existing: dict[str, Any]) -> tuple[str, str]:
    domains, ports = section(context.config, 'domains'), section(context.config, 'ports')
    sub_path = str(section(context.config, 'panel').get('subscription_path', '/sub')).rstrip('/') or '/sub'
    subscription_id = str(existing.get('subscription_id', '')).strip()
    subscription_id = subscription_id or secrets.token_urlsafe(24).replace('-', '').replace('_', '')
    return subscription_id, f"https://{domains['subscription']}:{ports['panel_public']}{sub_path}/"


def _container_ip(name: str) -> str:
    result = run(
        ['docker', 'inspect', '-f', '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}', name],
        capture=True,
    )
    value = result.stdout.strip()
    if not value:
        raise DeployError(f'Unable to determine {name} container address')
    return value


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _request(opener: Any, url: str, *, form: dict[str, Any] | None = None,
             payload: dict[str, Any] | None = None, csrf: str = '') -> dict[str, Any]:
    headers = {'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest'}
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
    elif payload is not None:
        data = json.dumps(payload).encode()
        headers['Content-Type'] = 'application/json'
    if csrf:
        headers['X-CSRF-Token'] = csrf
    request = urllib.request.Request(url, data=data, headers=headers)
    try:
        with opener.open(request, timeout=20) as response:
            raw = response.read().decode()
    except urllib.error.HTTPError as exc:
        raise DeployError(f'Panel API returned HTTP {exc.code} for {urllib.parse.urlsplit(url).path}') from exc
    try:
        result = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise DeployError(f'Panel API returned invalid JSON for {urllib.parse.urlsplit(url).path}') from exc
    if not isinstance(result, dict):
        raise DeployError('Panel API returned an unexpected response')
    return result


class NodeConfigTask(Task):
    name = 'node-config'

    def enabled(self, context: DeploymentContext) -> bool:
        return bool(_node_config(context).get('enabled', True))

    def validate(self, context: DeploymentContext) -> None:
        backend = _backend(context)
        if backend not in {'3x-ui', 's-ui'}:
            raise DeployError('node-config requires panel.backend to be 3x-ui or s-ui')
        node = _node_config(context)
        if not str(node.get('client_name', 'primary')).strip():
            raise DeployError('node.client_name cannot be empty')

    def apply(self, context: DeploymentContext) -> None:
        if _backend(context) == '3x-ui':
            client = self._configure_reality(context)
        else:
            client = self._configure_anytls(context)
        self._write_client_configs(context, client)
        context.state['node_client'] = client

    def _xui_session(self, context: DeploymentContext) -> tuple[Any, str, str]:
        credentials = _read_json(context.stack_dir / 'state/credentials.json').get('xui', {})
        if not isinstance(credentials, dict) or not credentials.get('password'):
            raise DeployError('3x-ui credentials are unavailable; run the proxy-stack task first')
        base = f"http://{_container_ip('3x-ui')}:{int(section(context.config, 'ports')['panel_internal'])}"
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        token_result = _request(opener, base + '/csrf-token')
        csrf = str(token_result.get('obj', ''))
        if not token_result.get('success') or not csrf:
            raise DeployError('Unable to obtain the 3x-ui CSRF token')
        login = _request(opener, base + '/login', payload={
            'username': credentials.get('username'), 'password': credentials.get('password'),
        }, csrf=csrf)
        if not login.get('success'):
            raise DeployError('3x-ui login failed with the persisted credentials')
        return opener, base, csrf

    def _xui_call(self, session: tuple[Any, str, str], path: str,
                  payload: dict[str, Any] | None = None) -> dict[str, Any]:
        opener, base, csrf = session
        return _request(opener, base + path, payload=payload, csrf=csrf)

    def _x25519(self) -> tuple[str, str]:
        output = run(
            ['docker', 'exec', '3x-ui', '/app/bin/xray-linux-amd64', 'x25519'], capture=True,
        ).stdout
        private = re.search(r'(?im)^(?:PrivateKey|Private key):\s*(\S+)', output)
        public = re.search(r'(?im)^(?:Password(?: \(PublicKey\))?|PublicKey|Public key):\s*(\S+)', output)
        if not private or not public:
            raise DeployError('Unable to parse Xray x25519 output')
        return private.group(1), public.group(1)

    def _configure_reality(self, context: DeploymentContext) -> dict[str, Any]:
        node_cfg = _node_config(context)
        reality = node_cfg.get('reality', {})
        if not isinstance(reality, dict):
            raise DeployError('node.reality must be a TOML table')
        domains, ports = section(context.config, 'domains'), section(context.config, 'ports')
        state_path = context.stack_dir / 'state/node-client.json'
        protocol_path = context.stack_dir / 'state/reality-client.json'
        current_state = _read_json(state_path)
        protocol_state = _read_json(protocol_path)
        existing = current_state if current_state.get('protocol') == 'vless-reality' else protocol_state
        if existing and not existing.get('_private_key'):
            runtime_result = run(
                ['docker', 'exec', '3x-ui', 'cat', '/app/bin/config.json'], capture=True,
            )
            runtime = json.loads(runtime_result.stdout)
            runtime_inbound = next(
                (row for row in runtime.get('inbounds', []) if int(row.get('port', 0)) == int(ports['proxy'])),
                {},
            )
            reality_settings = runtime_inbound.get('streamSettings', {}).get('realitySettings', {})
            existing = {
                **existing,
                'protocol': 'vless-reality',
                '_private_key': str(reality_settings.get('privateKey', '')),
            }
        rotate = bool(node_cfg.get('rotate_client_secret', False))
        if existing.get('protocol') == 'vless-reality' and not rotate:
            private_key = str(existing.get('_private_key', ''))
            public_key = str(existing.get('public_key', ''))
            client_id = str(existing.get('uuid', ''))
            short_id = str(existing.get('short_id', ''))
            subscription_id = str(existing.get('subscription_id', ''))
        else:
            private_key, public_key = self._x25519()
            client_id, short_id = str(uuid.uuid4()), secrets.token_hex(8)
            subscription_id = secrets.token_urlsafe(12).replace('-', '').replace('_', '')[:16]
        if not all((private_key, public_key, client_id, short_id, subscription_id)):
            raise DeployError('Managed Reality state is incomplete; set node.rotate_client_secret=true once')

        target = str(reality.get('target', 'www.cloudflare.com')).strip()
        server_name = str(reality.get('server_name', target)).strip()
        fingerprint = str(reality.get('fingerprint', 'chrome')).strip()
        flow = str(reality.get('flow', 'xtls-rprx-vision')).strip()
        port = int(ports['proxy'])
        tag = f'managed-reality-{port}'
        session = self._xui_session(context)
        requested_version = str(reality.get('xray_version', '')).strip()
        if requested_version:
            version = run(
                ['docker', 'exec', '3x-ui', '/app/bin/xray-linux-amd64', 'version'], capture=True,
            ).stdout.splitlines()[0]
            if requested_version.lstrip('v') not in version:
                installed = self._xui_call(session, f'/panel/api/server/installXray/{requested_version}', {})
                if not installed.get('success'):
                    raise DeployError(f'3x-ui could not install configured Xray version {requested_version}')

        listed = self._xui_call(session, '/panel/api/inbounds/list')
        if not listed.get('success'):
            raise DeployError('Unable to list 3x-ui inbounds')
        rows = listed.get('obj') or []
        current = next((row for row in rows if row.get('remark') == tag), None)
        port_row = next((row for row in rows if int(row.get('port', 0)) == port), None)
        if current is None and port_row and port_row.get('protocol') == 'vless':
            stream = port_row.get('streamSettings') or {}
            if stream.get('security') == 'reality':
                current = port_row
        conflict = port_row if port_row and current is None else None
        if conflict:
            raise DeployError(f'Port {port} is occupied by an unmanaged 3x-ui inbound')
        payload = {
            'id': int(current.get('id', 0)) if current else 0,
            'up': int(current.get('up', 0)) if current else 0,
            'down': int(current.get('down', 0)) if current else 0,
            'total': 0, 'remark': tag, 'enable': True, 'expiryTime': 0,
            'trafficReset': 'never', 'listen': '', 'port': port, 'protocol': 'vless',
            'settings': {'clients': [{
                'id': client_id, 'email': str(node_cfg.get('client_name', 'primary')), 'flow': flow,
                'limitIp': 0, 'totalGB': 0, 'expiryTime': 0, 'enable': True, 'tgId': 0,
                'subId': subscription_id, 'comment': 'Managed deployment client', 'reset': 0,
            }], 'decryption': 'none', 'encryption': 'none'},
            'streamSettings': {
                'network': 'tcp', 'security': 'reality',
                'tcpSettings': {'acceptProxyProtocol': False, 'header': {'type': 'none'}},
                'realitySettings': {
                    'show': False, 'xver': 0, 'target': target + ':443',
                    'serverNames': [server_name], 'privateKey': private_key,
                    'minClientVer': '', 'maxClientVer': '', 'maxTimediff': 0,
                    'shortIds': [short_id], 'settings': {
                        'publicKey': public_key, 'fingerprint': fingerprint,
                        'serverName': '', 'spiderX': '/',
                    },
                },
            },
            'tag': f'inbound-{port}-reality',
            'sniffing': {'enabled': True, 'destOverride': ['http', 'tls', 'quic'],
                         'metadataOnly': False, 'routeOnly': True},
        }
        path = f"/panel/api/inbounds/update/{payload['id']}" if current else '/panel/api/inbounds/add'
        saved = self._xui_call(session, path, payload)
        if not saved.get('success'):
            raise DeployError('3x-ui rejected the managed Reality inbound')
        restarted = self._xui_call(session, '/panel/api/server/restartXrayService', {})
        if not restarted.get('success'):
            raise DeployError('3x-ui failed to restart Xray after saving the inbound')

        client = {
            'protocol': 'vless-reality', 'name': tag, 'address': str(domains['node']), 'port': port,
            'uuid': client_id, 'flow': flow, 'server_name': server_name, 'public_key': public_key,
            'short_id': short_id, 'fingerprint': fingerprint, 'subscription_id': subscription_id,
            'subscription_url': f"https://{domains['subscription']}:{ports['panel_public']}{section(context.config, 'panel').get('subscription_path', '/sub')}/{subscription_id}",
            '_private_key': private_key,
        }
        serialized = json.dumps(client, indent=2, ensure_ascii=False)
        write_file(protocol_path, serialized, 0o600)
        write_file(state_path, serialized, 0o600)
        return client

    def _sui_session(self, context: DeploymentContext) -> tuple[Any, str]:
        credentials = _read_json(context.stack_dir / 'state/credentials.json').get('sui', {})
        if not isinstance(credentials, dict) or not credentials.get('password'):
            raise DeployError('S-UI credentials are unavailable; run the proxy-stack task first')
        panel_path = str(section(context.config, 'panel').get('path', '/')).rstrip('/')
        base = f"http://{_container_ip('s-ui')}:{int(section(context.config, 'ports')['panel_internal'])}{panel_path}"
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        login = _request(opener, base + '/api/login', form={
            'user': credentials.get('username'), 'pass': credentials.get('password'),
        })
        if not login.get('success'):
            raise DeployError('S-UI login failed with the persisted credentials')
        return opener, base

    def _sui_get(self, session: tuple[Any, str], path: str) -> dict[str, Any]:
        return _request(session[0], session[1] + path)

    def _sui_save(self, session: tuple[Any, str], obj: str, action: str,
                  data: Any, init_users: str = '') -> dict[str, Any]:
        result = _request(session[0], session[1] + '/api/save', form={
            'object': obj, 'action': action, 'data': json.dumps(data), 'initUsers': init_users,
        })
        if not result.get('success'):
            raise DeployError(f'S-UI rejected managed {obj} configuration')
        return result

    def _wait_anytls_certificate(self, context: DeploymentContext) -> tuple[Path, Path]:
        node_domain = str(section(context.config, 'domains')['node']).strip().lower()
        root = context.stack_dir / 'caddy/data/caddy/certificates'
        for _ in range(60):
            certs = [path for path in root.rglob(f'{node_domain}.crt') if 'acme-staging' not in str(path)] if root.is_dir() else []
            keys = [path for path in root.rglob(f'{node_domain}.key') if 'acme-staging' not in str(path)] if root.is_dir() else []
            if certs and keys:
                target_cert = context.stack_dir / 's-ui/cert/node.crt'
                target_key = context.stack_dir / 's-ui/cert/node.key'
                shutil.copy2(certs[0], target_cert)
                shutil.copy2(keys[0], target_key)
                target_cert.chmod(0o644)
                target_key.chmod(0o600)
                return target_cert, target_key
            time.sleep(2)
        raise DeployError('Caddy did not obtain the AnyTLS node certificate within 120 seconds')

    def _configure_anytls(self, context: DeploymentContext) -> dict[str, Any]:
        self._wait_anytls_certificate(context)
        node_cfg = _node_config(context)
        anytls = node_cfg.get('anytls', {})
        if not isinstance(anytls, dict):
            raise DeployError('node.anytls must be a TOML table')
        domains, ports = section(context.config, 'domains'), section(context.config, 'ports')
        state_path = context.stack_dir / 'state/node-client.json'
        protocol_path = context.stack_dir / 'state/anytls-client.json'
        current_state = _read_json(state_path)
        protocol_state = _read_json(protocol_path)
        existing = current_state if current_state.get('protocol') == 'anytls' else protocol_state
        rotate = bool(node_cfg.get('rotate_client_secret', False))
        password = str(existing.get('password', '')) if existing.get('protocol') == 'anytls' and not rotate else ''
        password = password or secrets.token_urlsafe(24)
        subscription_id, subscription_base = _anytls_subscription(context, existing)
        tag = f"managed-anytls-{int(ports['proxy'])}"
        display_name = str(node_cfg.get('client_name', 'primary'))
        client_name = subscription_id
        session = self._sui_session(context)
        self._sui_save(session, 'settings', 'edit', {'subURI': subscription_base})
        loaded = self._sui_get(session, '/api/load')
        if not loaded.get('success'):
            raise DeployError('Unable to load S-UI configuration')
        data = loaded.get('obj') or {}

        tls_name = 'managed-anytls-tls'
        tls_rows = data.get('tls') or []
        current_tls = next((row for row in tls_rows if row.get('name') == tls_name), None)
        tls_payload = {
            'id': int(current_tls.get('id', 0)) if current_tls else 0,
            'name': tls_name,
            'server': {'enabled': True, 'server_name': str(domains['node']),
                       'certificate_path': '/root/cert/node.crt', 'key_path': '/root/cert/node.key',
                       'min_version': '1.2', 'max_version': '1.3', 'alpn': ['h2', 'http/1.1']},
            'client': {'server_name': str(domains['node']), 'insecure': False,
                       'alpn': ['h2', 'http/1.1'], 'utls': {'enabled': True, 'fingerprint': 'chrome'}},
        }
        self._sui_save(session, 'tls', 'edit' if current_tls else 'new', tls_payload)
        data = (self._sui_get(session, '/api/load').get('obj') or {})
        tls_row = next((row for row in data.get('tls') or [] if row.get('name') == tls_name), None)
        if not tls_row:
            raise DeployError('S-UI did not persist the managed TLS profile')

        clients = data.get('clients') or []
        current_client = next((row for row in clients if row.get('name') == client_name), None)
        if current_client is None:
            legacy_names = {display_name, str(existing.get('client_name', ''))}
            current_client = next((row for row in clients if row.get('name') in legacy_names), None)
        client_payload = {
            'id': int(current_client.get('id', 0)) if current_client else 0,
            'enable': True, 'name': client_name,
            'config': {'anytls': {'name': client_name, 'password': password}},
            'inbounds': list(current_client.get('inbounds') or []) if current_client else [],
            'links': [], 'volume': 0, 'expiry': 0,
            'up': int(current_client.get('up', 0)) if current_client else 0,
            'down': int(current_client.get('down', 0)) if current_client else 0,
            'desc': 'Managed deployment client', 'group': 'managed', 'remark': '',
            'delayStart': False, 'autoReset': False, 'resetDays': 0, 'nextReset': 0,
        }
        self._sui_save(session, 'clients', 'edit' if current_client else 'new', client_payload)
        data = (self._sui_get(session, '/api/load').get('obj') or {})
        client_row = next((row for row in data.get('clients') or [] if row.get('name') == client_name), None)
        if not client_row:
            raise DeployError('S-UI did not persist the managed client')

        inbounds = data.get('inbounds') or []
        current_inbound = next((row for row in inbounds if row.get('tag') == tag), None)
        conflict = next((row for row in inbounds if int(row.get('listen_port', 0)) == int(ports['proxy']) and row.get('tag') != tag), None)
        if conflict:
            raise DeployError(f"Port {ports['proxy']} is occupied by an unmanaged S-UI inbound")
        inbound_payload = {
            'id': int(current_inbound.get('id', 0)) if current_inbound else 0,
            'type': 'anytls', 'tag': tag, 'listen': '::', 'listen_port': int(ports['proxy']),
            'tls_id': int(tls_row['id']), 'padding_scheme': list(anytls.get('padding_scheme', _PADDING)),
            'addrs': [{'server': str(domains['node']), 'server_port': int(ports['proxy']),
                       'tls': True, 'server_name': str(domains['node'])}], 'out_json': {},
        }
        self._sui_save(session, 'inbounds', 'edit' if current_inbound else 'new', inbound_payload,
                       str(client_row['id']))
        data = (self._sui_get(session, '/api/load').get('obj') or {})
        inbound_row = next((row for row in data.get('inbounds') or [] if row.get('tag') == tag), None)
        if not inbound_row:
            raise DeployError('S-UI did not persist the managed AnyTLS inbound')
        client_payload['id'] = int(client_row['id'])
        client_payload['inbounds'] = [int(inbound_row['id'])]
        self._sui_save(session, 'clients', 'edit', client_payload)

        client = {
            'protocol': 'anytls', 'name': tag, 'client_name': client_name,
            'display_name': display_name, 'subscription_id': subscription_id,
            'subscription_url': subscription_base + subscription_id,
            'address': str(domains['node']), 'port': int(ports['proxy']),
            'password': password, 'server_name': str(domains['node']), 'fingerprint': 'chrome',
        }
        serialized = json.dumps(client, indent=2, ensure_ascii=False)
        write_file(protocol_path, serialized, 0o600)
        write_file(state_path, serialized, 0o600)
        return client

    def _write_client_configs(self, context: DeploymentContext, client: dict[str, Any]) -> None:
        try:
            client_address = ipaddress.ip_address(str(client['address']))
        except ValueError:
            client_address = None
        require_ipv6 = client_address is not None and client_address.version == 6
        if client['protocol'] == 'vless-reality':
            mihomo_proxy = {
                'name': 'managed-node', 'type': 'vless', 'server': client['address'],
                'port': client['port'], 'uuid': client['uuid'], 'network': 'tcp', 'udp': True,
                'tls': True, 'servername': client['server_name'], 'flow': client['flow'],
                'client-fingerprint': client['fingerprint'],
                'reality-opts': {'public-key': client['public_key'], 'short-id': client['short_id']},
            }
            singbox_out = {
                'type': 'vless', 'tag': 'managed-node', 'server': client['address'],
                'server_port': client['port'], 'uuid': client['uuid'], 'flow': client['flow'],
                'tls': {'enabled': True, 'server_name': client['server_name'],
                        'utls': {'enabled': True, 'fingerprint': client['fingerprint']},
                        'reality': {'enabled': True, 'public_key': client['public_key'],
                                    'short_id': client['short_id']}},
            }
        else:
            mihomo_proxy = {
                'name': 'managed-node', 'type': 'anytls', 'server': client['address'],
                'port': client['port'], 'password': client['password'], 'udp': True,
                'client-fingerprint': client['fingerprint'], 'sni': client['server_name'],
                'alpn': ['h2', 'http/1.1'], 'skip-cert-verify': False,
            }
            singbox_out = {
                'type': 'anytls', 'tag': 'managed-node', 'server': client['address'],
                'server_port': client['port'], 'password': client['password'],
                'tls': {'enabled': True, 'server_name': client['server_name'],
                        'utls': {'enabled': True, 'fingerprint': client['fingerprint']}},
            }
        # JSON is valid YAML, avoiding a runtime YAML dependency.
        mihomo = {'mixed-port': 19081, 'allow-lan': False, 'mode': 'global', 'log-level': 'info',
                  'ipv6': require_ipv6, 'proxies': [mihomo_proxy],
                  'proxy-groups': [{'name': 'GLOBAL', 'type': 'select', 'proxies': ['managed-node']}]}
        singbox = {'log': {'level': 'info', 'timestamp': True},
                   'inbounds': [{'type': 'mixed', 'tag': 'mixed-in', 'listen': '127.0.0.1',
                                 'listen_port': 19080}],
                   'outbounds': [singbox_out], 'route': {'final': 'managed-node'}}
        write_file(context.stack_dir / 'state/mihomo-test.yaml', json.dumps(mihomo, indent=2), 0o600)
        write_file(context.stack_dir / 'state/sing-box-test.json', json.dumps(singbox, indent=2), 0o600)

    def verify(self, context: DeploymentContext) -> None:
        client = context.state.get('node_client') or _read_json(context.stack_dir / 'state/node-client.json')
        container = '3x-ui' if _backend(context) == '3x-ui' else 's-ui'
        if client['protocol'] == 'vless-reality':
            runtime_result = run(['docker', 'exec', container, 'cat', '/app/bin/config.json'], capture=True)
            try:
                runtime = json.loads(runtime_result.stdout)
            except json.JSONDecodeError as exc:
                raise DeployError(f'Unable to parse the {container} runtime configuration') from exc
            inbound = next(
                (row for row in runtime.get('inbounds', [])
                 if int(row.get('port', row.get('listen_port', 0))) == int(client['port'])),
                None,
            )
            if not inbound:
                raise DeployError('Managed node port is absent from the runtime configuration')
            stream = inbound.get('streamSettings', {})
            reality = stream.get('realitySettings', {})
            users = inbound.get('settings', {}).get('clients', [])
            private_key = str(reality.get('privateKey', ''))
            derived = run(
                ['docker', 'exec', '3x-ui', '/app/bin/xray-linux-amd64', 'x25519', '-i', private_key],
                capture=True, redact_values={private_key},
            ).stdout
            public = re.search(r'(?im)^(?:Password(?: \(PublicKey\))?|PublicKey|Public key):\s*(\S+)', derived)
            valid = (
                inbound.get('protocol') == 'vless'
                and stream.get('security') == 'reality'
                and stream.get('network') in {'tcp', 'raw'}
                and client['server_name'] in reality.get('serverNames', [])
                and client['short_id'] in reality.get('shortIds', [])
                and bool(re.fullmatch(r'[0-9a-fA-F]{2,16}', client['short_id']))
                and any(row.get('id') == client['uuid'] and row.get('flow') == client['flow'] for row in users)
                and public is not None and public.group(1) == client['public_key']
            )
            if not valid:
                raise DeployError('Xray runtime Reality fields do not match the persisted client configuration')
        else:
            loaded = self._sui_get(self._sui_session(context), '/api/load')
            if not loaded.get('success'):
                raise DeployError('Unable to load S-UI configuration for verification')
            data = loaded.get('obj') or {}
            expected_sub_uri = str(client.get('subscription_url', '')).rsplit('/', 1)[0] + '/'
            inbound = next(
                (row for row in data.get('inbounds') or []
                 if row.get('tag') == client.get('name')
                 and int(row.get('listen_port', 0)) == int(client['port'])),
                None,
            )
            managed_client = next(
                (row for row in data.get('clients') or []
                 if row.get('name') == client.get('client_name')),
                None,
            )
            tls = next(
                (row for row in data.get('tls') or []
                 if inbound and int(row.get('id', 0)) == int(inbound.get('tls_id', 0))),
                None,
            )
            server_tls = (tls or {}).get('server', {})
            valid = (
                inbound is not None
                and inbound.get('type') == 'anytls'
                and managed_client is not None
                and int(inbound.get('id', 0)) in [int(value) for value in managed_client.get('inbounds') or []]
                and bool(server_tls.get('enabled'))
                and server_tls.get('certificate_path') == '/root/cert/node.crt'
                and server_tls.get('key_path') == '/root/cert/node.key'
                and client.get('client_name') in (inbound.get('users') or [])
                and data.get('subURI') == expected_sub_uri
            )
            if not valid:
                raise DeployError('sing-box runtime AnyTLS fields do not match the persisted client configuration')
        listen = run(['ss', '-H', '-ltn', f"sport = :{int(client['port'])}"], capture=True)
        if not listen.stdout.strip():
            raise DeployError('Managed node port is not listening')
        fingerprint = hashlib.sha256(json.dumps(client, sort_keys=True).encode()).hexdigest()[:12]
        print(f"[node] {client['protocol']} configured; client fingerprint={fingerprint}")


class NodeVerifyTask(NodeConfigTask):
    name = 'node-verify'

    def enabled(self, context: DeploymentContext) -> bool:
        node = _node_config(context)
        verify = node.get('verify', {})
        return bool(node.get('enabled', True)) and isinstance(verify, dict) and bool(verify.get('enabled', True))

    def apply(self, context: DeploymentContext) -> None:
        verify = _node_config(context).get('verify', {})
        if not isinstance(verify, dict):
            raise DeployError('node.verify must be a TOML table')
        client = _read_json(context.stack_dir / 'state/node-client.json')
        if not client:
            raise DeployError('Node client state is unavailable; run node-config first')
        before = self._traffic(context, client)
        first = self._run_clients(context, verify)
        after = self._wait_traffic(context, client, before)

        selected = '3x-ui' if _backend(context) == '3x-ui' else 's-ui'
        run(['docker', 'restart', selected])
        self._wait_container(selected, 60)
        time.sleep(3)
        second_before = after
        second = self._run_clients(context, verify)
        second_after = self._wait_traffic(context, client, second_before)
        report = {
            'protocol': client['protocol'], 'clients': first, 'after_restart': second,
            'traffic_before': before, 'traffic_after': after, 'traffic_after_restart': second_after,
            'verified_at': int(time.time()),
        }
        ipv6_state = context.stack_dir / 'state/ipv6.json'
        ipv6 = _read_json(ipv6_state)
        if ipv6.get('ready') and ipv6.get('address'):
            ipv6_client = dict(client)
            ipv6_client['address'] = str(ipv6['address'])
            self._write_client_configs(context, ipv6_client)
            try:
                ipv6_before = second_after
                ipv6_results = self._run_clients(context, verify, required=False)
                if all(row['success'] for row in ipv6_results.values()):
                    ipv6_after = self._wait_traffic(context, client, ipv6_before)
                    report['ipv6_clients'] = ipv6_results
                    report['traffic_after_ipv6'] = ipv6_after
                    print(f"[verify] public IPv6 node path verified: {ipv6['address']}")
                else:
                    self._ipv6_dns_fallback(context, ipv6, 'public_node_client_failed')
                    report['ipv6_fallback'] = True
                    report['ipv6_clients'] = ipv6_results
            finally:
                self._write_client_configs(context, client)
        write_file(context.stack_dir / 'state/node-verification.json', json.dumps(report, indent=2), 0o600)
        context.state['node_verification'] = report

    def _wait_container(self, name: str, timeout: int) -> None:
        for _ in range(timeout):
            result = run(['docker', 'inspect', '-f', '{{.State.Running}}', name], check=False, capture=True)
            if result.returncode == 0 and result.stdout.strip() == 'true':
                return
            time.sleep(1)
        raise DeployError(f'{name} did not recover after restart')

    def _run_clients(self, context: DeploymentContext, verify: dict[str, Any],
                     required: bool = True) -> dict[str, Any]:
        results = {
            'mihomo': self._run_client(
                'vpsdeploy-mihomo-check', str(verify.get('mihomo_image', 'metacubex/mihomo:v1.19.28')), 19081,
                context.stack_dir / 'state/mihomo-test.yaml', '/root/.config/mihomo/config.yaml',
                ['-d', '/root/.config/mihomo'], verify,
            ),
            'sing-box': self._run_client(
                'vpsdeploy-singbox-check', str(verify.get('singbox_image', 'ghcr.io/sagernet/sing-box:v1.13.12')), 19080,
                context.stack_dir / 'state/sing-box-test.json', '/etc/sing-box/config.json',
                ['run', '-c', '/etc/sing-box/config.json'], verify,
            ),
        }
        if required and bool(verify.get('require_all_clients', True)) and not all(row['success'] for row in results.values()):
            failed = ', '.join(name for name, row in results.items() if not row['success'])
            raise DeployError(f'Node verification failed for required client(s): {failed}')
        if required and not any(row['success'] for row in results.values()):
            raise DeployError('Node verification failed for every configured client')
        return results

    def _ipv6_dns_fallback(self, context: DeploymentContext, ipv6: dict[str, Any], reason: str) -> None:
        domains = section(context.config, 'domains')
        names = [str(domains['panel']), str(domains.get('subscription', domains['panel'])), str(domains['node'])]
        sub2api = context.config.get('sub2api', {})
        if isinstance(sub2api, dict) and bool(sub2api.get('enabled', False)):
            names.append(str(sub2api.get('domain', '')))
        CloudflareDNSProvider().delete_managed_records(
            context, list(dict.fromkeys(name for name in names if name and '.' in name)), 'AAAA',
        )
        updated = {**ipv6, 'ready': False, 'rolled_back': True, 'reason': reason,
                   'checked_at': int(time.time())}
        context.state['ipv6_ready'] = False
        write_file(context.stack_dir / 'state/ipv6.json', json.dumps(updated, indent=2), 0o600)
        print('[ipv6] public node validation failed; managed AAAA removed, IPv4-only retained')

    def _run_client(self, name: str, image: str, port: int, source: Path, target: str,
                    command: list[str], verify: dict[str, Any]) -> dict[str, Any]:
        run(['docker', 'rm', '-f', name], check=False, capture=True)
        run(['docker', 'pull', image])
        started = run([
            'docker', 'run', '-d', '--name', name, '--network', 'host',
            '-v', f'{source}:{target}:ro', image, *command,
        ], check=False, capture=True)
        if started.returncode != 0:
            raise DeployError(f'Unable to start {name}')
        timeout = int(verify.get('timeout', 30))
        test_url = str(verify.get('test_url', 'https://api4.ipify.org'))
        try:
            last_error = ''
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                remaining = max(1, int(deadline - time.monotonic()))
                probe = run([
                    'curl', '--silent', '--show-error', '--max-time', str(min(5, remaining)),
                    '--proxy', f'http://127.0.0.1:{port}', test_url,
                ], check=False, capture=True)
                if probe.returncode == 0:
                    value = probe.stdout.strip()
                    try:
                        ipaddress.ip_address(value)
                    except ValueError:
                        last_error = 'test endpoint did not return an IP address'
                    else:
                        print(f'[verify] {name} exit=0 egress={value}')
                        return {'success': True, 'exit_code': 0, 'egress_ip': value}
                else:
                    last_error = (probe.stderr or '').strip()[-300:]
                if time.monotonic() < deadline:
                    time.sleep(min(1, max(0, deadline - time.monotonic())))
            logs = run(['docker', 'logs', '--tail', '40', name], check=False, capture=True)
            detail = '\n'.join(part for part in (logs.stdout, logs.stderr) if part).strip()[-1200:]
            print(f'[verify] {name} failed: {last_error}; logs={detail}')
            return {'success': False, 'exit_code': 1, 'error': last_error}
        finally:
            run(['docker', 'rm', '-f', name], check=False, capture=True)

    def _traffic(self, context: DeploymentContext, client: dict[str, Any]) -> dict[str, int]:
        if _backend(context) == '3x-ui':
            rows = self._xui_call(self._xui_session(context), '/panel/api/inbounds/list').get('obj') or []
            row = next((item for item in rows if item.get('remark') == client.get('name')), {})
        else:
            data = self._sui_get(self._sui_session(context), '/api/load').get('obj') or {}
            row = next((item for item in data.get('clients') or [] if item.get('name') == client.get('client_name')), {})
        return {'up': int(row.get('up', 0)), 'down': int(row.get('down', 0))}

    def _wait_traffic(self, context: DeploymentContext, client: dict[str, Any], before: dict[str, int]) -> dict[str, int]:
        latest = before
        for _ in range(20):
            time.sleep(1)
            latest = self._traffic(context, client)
            if latest['up'] > before['up'] or latest['down'] > before['down']:
                print(f"[verify] service traffic {before} -> {latest}")
                return latest
        raise DeployError(f'Service traffic counters did not increase after client verification: {before} -> {latest}')

    def verify(self, context: DeploymentContext) -> None:
        report = context.state.get('node_verification', {})
        if not report or not (context.stack_dir / 'state/node-verification.json').is_file():
            raise DeployError('Node verification report was not persisted')
        print('[verify] Mihomo and sing-box passed before and after backend restart')
