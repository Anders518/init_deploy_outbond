from __future__ import annotations

from vpsdeploy.core.runtime import DeploymentContext, section
from vpsdeploy.providers.tls.base import TLSMaterial


def render_compose(context: DeploymentContext, tls: TLSMaterial) -> str:
    ports, docker = section(context.config, 'ports'), section(context.config, 'docker')
    panel = section(context.config, 'panel')
    backend = str(panel.get('backend', '3x-ui')).strip().lower()
    if backend == 's-ui':
        panel_service = '''  s-ui:
    image: ${SUI_IMAGE}
    container_name: s-ui
    restart: unless-stopped
    tty: true
    environment:
      TZ: ${TZ}
    volumes:
      - ./s-ui/db:/app/db
      - ./s-ui/cert:/root/cert
'''
        dependency = 's-ui'
    else:
        panel_service = '''  3x-ui:
    image: ${XUI_IMAGE}
    container_name: 3x-ui
    restart: unless-stopped
    environment:
      TZ: ${TZ}
    volumes:
      - ./3x-ui/db:/etc/x-ui
      - ./3x-ui/cert:/root/cert
'''
        dependency = '3x-ui'
    udp = '      - "${PROXY_PORT}:${PROXY_PORT}/udp"\n' if ports.get('publish_proxy_udp') else ''
    build = '    build:\n      context: ./caddy-build\n' if tls.requires_custom_caddy else ''
    tls_mounts = ''
    if tls.mode == 'cloudflare_origin':
        tls_mounts = ('      - ./secrets/cloudflare-origin.crt:/run/secrets/cloudflare-origin.crt:ro\n'
                      '      - ./secrets/cloudflare-origin.key:/run/secrets/cloudflare-origin.key:ro\n')
    cf_env = '      CLOUDFLARE_API_TOKEN: ${CLOUDFLARE_API_TOKEN}\n' if tls.mode == 'acme_dns' else ''
    ipv6 = ''
    if docker.get('enable_ipv6', True):
        ipv6 = '    enable_ipv6: true\n'
        if docker.get('ipv6_subnet'):
            ipv6 += f'    ipam:\n      config:\n        - subnet: "{docker["ipv6_subnet"]}"\n'
    return f'''services:
{panel_service}    ports:
      - "${{PROXY_PORT}}:${{PROXY_PORT}}/tcp"
{udp}    expose:
      - "{ports['panel_internal']}/tcp"
      - "{ports['subscription_internal']}/tcp"
    networks: [proxy_stack]

  caddy:
{build}    image: ${{CADDY_IMAGE}}
    container_name: caddy-panel
    restart: unless-stopped
    environment:
      TZ: ${{TZ}}
{cf_env}    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - ./caddy/data:/data
      - ./caddy/config:/config
{tls_mounts}    ports:
      - "${{PANEL_PUBLIC_PORT}}:${{PANEL_PUBLIC_PORT}}/tcp"
    networks: [proxy_stack]
    depends_on: [{dependency}]

networks:
  proxy_stack:
    name: {docker.get('network_name', 'proxy_stack')}
{ipv6.rstrip()}
'''


def _tls_block(context: DeploymentContext, tls: TLSMaterial) -> str:
    if tls.mode == 'cloudflare_origin':
        return '    tls /run/secrets/cloudflare-origin.crt /run/secrets/cloudflare-origin.key'
    # Do not add a site-level tls/dns shortcut here. It explicitly provisions
    # only the ACME issuer and disables Caddy's built-in redundant issuer
    # policy. The global acme_dns option below applies DNS-01 to the default
    # issuer chain while retaining automatic fallback.
    return ''


def render_caddy(context: DeploymentContext, tls: TLSMaterial, password_hash: str) -> str:
    domains, ports, panel = section(context.config, 'domains'), section(context.config, 'ports'), section(context.config, 'panel')
    panel_domain = str(domains['panel']).strip().lower()
    subscription_domain = str(domains.get('subscription', panel_domain)).strip().lower() or panel_domain
    panel_path = str(panel.get('path', '/')).rstrip('/') or '/'
    sub_path = str(panel.get('subscription_path', '/sub')).rstrip('/') or '/sub'
    tls_block = _tls_block(context, tls)
    global_block = '' if tls.mode == 'cloudflare_origin' else f'''{{
    email {domains["acme_email"]}
    acme_dns cloudflare {{env.CLOUDFLARE_API_TOKEN}}
}}

'''
    cidrs = ' '.join(map(str, panel.get('allowed_cidrs', [])))
    allow = f'        @denied not remote_ip {cidrs}\n        respond @denied "Not Found" 404\n' if cidrs else ''
    matcher = '' if panel_path == '/' else f'    @panel path {panel_path} {panel_path}/*\n'
    handle = '    handle {' if panel_path == '/' else '    handle @panel {'
    fallback = '' if panel_path == '/' else '    handle { respond "Not Found" 404 }\n'
    panel_service = 's-ui' if str(panel.get('backend', '3x-ui')).strip().lower() == 's-ui' else '3x-ui'

    subscription_on_panel = ''
    if subscription_domain == panel_domain:
        subscription_on_panel = f'''    @subscription path {sub_path} {sub_path}/*
    handle @subscription {{
        reverse_proxy {panel_service}:{ports['subscription_internal']}
    }}

'''

    config = f'''{global_block}{panel_domain}:{ports['panel_public']} {{
    encode zstd gzip
{tls_block}

{subscription_on_panel}{matcher}{handle}
{allow}        basic_auth {{
            {panel['basic_auth_user']} {password_hash}
        }}
        reverse_proxy {panel_service}:{ports['panel_internal']}
    }}
{fallback}}}
'''

    if subscription_domain != panel_domain:
        config += f'''
{subscription_domain}:{ports['panel_public']} {{
    encode zstd gzip
{tls_block}

    @subscription path {sub_path} {sub_path}/*
    handle @subscription {{
        reverse_proxy {panel_service}:{ports['subscription_internal']}
    }}
    handle {{
        respond "Not Found" 404
    }}
}}
'''

    if panel_service == 's-ui':
        node_domain = str(domains['node']).strip().lower()
        config += f'''
{node_domain}:{ports['panel_public']} {{
    encode zstd gzip
{tls_block}
    respond "AnyTLS certificate endpoint" 404
}}
'''

    sub2api = context.config.get('sub2api', {})
    if isinstance(sub2api, dict) and bool(sub2api.get('enabled', False)):
        domain = str(sub2api.get('domain', '')).strip()
        if domain:
            config += f'''
{domain}:{ports['panel_public']} {{
    encode zstd gzip
{tls_block}
    reverse_proxy sub2api:8080 {{
        flush_interval -1
    }}
}}
'''
    return config
