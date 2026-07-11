from __future__ import annotations

from vpsdeploy.core.runtime import DeploymentContext, section
from vpsdeploy.providers.tls.base import TLSMaterial


def render_compose(context: DeploymentContext, tls: TLSMaterial) -> str:
    cfg, ports, docker = context.config, section(context.config, 'ports'), section(context.config, 'docker')
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
  3x-ui:
    image: ${{XUI_IMAGE}}
    container_name: 3x-ui
    restart: unless-stopped
    environment:
      TZ: ${{TZ}}
    volumes:
      - ./3x-ui/db:/etc/x-ui
      - ./3x-ui/cert:/root/cert
    ports:
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
    depends_on: [3x-ui]

networks:
  proxy_stack:
    name: {docker.get('network_name', 'proxy_stack')}
{ipv6.rstrip()}
'''


def render_caddy(context: DeploymentContext, tls: TLSMaterial, password_hash: str) -> str:
    domains, ports, panel = section(context.config, 'domains'), section(context.config, 'ports'), section(context.config, 'panel')
    panel_path = str(panel.get('path', '/')).rstrip('/') or '/'
    sub_path = str(panel.get('subscription_path', '/sub')).rstrip('/')
    tls_block = ('    tls /run/secrets/cloudflare-origin.crt /run/secrets/cloudflare-origin.key'
                 if tls.mode == 'cloudflare_origin' else
                 '    tls {\n        dns cloudflare {env.CLOUDFLARE_API_TOKEN}\n    }')
    global_block = '' if tls.mode == 'cloudflare_origin' else f'{{\n    email {domains["acme_email"]}\n}}\n\n'
    cidrs = ' '.join(map(str, panel.get('allowed_cidrs', [])))
    allow = f'        @denied not remote_ip {cidrs}\n        respond @denied "Not Found" 404\n' if cidrs else ''
    matcher = '' if panel_path == '/' else f'    @panel path {panel_path} {panel_path}/*\n'
    handle = '    handle {' if panel_path == '/' else '    handle @panel {'
    fallback = '' if panel_path == '/' else '    handle { respond "Not Found" 404 }\n'
    return f'''{global_block}{domains['panel']}:{ports['panel_public']} {{
    encode zstd gzip
{tls_block}

    @subscription path {sub_path} {sub_path}/*
    handle @subscription {{
        reverse_proxy 3x-ui:{ports['subscription_internal']}
    }}

{matcher}{handle}
{allow}        basic_auth {{
            {panel['basic_auth_user']} {password_hash}
        }}
        reverse_proxy 3x-ui:{ports['panel_internal']}
    }}
{fallback}}}
'''
