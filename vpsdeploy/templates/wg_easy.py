from __future__ import annotations

from typing import Any


def render_wg_easy_compose(cfg: dict[str, Any], *, initialize: bool) -> str:
    init_environment = ''
    if initialize:
        init_environment = '''      INIT_ENABLED: "true"
      INIT_USERNAME: ${WG_ADMIN_USERNAME}
      INIT_PASSWORD: ${WG_ADMIN_PASSWORD}
      INIT_HOST: ${WG_PROXY_ENDPOINT}
      INIT_PORT: ${WG_PORT}
      INIT_DNS: ${WG_DNS}
      INIT_IPV4_CIDR: ${WG_IPV4_CIDR}
      INIT_IPV6_CIDR: ${WG_IPV6_CIDR}
'''
    return f'''services:
  wg-easy:
    image: ${{WG_EASY_IMAGE}}
    container_name: wg-easy
    restart: unless-stopped
    environment:
      PORT: "51821"
      HOST: 0.0.0.0
      INSECURE: "true"
{init_environment}    volumes:
      - ./data:/etc/wireguard
      - /lib/modules:/lib/modules:ro
    ports:
      - "127.0.0.1:${{WG_WEB_PORT}}:51821/tcp"
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    sysctls:
      - net.ipv4.ip_forward=1
      - net.ipv4.conf.all.src_valid_mark=1
      - net.ipv6.conf.all.disable_ipv6=0
      - net.ipv6.conf.all.forwarding=1
      - net.ipv6.conf.default.forwarding=1
    logging:
      driver: json-file
      options:
        max-size: "${{LOG_MAX_SIZE}}"
        max-file: "${{LOG_MAX_FILE}}"
    networks:
      proxy:
        ipv4_address: ${{WG_PROXY_ENDPOINT}}

networks:
  proxy:
    external: true
    name: ${{PROXY_NETWORK}}
'''
