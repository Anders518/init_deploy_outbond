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
    ssh_forward_service = ''
    if bool(cfg.get('ssh_forward_enabled', False)):
        ssh_forward_service = '''
  wg-ssh-forward:
    image: ${WG_EASY_IMAGE}
    container_name: wg-easy-ssh-forward
    restart: unless-stopped
    network_mode: "service:wg-easy"
    depends_on:
      wg-easy:
        condition: service_started
    cap_add:
      - NET_ADMIN
    entrypoint: ["/bin/sh", "-ec"]
    command:
      - |
        dnat_rule="-i wg0 -s $${WG_IPV4_CIDR} -d $${WG_SSH_VIRTUAL_IP}/32 -p tcp --dport $${WG_SSH_PORT} -j DNAT --to-destination $${WG_HOST_GATEWAY}:$${WG_SSH_PORT}"
        forward_rule="-i wg0 -s $${WG_IPV4_CIDR} -d $${WG_HOST_GATEWAY}/32 -p tcp --dport $${WG_SSH_PORT} -j ACCEPT"
        return_rule="-o wg0 -s $${WG_SSH_VIRTUAL_IP}/32 -d $${WG_IPV4_CIDR} -p tcp --sport $${WG_SSH_PORT} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
        masq_rule="-s $${WG_IPV4_CIDR} -d $${WG_HOST_GATEWAY}/32 -o eth0 -p tcp --dport $${WG_SSH_PORT} -j MASQUERADE"
        cleanup() {
          while iptables -t nat -C PREROUTING $${dnat_rule} 2>/dev/null; do iptables -t nat -D PREROUTING $${dnat_rule}; done
          while iptables -C FORWARD $${forward_rule} 2>/dev/null; do iptables -D FORWARD $${forward_rule}; done
          while iptables -C FORWARD $${return_rule} 2>/dev/null; do iptables -D FORWARD $${return_rule}; done
          while iptables -t nat -C POSTROUTING $${masq_rule} 2>/dev/null; do iptables -t nat -D POSTROUTING $${masq_rule}; done
        }
        trap cleanup EXIT INT TERM
        until ip link show wg0 >/dev/null 2>&1; do sleep 1; done
        while true; do
          iptables -t nat -C PREROUTING $${dnat_rule} 2>/dev/null || iptables -t nat -I PREROUTING 1 $${dnat_rule}
          iptables -C FORWARD $${forward_rule} 2>/dev/null || iptables -I FORWARD 1 $${forward_rule}
          iptables -C FORWARD $${return_rule} 2>/dev/null || iptables -I FORWARD 1 $${return_rule}
          iptables -t nat -C POSTROUTING $${masq_rule} 2>/dev/null || iptables -t nat -I POSTROUTING 1 $${masq_rule}
          sleep 5 & wait $$!
        done
    environment:
      WG_IPV4_CIDR: ${WG_IPV4_CIDR}
      WG_SSH_VIRTUAL_IP: ${WG_SSH_VIRTUAL_IP}
      WG_HOST_GATEWAY: ${WG_HOST_GATEWAY}
      WG_SSH_PORT: ${WG_SSH_PORT}
    logging:
      driver: json-file
      options:
        max-size: "${LOG_MAX_SIZE}"
        max-file: "${LOG_MAX_FILE}"
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
{ssh_forward_service}

networks:
  proxy:
    external: true
    name: ${{PROXY_NETWORK}}
'''
