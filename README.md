# init_deploy_outbond

A standard-library-only Python deployment tool for a small VPS proxy stack:

- 3x-ui / Xray in Docker bridge mode
- VLESS Reality entry point reserved on TCP 443 by default
- Caddy panel reverse proxy on TCP 8443
- Cloudflare DNS-01 certificates; no HTTP-01 port required
- Separate internal 3x-ui panel and subscription services
- Optional Docker IPv6 networking
- Optional SSH, Fail2Ban, unattended-upgrades and sysctl hardening
- Configuration backups and idempotent Caddy image builds

## Important security notes

Do not commit `config.toml`, `.env`, `secrets.txt`, Cloudflare tokens, UUIDs, Reality private keys or Short IDs.

The generated runtime state is stored under `/opt/proxy-stack` by default. The Cloudflare token is written to `/opt/proxy-stack/.env` with mode `0600` because Caddy needs it at runtime.

SSH hardening is disabled by default. Keep the current SSH session open and test a second session before disabling root login or removing the old firewall rule.

## Requirements

- Debian or Ubuntu
- Python 3.11+
- Root privileges
- A Cloudflare-managed DNS zone
- A Cloudflare API token restricted to the required zone with:
  - Zone / Zone / Read
  - Zone / DNS / Edit

## Quick start

```bash
git clone https://github.com/Anders518/init_deploy_outbond.git
cd init_deploy_outbond
cp config.example.toml config.toml
nano config.toml
sudo CLOUDFLARE_API_TOKEN='your-token' python3 deploy.py deploy
```

Using an environment variable is preferable to storing the token in `config.toml`.

## Recommended DNS records

Use separate hostnames:

```text
panel.example.net  A/AAAA  VPS address
node.example.net   A/AAAA  VPS address, DNS only
```

The Reality node hostname must not be proxied through Cloudflare. Only create an AAAA record when the VPS IPv6 route and inbound firewall are working.

## Port model

Default configuration:

```text
443/tcp   Public VLESS Reality entry point
8443/tcp  Public Caddy HTTPS panel and subscription entry point
2053/tcp  Internal 3x-ui panel; never publish to the host
2096/tcp  Internal subscription service; never publish to the host
80/tcp    Not required because certificates use DNS-01
```

The VPS provider firewall should allow only the configured SSH port, proxy port and panel public port. Apply equivalent IPv4 and IPv6 rules where required.

## Commands

Deploy or reconcile generated configuration:

```bash
sudo CLOUDFLARE_API_TOKEN='your-token' python3 deploy.py deploy
```

Show stack, listening-port and Docker network state:

```bash
sudo python3 deploy.py status
```

Update 3x-ui and reconcile containers:

```bash
sudo python3 deploy.py update
```

To rebuild Caddy with the latest Cloudflare module, set:

```toml
[docker]
force_rebuild_caddy = true
```

Then run `deploy` or `update`. Normal runs reuse the existing custom Caddy image.

## First 3x-ui configuration

Configure the panel:

```text
Listen IP: blank or 0.0.0.0
Listen port: 2053
URI path: must equal panel.path
Trusted proxies: include the Docker bridge ranges used by your host
```

Configure subscriptions:

```text
Listen IP: blank or 0.0.0.0
Internal port: 2096
URI path: must equal panel.subscription_path
External scheme: https
External domain: the panel hostname
External port: 8443
```

Configure the initial Reality inbound:

```text
Protocol: VLESS
Port: 443
Network: TCP
Security: Reality
Flow: xtls-rprx-vision
Encryption/decryption: none
```

The subscription route is intentionally not protected by Caddy BasicAuth because most clients cannot supply interactive BasicAuth credentials when refreshing subscriptions. The panel route remains protected by BasicAuth and 3x-ui's own login.

## Optional hardening

Enable features selectively in `config.toml`:

```toml
[hardening]
enabled = true

[hardening.ssh]
enabled = true
current_port = 22
new_port = 4522
create_admin_user = true
admin_user = "deploy"
disable_root_login = false
allow_users = ["root", "deploy"]
```

Recommended two-stage SSH migration:

1. Allow the new SSH port in the VPS provider firewall.
2. Keep the existing SSH session open.
3. First deploy with `disable_root_login = false` and both users in `allow_users`.
4. Test a new session:

   ```bash
   ssh -p 4522 deploy@SERVER
   sudo whoami
   ```

5. After successful verification, set:

   ```toml
   disable_root_login = true
   allow_users = ["deploy"]
   ```

6. Run deploy again, test a new session, then remove the old SSH port from the provider firewall.

The script supports Ubuntu `ssh.socket` activation and validates SSH configuration with `sshd -t` before reloading it.

### Fail2Ban

Fail2Ban can protect the configured SSH port. It uses the system firewall locally and can coexist with a provider-level firewall.

### Automatic updates

Unattended security updates are optional. Automatic reboot is disabled by default to avoid unplanned proxy downtime.

### sysctl

The optional sysctl profile disables source routing and redirects and enables conservative kernel protections. It does not disable IPv6 forwarding, which may be needed for Docker IPv6 egress.

## Docker IPv6

`docker.enable_ipv6 = true` enables IPv6 on the Compose network. Docker Engine and the host must also have suitable IPv6 forwarding/routing configuration.

Leaving `docker.ipv6_subnet` empty avoids hard-coded subnet collisions on newer Docker versions. If your Docker version requires an explicit subnet, choose an unused ULA `/64`, for example:

```toml
ipv6_subnet = "fd42:7c31:9a80:100::/64"
```

Inspect existing Docker subnets before selecting one:

```bash
docker network inspect $(docker network ls -q) | grep -E '"Name"|"Subnet"|"EnableIPv6"'
```

## Generated files

By default, deployment generates:

```text
/opt/proxy-stack/
├── .env
├── Caddyfile
├── docker-compose.yml
├── secrets.txt
├── backups/
├── caddy-build/
├── caddy/
└── 3x-ui/
```

Existing generated configuration is archived before replacement. Persistent 3x-ui and Caddy data are not deleted during normal deployment or update operations.

## Backup scope

Back up at least:

```text
/opt/proxy-stack/3x-ui/db
/opt/proxy-stack/caddy/data
/opt/proxy-stack/Caddyfile
/opt/proxy-stack/docker-compose.yml
/opt/proxy-stack/.env
/etc/docker/daemon.json
/etc/ssh
```

Encrypt backups because `.env`, Caddy ACME state and 3x-ui databases contain sensitive material.
