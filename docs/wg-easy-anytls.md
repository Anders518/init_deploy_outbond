# wg-easy over AnyTLS

This branch adds an optional `wg-easy` task. The default transport is `anytls`: the WireGuard UDP port is kept off the public Internet, and a client-side sing-box relay forwards local WireGuard UDP through the managed S-UI/AnyTLS node to the `wg-easy` container on the private Docker network.

## Topology

```text
WireGuard client
  Endpoint 127.0.0.1:51820/udp
        |
        v
local sing-box direct UDP inbound
        |
        v
managed AnyTLS outbound -> node.example.net:443/tcp
        |
        v
S-UI / sing-box AnyTLS inbound
        |
        v
Docker DNS: wg-easy:51820/udp
        |
        v
wg-easy / WireGuard
```

The generated relay is intended for client platforms where a local sing-box process and WireGuard can run at the same time. Mobile platforms that allow only one system VPN tunnel at a time may not be able to use this topology with two separate VPN applications.

## Configuration

Add the following table to `config.toml`:

```toml
[wg_easy]
enabled = true
install_dir = "/opt/wg-easy"
image = "ghcr.io/wg-easy/wg-easy:15"

# "anytls" keeps 51820/udp private. "direct" publishes it normally.
transport = "anytls"
wireguard_port = 51820

# The Web UI is intentionally bound to localhost. Use an SSH tunnel to reach it.
ui_bind = "127.0.0.1"
ui_port = 51821

# The local UDP endpoint used by WireGuard on a client device.
client_relay_listen = "127.0.0.1"
client_relay_port = 51820

# Docker DNS name reached by the server-side sing-box process.
server_target = "wg-easy"

# Optional first-run unattended initialization. The password is read only from
# the environment and is removed from /opt/wg-easy/.env after container launch.
init_enabled = false
init_username = "admin"
init_password_env = "VPSDEPLOY_WG_EASY_PASSWORD"
init_host = "127.0.0.1"
init_dns = "1.1.1.1,8.8.8.8"
init_ipv4_cidr = "10.8.0.0/24"
init_ipv6_cidr = "fd42:42:42::/64"
```

`transport = "anytls"` requires:

```toml
[panel]
backend = "s-ui"

[node]
enabled = true
```

The managed AnyTLS node must already be configured by `node-config`.

## Deployment

Full deployment:

```bash
sudo uv run --no-dev --frozen python deploy.py deploy
```

Only wg-easy after the proxy stack and AnyTLS node already exist:

```bash
sudo uv run --no-dev --frozen python deploy.py deploy --task wg-easy
```

For unattended first-run setup:

```bash
sudo env VPSDEPLOY_WG_EASY_PASSWORD='use-a-strong-password' \
  uv run --no-dev --frozen python deploy.py deploy --task wg-easy
```

## Generated client relay

In AnyTLS mode the task writes:

```text
/opt/wg-easy/state/anytls-relay.json
/opt/wg-easy/state/README.txt
```

Copy `anytls-relay.json` to the WireGuard client device and run it with a compatible sing-box version. The WireGuard profile must use:

```text
Endpoint = 127.0.0.1:51820
```

The relay uses a sing-box `direct` UDP inbound with destination override and the managed AnyTLS outbound. The remote destination is `wg-easy:51820`, which is resolved inside the server Docker network.

## Web UI

By default the UI listens only on the VPS loopback interface:

```text
127.0.0.1:51821
```

Access it through SSH port forwarding, for example:

```bash
ssh -L 51821:127.0.0.1:51821 -p 4522 deploy@SERVER_IP
```

Then open `http://127.0.0.1:51821` locally.

## Direct mode

Set:

```toml
[wg_easy]
enabled = true
transport = "direct"
```

The task publishes `wireguard_port/udp` on the host. When the project-managed UFW task is enabled, it also allows that UDP port.

## Security and performance notes

- AnyTLS mode does not publish the WireGuard UDP port on the host.
- The wg-easy UI is loopback-only by default.
- WireGuard-over-AnyTLS adds an extra stream transport layer and can suffer additional latency and head-of-line blocking under packet loss compared with native WireGuard UDP.
- The generated AnyTLS relay file contains the managed AnyTLS password and is created with mode `0600`; treat it as a secret.
