# Sub2API deployment

The `sub2api` task deploys an independent Docker Compose stack under `/opt/sub2api`:

- `sub2api`
- PostgreSQL
- Redis

Only the application joins the existing external `proxy_stack` network. PostgreSQL and Redis remain on an internal bridge network and are not published to the host.

## Configuration

```toml
[sub2api]
enabled = true
domain = "api.example.net"
admin_email = "admin@example.net"
admin_password_mode = "prompt"
postgres_password_mode = "generate"
redis_password_mode = "generate"
jwt_secret_mode = "generate"
totp_key_mode = "generate"

[dns]
enabled = true

[dns.sub2api]
enabled = true
proxied = true
```

For Cloudflare Origin CA, leave `panel.tls.hostnames = []` so the provider derives SANs from the panel and enabled Sub2API domains. If a single-host certificate already exists, set:

```toml
[panel.tls]
force_reissue = true
```

Run a full deployment so DNS, certificate, Caddy and Sub2API are updated in order:

```bash
sudo env \
  CLOUDFLARE_DNS_API_TOKEN="$CLOUDFLARE_DNS_API_TOKEN" \
  CLOUDFLARE_ORIGIN_CA_TOKEN="$CLOUDFLARE_ORIGIN_CA_TOKEN" \
  python3 deploy.py deploy
```

After successful issuance, set `force_reissue = false` again.

## Credentials

Credentials and generated secrets are stored at:

```text
/opt/sub2api/state/credentials.json
```

The file is mode `0600`. Display all managed credentials with:

```bash
sudo python3 deploy.py credentials
```

## Operations

```bash
cd /opt/sub2api
docker compose ps
docker compose logs -f sub2api
docker compose restart sub2api
```

Update both the proxy stack and Sub2API:

```bash
sudo python3 deploy.py update
```

## Backup

Stop the stack before a consistent filesystem-level backup:

```bash
cd /opt/sub2api
docker compose down
sudo tar -C /opt -czf /root/sub2api-backup.tar.gz sub2api
docker compose up -d
```

The deployment defaults to URL allowlist validation, disallows insecure HTTP upstreams, and disallows private upstream hosts. Relax these settings only when required by a trusted integration.
