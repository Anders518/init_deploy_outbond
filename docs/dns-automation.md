# Cloudflare DNS automation

Enable the task in `config.toml`:

```toml
[dns]
enabled = true
provider = "cloudflare"
auto_detect_addresses = true
create_ipv4 = true
create_ipv6 = true
ttl = 1
ipv4_address = ""
ipv6_address = ""

[dns.panel]
enabled = true
proxied = true

[dns.node]
enabled = true
proxied = false
```

Use a dedicated Cloudflare API token with `Zone / Zone / Read` and `Zone / DNS / Edit`, restricted to the required zone. Pass it without storing it in Git:

```bash
read -rsp "Cloudflare DNS token: " CF_DNS_TOKEN
echo
sudo env CLOUDFLARE_DNS_API_TOKEN="$CF_DNS_TOKEN" \
  python3 deploy.py deploy --task dns-records
unset CF_DNS_TOKEN
```

The task is idempotent:

- missing A/AAAA records are created;
- changed addresses or proxy settings are updated;
- matching records are left unchanged;
- duplicate records of the same name and type cause a safe failure;
- unrelated records are never deleted.

The panel record defaults to Cloudflare Proxy. The Reality node record is required to remain DNS only. IPv6 records are skipped when automatic IPv6 address detection fails. To avoid relying on external address detection services, set `ipv4_address` and `ipv6_address` explicitly.
