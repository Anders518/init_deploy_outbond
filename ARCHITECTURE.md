# Architecture

The CLI is intentionally thin. `deploy.py` loads TOML configuration and delegates to `vpsdeploy.application`.

```text
vpsdeploy/
├── application.py          task orchestration and ordering
├── core/
│   └── runtime.py          command execution, context, errors, filesystem helpers
├── tasks/
│   ├── prerequisites.py
│   ├── certificates.py
│   ├── proxy_stack.py
│   ├── ssh_hardening.py
│   ├── fail2ban.py
│   ├── unattended_upgrades.py
│   ├── system_hardening.py
│   └── diagnostics.py
├── providers/tls/
│   ├── base.py
│   ├── cloudflare_origin.py
│   └── acme_dns.py
└── templates/
    └── render.py
```

Tasks implement a common lifecycle: `enabled`, `validate`, `apply`, and `verify`. Providers isolate replaceable implementations such as automatic Cloudflare Origin CA issuance and ACME DNS-01. Templates contain only rendering logic.

## Commands

```bash
python3 deploy.py list-tasks
sudo CLOUDFLARE_ORIGIN_CA_TOKEN='...' python3 deploy.py deploy
sudo python3 deploy.py deploy --task certificate --task proxy-stack
sudo python3 deploy.py --dry-run deploy
sudo python3 deploy.py status
sudo python3 deploy.py update
```

Automatic Origin CA issuance creates the private key locally with OpenSSL and sends only the CSR to Cloudflare. Generated certificate material is stored under `/opt/proxy-stack/secrets` and must not be committed.
