from __future__ import annotations

import json
import os
import shutil
import urllib.error
import urllib.request
from pathlib import Path

from vpsdeploy.core.runtime import DeployError, DeploymentContext, run, section, write_file
from vpsdeploy.providers.tls.base import TLSMaterial


class CloudflareOriginProvider:
    def validate(self, context: DeploymentContext) -> None:
        cfg = section(context.config, "panel.tls")
        auto = bool(cfg.get("auto_create", False))
        if not auto:
            cert = Path(str(cfg.get("certificate_file", ""))).expanduser()
            key = Path(str(cfg.get("private_key_file", ""))).expanduser()
            if not cert.is_file() or not key.is_file():
                raise DeployError("Origin CA certificate/key files are missing")
        self._hostnames(context)

    def obtain(self, context: DeploymentContext) -> TLSMaterial:
        cfg = section(context.config, "panel.tls")
        target_dir = context.stack_dir / "secrets"
        target_dir.mkdir(parents=True, exist_ok=True)
        cert_target = target_dir / "cloudflare-origin.crt"
        key_target = target_dir / "cloudflare-origin.key"

        if cert_target.is_file() and key_target.is_file() and not bool(cfg.get("force_reissue", False)):
            return TLSMaterial("cloudflare_origin", cert_target, key_target)

        if bool(cfg.get("auto_create", False)):
            self._create(context, cert_target, key_target)
        else:
            shutil.copy2(Path(str(cfg["certificate_file"])).expanduser(), cert_target)
            shutil.copy2(Path(str(cfg["private_key_file"])).expanduser(), key_target)
            cert_target.chmod(0o644)
            key_target.chmod(0o600)
        return TLSMaterial("cloudflare_origin", cert_target, key_target)

    def _hostnames(self, context: DeploymentContext) -> list[str]:
        cfg = section(context.config, 'panel.tls')
        configured = cfg.get('hostnames', [])
        if configured:
            if not isinstance(configured, list):
                raise DeployError('panel.tls.hostnames must be a TOML array')
            values = [str(item).strip().lower() for item in configured]
        else:
            values = [str(section(context.config, 'domains')['panel']).strip().lower()]
            sub2api = context.config.get('sub2api', {})
            if isinstance(sub2api, dict) and bool(sub2api.get('enabled', False)):
                values.append(str(sub2api.get('domain', '')).strip().lower())
        hostnames: list[str] = []
        for hostname in values:
            if not hostname or '.' not in hostname or any(char.isspace() for char in hostname):
                raise DeployError(f'Invalid Origin CA hostname: {hostname!r}')
            if hostname not in hostnames:
                hostnames.append(hostname)
        return hostnames

    def _create(self, context: DeploymentContext, cert: Path, key: Path) -> None:
        cfg = section(context.config, "panel.tls")
        token = os.environ.get("CLOUDFLARE_ORIGIN_CA_TOKEN", "").strip() or str(cfg.get("api_token", "")).strip()
        if not token:
            raise DeployError("Set CLOUDFLARE_ORIGIN_CA_TOKEN for automatic Origin CA creation")

        hostnames = self._hostnames(context)
        validity = int(cfg.get("validity_days", 5475))
        allowed_validities = {7, 30, 90, 365, 730, 1095, 5475}
        if validity not in allowed_validities:
            raise DeployError("panel.tls.validity_days must be one of: " + ", ".join(str(value) for value in sorted(allowed_validities)))

        csr = cert.with_suffix(".csr")
        key.unlink(missing_ok=True)
        csr.unlink(missing_ok=True)
        san = ','.join(f'DNS:{hostname}' for hostname in hostnames)
        run([
            "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(csr), "-subj", f"/CN={hostnames[0]}",
            "-addext", f"subjectAltName={san}",
        ])
        key.chmod(0o600)

        payload = json.dumps({
            "hostnames": hostnames,
            "requested_validity": validity,
            "request_type": "origin-rsa",
            "csr": csr.read_text(encoding="utf-8"),
        }).encode("utf-8")
        request = urllib.request.Request(
            "https://api.cloudflare.com/client/v4/certificates",
            data=payload,
            method="POST",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "init_deploy_outbond/1.0",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                body = json.loads(response.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as exc:
            response_text = exc.read().decode("utf-8", errors="replace")
            try:
                error_body = json.loads(response_text)
                details = error_body.get("errors") or error_body
            except json.JSONDecodeError:
                details = response_text or exc.reason
            key.unlink(missing_ok=True)
            csr.unlink(missing_ok=True)
            raise DeployError(
                f"Cloudflare Origin CA HTTP {exc.code}: {details}. Confirm that every hostname belongs "
                "to a zone in the token's account and that the token has Origin CA certificate edit permission."
            ) from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            key.unlink(missing_ok=True)
            csr.unlink(missing_ok=True)
            raise DeployError(f"Cloudflare Origin CA request failed: {exc}") from exc

        if not body.get("success") or not body.get("result", {}).get("certificate"):
            key.unlink(missing_ok=True)
            csr.unlink(missing_ok=True)
            raise DeployError(f"Cloudflare Origin CA error: {body.get('errors', body)}")
        write_file(cert, body["result"]["certificate"], 0o644)
        key.chmod(0o600)
        csr.unlink(missing_ok=True)
