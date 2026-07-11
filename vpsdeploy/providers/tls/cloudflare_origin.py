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

    def obtain(self, context: DeploymentContext) -> TLSMaterial:
        cfg = section(context.config, "panel.tls")
        target_dir = context.stack_dir / "secrets"
        target_dir.mkdir(parents=True, exist_ok=True)
        cert_target = target_dir / "cloudflare-origin.crt"
        key_target = target_dir / "cloudflare-origin.key"

        if (
            cert_target.is_file()
            and key_target.is_file()
            and not bool(cfg.get("force_reissue", False))
        ):
            return TLSMaterial("cloudflare_origin", cert_target, key_target)

        if bool(cfg.get("auto_create", False)):
            self._create(context, cert_target, key_target)
        else:
            shutil.copy2(Path(str(cfg["certificate_file"])).expanduser(), cert_target)
            shutil.copy2(Path(str(cfg["private_key_file"])).expanduser(), key_target)
            cert_target.chmod(0o644)
            key_target.chmod(0o600)
        return TLSMaterial("cloudflare_origin", cert_target, key_target)

    def _create(self, context: DeploymentContext, cert: Path, key: Path) -> None:
        cfg = section(context.config, "panel.tls")
        token = (
            os.environ.get("CLOUDFLARE_ORIGIN_CA_TOKEN", "").strip()
            or str(cfg.get("api_token", "")).strip()
        )
        if not token:
            raise DeployError(
                "Set CLOUDFLARE_ORIGIN_CA_TOKEN for automatic Origin CA creation"
            )

        hostname = str(section(context.config, "domains")["panel"]).strip().lower()
        if not hostname or "." not in hostname:
            raise DeployError("domains.panel must be a fully qualified domain name")

        validity = int(cfg.get("validity_days", 5475))
        allowed_validities = {7, 30, 90, 365, 730, 1095, 5475}
        if validity not in allowed_validities:
            raise DeployError(
                "panel.tls.validity_days must be one of: "
                + ", ".join(str(value) for value in sorted(allowed_validities))
            )

        csr = cert.with_suffix(".csr")
        key.unlink(missing_ok=True)
        csr.unlink(missing_ok=True)

        run(
            [
                "openssl",
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(key),
                "-out",
                str(csr),
                "-subj",
                f"/CN={hostname}",
                "-addext",
                f"subjectAltName=DNS:{hostname}",
            ]
        )
        key.chmod(0o600)

        payload = json.dumps(
            {
                "hostnames": [hostname],
                "requested_validity": validity,
                "request_type": "origin-rsa",
                "csr": csr.read_text(encoding="utf-8"),
            }
        ).encode("utf-8")

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
                response_text = response.read().decode("utf-8", errors="replace")
                body = json.loads(response_text)
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
                f"Cloudflare Origin CA HTTP {exc.code}: {details}. "
                "Confirm that the hostname belongs to a zone in the token's account "
                "and that the token has Origin CA certificate edit permission."
            ) from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            key.unlink(missing_ok=True)
            csr.unlink(missing_ok=True)
            raise DeployError(f"Cloudflare Origin CA request failed: {exc}") from exc

        if not body.get("success") or not body.get("result", {}).get("certificate"):
            key.unlink(missing_ok=True)
            csr.unlink(missing_ok=True)
            raise DeployError(
                f"Cloudflare Origin CA error: {body.get('errors', body)}"
            )

        write_file(cert, body["result"]["certificate"], 0o644)
        key.chmod(0o600)
        csr.unlink(missing_ok=True)
