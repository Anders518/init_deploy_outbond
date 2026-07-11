from __future__ import annotations

import datetime as dt
import getpass
import json
import os
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .common import DeployError, log, run, write_file
from .config import section

API_URL = "https://api.cloudflare.com/client/v4/certificates"


def certificate_is_usable(cert_file: Path, renew_before_days: int) -> bool:
    if not cert_file.is_file() or cert_file.stat().st_size == 0:
        return False
    result = subprocess.run(
        [
            "openssl", "x509", "-in", str(cert_file), "-noout", "-checkend",
            str(max(0, renew_before_days) * 86400),
        ],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def get_origin_ca_key(tls_config: dict[str, Any]) -> str:
    key = os.environ.get("CLOUDFLARE_ORIGIN_CA_KEY", "").strip()
    if not key:
        key = str(tls_config.get("origin_ca_key", "")).strip()
    if not key and os.isatty(0):
        key = getpass.getpass("Cloudflare Origin CA Key: ").strip()
    if not key:
        raise DeployError(
            "CLOUDFLARE_ORIGIN_CA_KEY is required to create an Origin CA certificate"
        )
    return key


def generate_key_and_csr(hostnames: list[str], request_type: str) -> tuple[str, str]:
    if not hostnames:
        raise DeployError("At least one Origin CA hostname is required")
    with tempfile.TemporaryDirectory(prefix="origin-ca-") as temporary_dir:
        root = Path(temporary_dir)
        key_file = root / "origin.key"
        csr_file = root / "origin.csr"
        config_file = root / "openssl.cnf"
        san = ",".join(f"DNS:{hostname}" for hostname in hostnames)
        config_file.write_text(
            "[req]\n"
            "prompt = no\n"
            "distinguished_name = dn\n"
            "req_extensions = req_ext\n"
            "[dn]\n"
            f"CN = {hostnames[0]}\n"
            "[req_ext]\n"
            f"subjectAltName = {san}\n",
            encoding="utf-8",
        )
        if request_type == "origin-ecc":
            run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key_file)])
        else:
            run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(key_file)])
        run([
            "openssl", "req", "-new", "-key", str(key_file), "-out", str(csr_file),
            "-config", str(config_file),
        ])
        return key_file.read_text(encoding="utf-8"), csr_file.read_text(encoding="utf-8")


def request_certificate(
    origin_ca_key: str,
    csr: str,
    hostnames: list[str],
    validity_days: int,
    request_type: str,
) -> str:
    payload = json.dumps({
        "csr": csr,
        "hostnames": hostnames,
        "request_type": request_type,
        "requested_validity": validity_days,
    }).encode("utf-8")
    request = urllib.request.Request(
        API_URL,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Auth-User-Service-Key": origin_ca_key,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise DeployError(f"Cloudflare Origin CA API failed: HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise DeployError(f"Cloudflare Origin CA API connection failed: {exc}") from exc
    if not body.get("success"):
        raise DeployError(f"Cloudflare Origin CA API error: {body.get('errors', body)}")
    certificate = str(body.get("result", {}).get("certificate", "")).strip()
    if not certificate:
        raise DeployError("Cloudflare Origin CA API returned no certificate")
    return certificate


def validate_pair(cert_file: Path, key_file: Path) -> None:
    cert_pub = run(["openssl", "x509", "-in", str(cert_file), "-pubkey", "-noout"], capture=True).stdout
    key_pub = run(["openssl", "pkey", "-in", str(key_file), "-pubout"], capture=True).stdout
    if cert_pub.strip() != key_pub.strip():
        raise DeployError("Origin certificate does not match the private key")


def backup(path: Path) -> None:
    if path.exists():
        stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
        shutil.copy2(path, path.with_name(f"{path.name}.backup-{stamp}"))


def ensure_origin_certificate(config: dict[str, Any], stack_dir: Path) -> tuple[Path, Path]:
    tls = section(config, "panel.tls")
    target_cert = stack_dir / "secrets" / "cloudflare-origin.crt"
    target_key = stack_dir / "secrets" / "cloudflare-origin.key"
    renew_before_days = int(tls.get("renew_before_days", 30))

    if target_key.is_file() and certificate_is_usable(target_cert, renew_before_days):
        validate_pair(target_cert, target_key)
        log("Existing Cloudflare Origin CA certificate is still usable")
        return target_cert, target_key

    if not bool(tls.get("auto_create", True)):
        source_cert = Path(str(tls.get("certificate_file", ""))).expanduser().resolve()
        source_key = Path(str(tls.get("private_key_file", ""))).expanduser().resolve()
        shutil.copy2(source_cert, target_cert)
        shutil.copy2(source_key, target_key)
        target_cert.chmod(0o644)
        target_key.chmod(0o600)
        validate_pair(target_cert, target_key)
        return target_cert, target_key

    domains = section(config, "domains")
    hostnames = [str(item) for item in tls.get("hostnames", []) if str(item).strip()]
    if not hostnames:
        hostnames = [str(domains["panel"])]
    request_type = str(tls.get("request_type", "origin-rsa"))
    if request_type not in {"origin-rsa", "origin-ecc"}:
        raise DeployError("panel.tls.request_type must be origin-rsa or origin-ecc")

    log("Creating Cloudflare Origin CA certificate with a locally generated private key")
    private_key, csr = generate_key_and_csr(hostnames, request_type)
    certificate = request_certificate(
        get_origin_ca_key(tls),
        csr,
        hostnames,
        int(tls.get("validity_days", 5475)),
        request_type,
    )
    backup(target_cert)
    backup(target_key)
    write_file(target_cert, certificate, 0o644)
    write_file(target_key, private_key, 0o600)
    validate_pair(target_cert, target_key)
    return target_cert, target_key
