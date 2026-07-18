from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any

from .common import warn
from .core.runtime import DeployError

try:
    import tomllib
except ModuleNotFoundError as exc:  # pragma: no cover
    raise SystemExit("Python 3.11 or newer is required") from exc


def load_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise DeployError(f"Configuration file not found: {path}")
    with path.open("rb") as handle:
        return tomllib.load(handle)


def section(config: dict[str, Any], dotted: str) -> dict[str, Any]:
    value: Any = config
    for key in dotted.split("."):
        if not isinstance(value, dict) or key not in value:
            raise DeployError(f"Missing configuration section: {dotted}")
        value = value[key]
    if not isinstance(value, dict):
        raise DeployError(f"Configuration section is not a table: {dotted}")
    return value


def normalize_path(value: str, name: str) -> str:
    if not value.startswith("/"):
        raise DeployError(f"{name} must start with /")
    return "/" if value == "/" else value.rstrip("/")


def validate_port(value: Any, name: str) -> int:
    if not isinstance(value, int) or not 1 <= value <= 65535:
        raise DeployError(f"{name} must be an integer between 1 and 65535")
    return value


def tls_mode(config: dict[str, Any]) -> str:
    mode = str(section(config, "panel.tls").get("mode", "cloudflare_origin")).strip()
    if mode not in {"cloudflare_origin", "acme_dns"}:
        raise DeployError("panel.tls.mode must be cloudflare_origin or acme_dns")
    return mode


def validate_config(config: dict[str, Any]) -> None:
    domains = section(config, "domains")
    ports = section(config, "ports")
    panel = section(config, "panel")
    docker = section(config, "docker")
    tls = section(config, "panel.tls")
    node = config.get("node", {})
    if not isinstance(node, dict):
        raise DeployError("node must be a TOML table")

    backend = str(panel.get("backend", "3x-ui")).strip().lower()
    if backend not in {"3x-ui", "s-ui"}:
        raise DeployError('panel.backend must be "3x-ui" or "s-ui"')
    backend_section = "xui" if backend == "3x-ui" else "sui"
    if not isinstance(panel.get(backend_section, {}), dict):
        raise DeployError(f"panel.{backend_section} must be a TOML table")
    image_key = "xui_image" if backend == "3x-ui" else "sui_image"
    if not str(docker.get(image_key, "")).strip():
        raise DeployError(f"docker.{image_key} cannot be empty when panel.backend={backend!r}")
    verify = node.get("verify", {})
    if not isinstance(verify, dict):
        raise DeployError("node.verify must be a TOML table")
    if bool(verify.get("enabled", True)):
        if not str(verify.get("mihomo_image", "metacubex/mihomo:v1.19.28")).strip():
            raise DeployError("node.verify.mihomo_image cannot be empty")
        if not str(verify.get("singbox_image", "ghcr.io/sagernet/sing-box:v1.13.12")).strip():
            raise DeployError("node.verify.singbox_image cannot be empty")
    if backend == "s-ui" and tls_mode(config) != "acme_dns":
        raise DeployError('panel.backend="s-ui" requires panel.tls.mode="acme_dns" for a publicly trusted AnyTLS certificate')

    for name in ("panel", "node"):
        if not str(domains.get(name, "")).strip():
            raise DeployError(f"domains.{name} cannot be empty")

    values = {
        "proxy": validate_port(ports.get("proxy"), "ports.proxy"),
        "panel_public": validate_port(ports.get("panel_public"), "ports.panel_public"),
        "panel_internal": validate_port(ports.get("panel_internal"), "ports.panel_internal"),
        "subscription_internal": validate_port(
            ports.get("subscription_internal"), "ports.subscription_internal"
        ),
    }
    if len(set(values.values())) != len(values):
        raise DeployError(f"Port conflict detected: {values}")

    normalize_path(str(panel.get("path", "/")), "panel.path")
    normalize_path(str(panel.get("subscription_path", "/sub")), "panel.subscription_path")

    for cidr in panel.get("allowed_cidrs", []):
        try:
            ipaddress.ip_network(str(cidr), strict=False)
        except ValueError as exc:
            raise DeployError(f"Invalid panel.allowed_cidrs entry: {cidr}") from exc

    subnet = str(docker.get("ipv6_subnet", "")).strip()
    if subnet:
        network = ipaddress.ip_network(subnet, strict=False)
        if network.version != 6:
            raise DeployError("docker.ipv6_subnet must be IPv6")

    if tls_mode(config) == "cloudflare_origin":
        auto_create = bool(tls.get("auto_create", True))
        if not auto_create:
            cert = Path(str(tls.get("certificate_file", ""))).expanduser()
            key = Path(str(tls.get("private_key_file", ""))).expanduser()
            if not cert.is_file() or not key.is_file():
                raise DeployError("Manual Origin CA certificate/key files are missing")
            if key.stat().st_mode & 0o077:
                warn(f"Private key permissions are broader than recommended: {key}")
        validity = int(tls.get("validity_days", 5475))
        if validity not in {7, 30, 90, 365, 730, 1095, 5475}:
            raise DeployError("panel.tls.validity_days is not supported by Origin CA")
    elif not str(domains.get("acme_email", "")).strip():
        raise DeployError("domains.acme_email is required for acme_dns mode")

    ssh_cfg = section(config, "hardening.ssh")
    new_ssh_port = validate_port(ssh_cfg.get("new_port"), "hardening.ssh.new_port")
    if new_ssh_port in values.values():
        raise DeployError("The new SSH port conflicts with a proxy-stack port")
