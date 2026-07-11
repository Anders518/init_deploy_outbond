#!/usr/bin/env python3
"""Deploy a hardened 3x-ui + Caddy stack on Debian/Ubuntu.

TLS modes:
- cloudflare_origin: standard Caddy image + Cloudflare Origin CA certificate
- acme_dns: custom Caddy image with Cloudflare DNS provider
"""

from __future__ import annotations

import argparse
import datetime as dt
import getpass
import ipaddress
import os
import pwd
import re
import secrets
import shlex
import shutil
import string
import subprocess
import sys
import tarfile
import textwrap
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError as exc:
    raise SystemExit("Python 3.11 or newer is required") from exc


class DeployError(RuntimeError):
    pass


def log(message: str) -> None:
    print(f"\033[1;32m[+] {message}\033[0m")


def warn(message: str) -> None:
    print(f"\033[1;33m[!] {message}\033[0m", file=sys.stderr)


def run(command: list[str], *, check: bool = True, capture: bool = False,
        cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    print("$", shlex.join(command))
    return subprocess.run(command, check=check, text=True, capture_output=capture, cwd=cwd)


def require_root() -> None:
    if os.geteuid() != 0:
        raise DeployError("Run as root, for example: sudo python3 deploy.py deploy")


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

    mode = tls_mode(config)
    if mode == "cloudflare_origin":
        cert = Path(str(tls.get("certificate_file", ""))).expanduser()
        key = Path(str(tls.get("private_key_file", ""))).expanduser()
        if not cert.is_file() or not key.is_file():
            raise DeployError(
                "Cloudflare Origin CA certificate/key files are missing. "
                "Set panel.tls.certificate_file and private_key_file."
            )
        if key.stat().st_mode & 0o077:
            warn(f"Private key permissions are broader than recommended: {key}")
    else:
        if not str(domains.get("acme_email", "")).strip():
            raise DeployError("domains.acme_email is required for acme_dns mode")

    ssh_cfg = section(config, "hardening.ssh")
    new_ssh_port = validate_port(ssh_cfg.get("new_port"), "hardening.ssh.new_port")
    if new_ssh_port in values.values():
        raise DeployError("The new SSH port conflicts with a proxy-stack port")


def install_base_packages() -> None:
    if shutil.which("apt-get") is None:
        raise DeployError("Only Debian and Ubuntu are currently supported")
    run(["apt-get", "update"])
    run(["apt-get", "install", "-y", "ca-certificates", "curl", "openssl", "iproute2"])


def ensure_docker(config: dict[str, Any]) -> None:
    if shutil.which("docker"):
        result = run(["docker", "compose", "version"], check=False, capture=True)
        if result.returncode == 0:
            return
    if not bool(section(config, "stack").get("install_docker", True)):
        raise DeployError("Docker is missing and stack.install_docker is false")
    script = Path("/tmp/get-docker.sh")
    run(["curl", "-fsSL", "https://get.docker.com", "-o", str(script)])
    run(["sh", str(script)])
    script.unlink(missing_ok=True)
    run(["systemctl", "enable", "--now", "docker"])


def random_password(length: int = 28) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def get_cloudflare_token(config: dict[str, Any]) -> str:
    token = os.environ.get("CLOUDFLARE_API_TOKEN", "").strip()
    if not token:
        token = str(section(config, "cloudflare").get("api_token", "")).strip()
    if not token:
        token = getpass.getpass("Cloudflare API Token: ").strip()
    if not token:
        raise DeployError("Cloudflare API Token cannot be empty")
    return token


def write_file(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.rstrip() + "\n", encoding="utf-8")
    path.chmod(mode)


def backup_generated_files(stack_dir: Path) -> None:
    names = ["docker-compose.yml", "Caddyfile", ".env", "secrets.txt"]
    existing = [stack_dir / name for name in names if (stack_dir / name).exists()]
    if not existing:
        return
    backup_dir = stack_dir / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    archive = backup_dir / f"config-{stamp}.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        for item in existing:
            tar.add(item, arcname=item.name)
    log(f"Backed up generated configuration to {archive}")


def prepare_directories(stack_dir: Path) -> None:
    for relative in (
        "3x-ui/db", "3x-ui/cert", "caddy/data", "caddy/config",
        "caddy-build", "secrets", "backups"
    ):
        (stack_dir / relative).mkdir(parents=True, exist_ok=True)


def bcrypt_hash(password: str) -> str:
    result = run([
        "docker", "run", "--rm", "caddy:2-alpine", "caddy",
        "hash-password", "--plaintext", password
    ], capture=True)
    value = result.stdout.strip()
    if not value.startswith("$2"):
        raise DeployError("Failed to generate Caddy bcrypt hash")
    return value


def install_origin_certificate(config: dict[str, Any], stack_dir: Path) -> tuple[Path, Path]:
    tls = section(config, "panel.tls")
    source_cert = Path(str(tls["certificate_file"])).expanduser().resolve()
    source_key = Path(str(tls["private_key_file"])).expanduser().resolve()
    target_cert = stack_dir / "secrets" / "cloudflare-origin.crt"
    target_key = stack_dir / "secrets" / "cloudflare-origin.key"
    shutil.copy2(source_cert, target_cert)
    shutil.copy2(source_key, target_key)
    target_cert.chmod(0o644)
    target_key.chmod(0o600)
    return target_cert, target_key


def generate_files(config: dict[str, Any], token: str | None) -> Path:
    stack = section(config, "stack")
    domains = section(config, "domains")
    ports = section(config, "ports")
    panel = section(config, "panel")
    docker = section(config, "docker")
    mode = tls_mode(config)

    stack_dir = Path(str(stack["install_dir"])).resolve()
    prepare_directories(stack_dir)
    backup_generated_files(stack_dir)

    password = str(panel.get("basic_auth_password", "")).strip() or random_password()
    password_hash = bcrypt_hash(password)
    panel_path = normalize_path(str(panel.get("path", "/")), "panel.path")
    sub_path = normalize_path(str(panel.get("subscription_path", "/sub")), "panel.subscription_path")

    env_lines = [
        f"TZ={stack.get('timezone', 'UTC')}",
        f"XUI_IMAGE={docker.get('xui_image')}",
        f"CADDY_IMAGE={docker.get('caddy_image')}",
        f"PROXY_PORT={ports.get('proxy')}",
        f"PANEL_PUBLIC_PORT={ports.get('panel_public')}",
    ]
    if token:
        env_lines.append(f"CLOUDFLARE_API_TOKEN={token}")
    write_file(stack_dir / ".env", "\n".join(env_lines), 0o600)

    udp_line = (
        '      - "${PROXY_PORT}:${PROXY_PORT}/udp"\n'
        if bool(ports.get("publish_proxy_udp", False)) else ""
    )
    ipv6_lines = ""
    if bool(docker.get("enable_ipv6", True)):
        ipv6_lines = "    enable_ipv6: true\n"
        subnet = str(docker.get("ipv6_subnet", "")).strip()
        if subnet:
            ipv6_lines += f'    ipam:\n      config:\n        - subnet: "{subnet}"\n'

    if mode == "cloudflare_origin":
        install_origin_certificate(config, stack_dir)
        caddy_build = ""
        caddy_volumes = (
            "      - ./secrets/cloudflare-origin.crt:/run/secrets/cloudflare-origin.crt:ro\n"
            "      - ./secrets/cloudflare-origin.key:/run/secrets/cloudflare-origin.key:ro\n"
        )
        caddy_environment = "      TZ: ${TZ}\n"
    else:
        write_file(
            stack_dir / "caddy-build" / "Dockerfile",
            "FROM caddy:2-builder-alpine AS builder\n"
            "RUN xcaddy build --with github.com/caddy-dns/cloudflare\n"
            "FROM caddy:2-alpine\n"
            "COPY --from=builder /usr/bin/caddy /usr/bin/caddy\n",
            0o644,
        )
        caddy_build = "    build:\n      context: ./caddy-build\n"
        caddy_volumes = ""
        caddy_environment = (
            "      TZ: ${TZ}\n"
            "      CLOUDFLARE_API_TOKEN: ${CLOUDFLARE_API_TOKEN}\n"
        )

    compose = f"""\
services:
  3x-ui:
    image: ${{XUI_IMAGE}}
    container_name: 3x-ui
    restart: unless-stopped
    environment:
      TZ: ${{TZ}}
    volumes:
      - ./3x-ui/db:/etc/x-ui
      - ./3x-ui/cert:/root/cert
    ports:
      - "${{PROXY_PORT}}:${{PROXY_PORT}}/tcp"
{udp_line}    expose:
      - "{ports['panel_internal']}/tcp"
      - "{ports['subscription_internal']}/tcp"
    networks:
      - {docker['network_name']}

  caddy:
{caddy_build}    image: ${{CADDY_IMAGE}}
    container_name: caddy-panel
    restart: unless-stopped
    environment:
{caddy_environment}    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - ./caddy/data:/data
      - ./caddy/config:/config
{caddy_volumes}    ports:
      - "${{PANEL_PUBLIC_PORT}}:${{PANEL_PUBLIC_PORT}}/tcp"
    networks:
      - {docker['network_name']}
    depends_on:
      - 3x-ui

networks:
  {docker['network_name']}:
    name: {docker['network_name']}
{ipv6_lines.rstrip()}
"""
    write_file(stack_dir / "docker-compose.yml", compose, 0o600)

    cidrs = " ".join(str(item) for item in panel.get("allowed_cidrs", []))
    whitelist = ""
    if cidrs:
        whitelist = (
            f"        @panel_denied not remote_ip {cidrs}\n"
            '        respond @panel_denied "Not Found" 404\n\n'
        )

    subscription_route = f"""\
    @subscription path {sub_path} {sub_path}/*
    handle @subscription {{
        reverse_proxy 3x-ui:{ports['subscription_internal']}
    }}
"""
    if panel_path == "/":
        panel_route = f"""\
    handle {{
{whitelist}        basic_auth {{
            {panel['basic_auth_user']} {password_hash}
        }}
        reverse_proxy 3x-ui:{ports['panel_internal']}
    }}
"""
    else:
        panel_route = f"""\
    @panel path {panel_path} {panel_path}/*
    handle @panel {{
{whitelist}        basic_auth {{
            {panel['basic_auth_user']} {password_hash}
        }}
        reverse_proxy 3x-ui:{ports['panel_internal']}
    }}
    handle {{
        respond "Not Found" 404
    }}
"""

    if mode == "cloudflare_origin":
        tls_block = "    tls /run/secrets/cloudflare-origin.crt /run/secrets/cloudflare-origin.key"
        global_block = ""
    else:
        tls_block = (
            "    tls {\n"
            "        dns cloudflare {env.CLOUDFLARE_API_TOKEN}\n"
            "        resolvers 1.1.1.1 1.0.0.1\n"
            "    }"
        )
        global_block = f"{{\n    email {domains['acme_email']}\n}}\n\n"

    caddyfile = f"""\
{global_block}{domains['panel']}:{ports['panel_public']} {{
    encode zstd gzip
{tls_block}

{subscription_route}
{panel_route}
}}
"""
    write_file(stack_dir / "Caddyfile", caddyfile, 0o600)

    notes = [
        f"Panel URL: https://{domains['panel']}:{ports['panel_public']}{panel_path}",
        f"Subscription base: https://{domains['panel']}:{ports['panel_public']}{sub_path}/",
        f"Node address: {domains['node']}:{ports['proxy']}",
        f"Caddy BasicAuth user: {panel['basic_auth_user']}",
        f"Caddy BasicAuth password: {password}",
        f"TLS mode: {mode}",
    ]
    if mode == "cloudflare_origin":
        notes += [
            "Cloudflare panel DNS record must be Proxied.",
            "Cloudflare SSL/TLS mode must be Full (strict).",
            "The Origin CA certificate is not browser-trusted when accessed directly.",
        ]
    write_file(stack_dir / "secrets.txt", "\n".join(notes), 0o600)
    return stack_dir


def prepare_caddy(config: dict[str, Any], stack_dir: Path) -> None:
    docker_cfg = section(config, "docker")
    image = str(docker_cfg["caddy_image"])
    if tls_mode(config) == "cloudflare_origin":
        run(["docker", "pull", image])
        return

    force = bool(docker_cfg.get("force_rebuild_caddy", False))
    inspect = run(["docker", "image", "inspect", image], check=False, capture=True)
    module_ok = False
    if inspect.returncode == 0 and not force:
        modules = run(["docker", "run", "--rm", image, "caddy", "list-modules"],
                      check=False, capture=True)
        module_ok = "dns.providers.cloudflare" in modules.stdout
    if force or inspect.returncode != 0 or not module_ok:
        run(["docker", "compose", "build", "--pull", "caddy"], cwd=stack_dir)


def validate_caddy(config: dict[str, Any], stack_dir: Path) -> None:
    image = str(section(config, "docker")["caddy_image"])
    mounts = ["-v", f"{stack_dir / 'Caddyfile'}:/etc/caddy/Caddyfile"]
    if tls_mode(config) == "cloudflare_origin":
        mounts += [
            "-v", f"{stack_dir / 'secrets/cloudflare-origin.crt'}:/run/secrets/cloudflare-origin.crt:ro",
            "-v", f"{stack_dir / 'secrets/cloudflare-origin.key'}:/run/secrets/cloudflare-origin.key:ro",
        ]
    command = ["docker", "run", "--rm", *mounts, image, "caddy", "validate",
               "--config", "/etc/caddy/Caddyfile"]
    if tls_mode(config) == "acme_dns":
        command[3:3] = ["--env-file", str(stack_dir / ".env")]
    run(command)


def start_stack(config: dict[str, Any], stack_dir: Path) -> None:
    run(["docker", "compose", "pull", "3x-ui"], cwd=stack_dir)
    run(["docker", "compose", "up", "-d", "--remove-orphans"], cwd=stack_dir)
    run(["docker", "compose", "ps"], cwd=stack_dir)
    if bool(section(config, "stack").get("prune_dangling_images", True)):
        run(["docker", "image", "prune", "-f"])


def create_admin_user(config: dict[str, Any]) -> None:
    hardening = section(config, "hardening")
    ssh_cfg = section(config, "hardening.ssh")
    system_cfg = section(config, "hardening.system")
    if not (hardening.get("enabled") and ssh_cfg.get("enabled") and ssh_cfg.get("create_admin_user")):
        return
    username = str(ssh_cfg["admin_user"])
    if not re.fullmatch(r"[a-z_][a-z0-9_-]*[$]?", username):
        raise DeployError(f"Invalid admin username: {username}")
    try:
        user_info = pwd.getpwnam(username)
    except KeyError:
        run(["useradd", "--create-home", "--shell", "/bin/bash", username])
        run(["passwd", "-l", username])
        user_info = pwd.getpwnam(username)
    if bool(ssh_cfg.get("grant_sudo", True)):
        run(["usermod", "-aG", "sudo", username])
        sudoers = Path(f"/etc/sudoers.d/90-{username}")
        write_file(sudoers, f"{username} ALL=(ALL:ALL) ALL", 0o440)
        run(["visudo", "-cf", str(sudoers)])
    if bool(system_cfg.get("remove_admin_from_docker_group", True)):
        run(["gpasswd", "-d", username, "docker"], check=False)
    if bool(ssh_cfg.get("copy_root_authorized_keys", True)):
        source = Path("/root/.ssh/authorized_keys")
        if not source.is_file() or source.stat().st_size == 0:
            raise DeployError("/root/.ssh/authorized_keys is empty")
        ssh_dir = Path(user_info.pw_dir) / ".ssh"
        ssh_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        target = ssh_dir / "authorized_keys"
        shutil.copy2(source, target)
        os.chown(ssh_dir, user_info.pw_uid, user_info.pw_gid)
        os.chown(target, user_info.pw_uid, user_info.pw_gid)
        ssh_dir.chmod(0o700)
        target.chmod(0o600)


def port_is_listening(port: int) -> bool:
    result = run(["ss", "-H", "-ltn", f"sport = :{port}"], check=False, capture=True)
    return bool(result.stdout.strip())


def configure_ssh(config: dict[str, Any]) -> None:
    hardening = section(config, "hardening")
    cfg = section(config, "hardening.ssh")
    if not (hardening.get("enabled") and cfg.get("enabled")):
        return
    current_port, new_port = int(cfg["current_port"]), int(cfg["new_port"])
    if current_port != new_port and port_is_listening(new_port):
        raise DeployError(f"New SSH port {new_port} is already in use")
    dropin = Path("/etc/ssh/sshd_config.d/99-vps-hardening.conf")
    lines = [
        "# Generated by init_deploy_outbond",
        f"Port {new_port}", "PubkeyAuthentication yes", "PermitEmptyPasswords no",
        "StrictModes yes", f"MaxAuthTries {int(cfg.get('max_auth_tries', 3))}",
        f"LoginGraceTime {int(cfg.get('login_grace_time', 30))}",
        f"ClientAliveInterval {int(cfg.get('client_alive_interval', 300))}",
        f"ClientAliveCountMax {int(cfg.get('client_alive_count_max', 2))}",
        "UseDNS no",
        "PermitRootLogin no" if cfg.get("disable_root_login") else "PermitRootLogin prohibit-password",
    ]
    if cfg.get("disable_password_auth"):
        lines += ["PasswordAuthentication no", "KbdInteractiveAuthentication no",
                  "ChallengeResponseAuthentication no"]
    allow_users = [str(x) for x in cfg.get("allow_users", [])]
    if allow_users:
        lines.append("AllowUsers " + " ".join(allow_users))
    if cfg.get("disable_tcp_forwarding"):
        lines += ["AllowTcpForwarding no", "PermitTunnel no", "GatewayPorts no"]
    if cfg.get("disable_agent_forwarding"):
        lines.append("AllowAgentForwarding no")
    if cfg.get("disable_x11_forwarding"):
        lines.append("X11Forwarding no")
    write_file(dropin, "\n".join(lines), 0o600)
    run(["sshd", "-t"])

    socket_active = run(["systemctl", "is-active", "ssh.socket"], check=False, capture=True)
    socket_enabled = run(["systemctl", "is-enabled", "ssh.socket"], check=False, capture=True)
    if socket_active.returncode == 0 or socket_enabled.returncode == 0:
        write_file(
            Path("/etc/systemd/system/ssh.socket.d/override.conf"),
            f"[Socket]\nListenStream=\nListenStream={new_port}",
            0o644,
        )
        run(["systemctl", "daemon-reload"])
        run(["systemctl", "restart", "ssh.socket"])
    if run(["systemctl", "reload", "ssh"], check=False).returncode != 0:
        run(["systemctl", "reload", "sshd"])
    if not port_is_listening(new_port):
        raise DeployError(f"SSH is not listening on {new_port}; keep current session open")
    warn(f"Test before disconnecting: ssh -p {new_port} {cfg.get('admin_user')}@SERVER")


def configure_fail2ban(config: dict[str, Any]) -> None:
    if not section(config, "hardening").get("enabled"):
        return
    cfg = section(config, "hardening.fail2ban")
    if not cfg.get("enabled"):
        return
    ssh_port = int(section(config, "hardening.ssh")["new_port"])
    run(["apt-get", "install", "-y", "fail2ban"])
    ignore = " ".join(["127.0.0.1/8", "::1", *map(str, cfg.get("ignore_ips", []))])
    write_file(Path("/etc/fail2ban/jail.d/sshd-hardening.local"), textwrap.dedent(f"""\
        [sshd]
        enabled = true
        port = {ssh_port}
        backend = systemd
        maxretry = {int(cfg.get('max_retry', 5))}
        findtime = {cfg.get('find_time', '10m')}
        bantime = {cfg.get('ban_time', '1h')}
        ignoreip = {ignore}
    """), 0o644)
    run(["fail2ban-client", "-t"])
    run(["systemctl", "enable", "--now", "fail2ban"])
    run(["systemctl", "restart", "fail2ban"])


def configure_unattended(config: dict[str, Any]) -> None:
    if not section(config, "hardening").get("enabled"):
        return
    cfg = section(config, "hardening.unattended_upgrades")
    if not cfg.get("enabled"):
        return
    run(["apt-get", "install", "-y", "unattended-upgrades", "apt-listchanges"])
    write_file(Path("/etc/apt/apt.conf.d/20auto-upgrades"),
               'APT::Periodic::Update-Package-Lists "1";\n'
               'APT::Periodic::Unattended-Upgrade "1";\n'
               'APT::Periodic::AutocleanInterval "7";', 0o644)
    reboot = "true" if cfg.get("automatic_reboot") else "false"
    write_file(Path("/etc/apt/apt.conf.d/52proxy-stack-unattended"),
               f'Unattended-Upgrade::Automatic-Reboot "{reboot}";\n'
               f'Unattended-Upgrade::Automatic-Reboot-Time "{cfg.get("reboot_time", "04:30")}";\n'
               'Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";\n'
               'Unattended-Upgrade::Remove-Unused-Dependencies "true";', 0o644)


def configure_system(config: dict[str, Any]) -> None:
    if not section(config, "hardening").get("enabled"):
        return
    cfg = section(config, "hardening.system")
    if cfg.get("disable_apport"):
        run(["systemctl", "disable", "--now", "apport.service", "apport-autoreport.path"], check=False)
    if not cfg.get("enable_sysctl"):
        return
    values = [
        "net.ipv4.conf.all.accept_source_route = 0",
        "net.ipv4.conf.default.accept_source_route = 0",
        "net.ipv6.conf.all.accept_source_route = 0",
        "net.ipv6.conf.default.accept_source_route = 0",
        "net.ipv4.tcp_syncookies = 1",
        "kernel.kptr_restrict = 2",
        "kernel.dmesg_restrict = 1",
        "kernel.unprivileged_bpf_disabled = 1",
        "fs.protected_hardlinks = 1",
        "fs.protected_symlinks = 1",
    ]
    if cfg.get("disable_redirects"):
        values += [
            "net.ipv4.conf.all.accept_redirects = 0",
            "net.ipv4.conf.default.accept_redirects = 0",
            "net.ipv6.conf.all.accept_redirects = 0",
            "net.ipv6.conf.default.accept_redirects = 0",
            "net.ipv4.conf.all.send_redirects = 0",
            "net.ipv4.conf.default.send_redirects = 0",
        ]
    write_file(Path("/etc/sysctl.d/99-vps-hardening.conf"), "\n".join(values), 0o644)
    run(["sysctl", "--system"])


def deploy(config: dict[str, Any]) -> None:
    require_root()
    validate_config(config)
    install_base_packages()
    ensure_docker(config)
    token = get_cloudflare_token(config) if tls_mode(config) == "acme_dns" else None
    stack_dir = generate_files(config, token)
    prepare_caddy(config, stack_dir)
    validate_caddy(config, stack_dir)
    start_stack(config, stack_dir)
    create_admin_user(config)
    configure_ssh(config)
    configure_fail2ban(config)
    configure_unattended(config)
    configure_system(config)
    print(f"\nDeployment complete\nSecrets: {stack_dir / 'secrets.txt'}")
    if tls_mode(config) == "cloudflare_origin":
        print("Panel DNS must be Cloudflare Proxied and SSL/TLS mode must be Full (strict).")


def status(config: dict[str, Any]) -> None:
    stack_dir = Path(str(section(config, "stack")["install_dir"])).resolve()
    run(["docker", "compose", "ps"], cwd=stack_dir)
    run(["ss", "-lntup"], check=False)
    run(["docker", "network", "inspect", str(section(config, "docker")["network_name"])],
        check=False)


def update(config: dict[str, Any]) -> None:
    require_root()
    validate_config(config)
    stack_dir = Path(str(section(config, "stack")["install_dir"])).resolve()
    run(["docker", "compose", "pull"], cwd=stack_dir)
    if tls_mode(config) == "acme_dns" and bool(section(config, "docker").get("force_rebuild_caddy")):
        run(["docker", "compose", "build", "--pull", "caddy"], cwd=stack_dir)
    run(["docker", "compose", "up", "-d", "--remove-orphans"], cwd=stack_dir)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("config.toml"))
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("deploy")
    commands.add_parser("status")
    commands.add_parser("update")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        config = load_config(args.config)
        {"deploy": deploy, "status": status, "update": update}[args.command](config)
        return 0
    except (DeployError, subprocess.CalledProcessError, OSError, ValueError) as exc:
        print(f"\033[1;31m[-] {exc}\033[0m", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
