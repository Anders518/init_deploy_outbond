#!/usr/bin/env python3
"""Deploy 3x-ui and Caddy with Cloudflare DNS-01 on Debian/Ubuntu.

The program uses only the Python standard library. Runtime state and secrets are
written under stack.install_dir and are not intended to be committed to Git.
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
import socket
import string
import subprocess
import sys
import tarfile
import textwrap
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError as exc:  # pragma: no cover
    raise SystemExit("Python 3.11 or newer is required") from exc


class DeployError(RuntimeError):
    pass


def log(message: str) -> None:
    print(f"\033[1;32m[+] {message}\033[0m")


def warn(message: str) -> None:
    print(f"\033[1;33m[!] {message}\033[0m", file=sys.stderr)


def run(
    command: list[str],
    *,
    check: bool = True,
    capture: bool = False,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    print("$", shlex.join(command))
    return subprocess.run(
        command,
        check=check,
        text=True,
        capture_output=capture,
        cwd=cwd,
        env=env,
    )


def require_root() -> None:
    if os.geteuid() != 0:
        raise DeployError("Run this command as root, for example: sudo python3 deploy.py")


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


def validate_config(config: dict[str, Any]) -> None:
    domains = section(config, "domains")
    ports = section(config, "ports")
    panel = section(config, "panel")
    docker = section(config, "docker")

    for name in ("panel", "node", "acme_email"):
        if not str(domains.get(name, "")).strip():
            raise DeployError(f"domains.{name} cannot be empty")

    values = {
        "ports.proxy": validate_port(ports.get("proxy"), "ports.proxy"),
        "ports.panel_public": validate_port(ports.get("panel_public"), "ports.panel_public"),
        "ports.panel_internal": validate_port(ports.get("panel_internal"), "ports.panel_internal"),
        "ports.subscription_internal": validate_port(
            ports.get("subscription_internal"), "ports.subscription_internal"
        ),
    }
    if len(set(values.values())) != len(values):
        raise DeployError(f"Port conflict detected: {values}")

    normalize_path(str(panel.get("path", "/")), "panel.path")
    normalize_path(str(panel.get("subscription_path", "/sub")), "panel.subscription_path")

    for cidr in panel.get("allowed_cidrs", []):
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise DeployError(f"Invalid panel.allowed_cidrs entry: {cidr}") from exc

    subnet = str(docker.get("ipv6_subnet", "")).strip()
    if subnet:
        try:
            network = ipaddress.ip_network(subnet, strict=False)
        except ValueError as exc:
            raise DeployError(f"Invalid docker.ipv6_subnet: {subnet}") from exc
        if network.version != 6:
            raise DeployError("docker.ipv6_subnet must be IPv6")

    ssh_cfg = section(config, "hardening.ssh")
    new_ssh_port = validate_port(ssh_cfg.get("new_port"), "hardening.ssh.new_port")
    if new_ssh_port in values.values():
        raise DeployError("The new SSH port conflicts with a proxy-stack port")


def install_base_packages() -> None:
    if shutil.which("apt-get") is None:
        raise DeployError("Only Debian and Ubuntu are currently supported")
    log("Installing base packages")
    run(["apt-get", "update"])
    run(
        [
            "apt-get",
            "install",
            "-y",
            "ca-certificates",
            "curl",
            "openssl",
            "iproute2",
        ]
    )


def ensure_docker(config: dict[str, Any]) -> None:
    stack = section(config, "stack")
    if shutil.which("docker"):
        result = run(["docker", "compose", "version"], check=False, capture=True)
        if result.returncode == 0:
            log("Docker and Docker Compose are already installed")
            return
    if not bool(stack.get("install_docker", True)):
        raise DeployError("Docker is not installed and stack.install_docker is false")
    log("Installing Docker")
    script = Path("/tmp/get-docker.sh")
    run(["curl", "-fsSL", "https://get.docker.com", "-o", str(script)])
    run(["sh", str(script)])
    script.unlink(missing_ok=True)
    run(["systemctl", "enable", "--now", "docker"])
    run(["docker", "compose", "version"])


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


def backup_generated_files(stack_dir: Path) -> None:
    candidates = ["docker-compose.yml", "Caddyfile", ".env", "secrets.txt"]
    existing = [stack_dir / name for name in candidates if (stack_dir / name).exists()]
    if not existing:
        return
    backup_dir = stack_dir / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    archive = backup_dir / f"config-{timestamp}.tar.gz"
    log(f"Backing up current generated configuration to {archive}")
    with tarfile.open(archive, "w:gz") as tar:
        for item in existing:
            tar.add(item, arcname=item.name)


def create_directories(stack_dir: Path) -> None:
    for relative in (
        "3x-ui/db",
        "3x-ui/cert",
        "caddy/data",
        "caddy/config",
        "caddy-build",
        "backups",
    ):
        (stack_dir / relative).mkdir(parents=True, exist_ok=True)


def write_file(path: Path, content: str, mode: int = 0o600) -> None:
    path.write_text(content.rstrip() + "\n", encoding="utf-8")
    path.chmod(mode)


def bcrypt_hash(password: str) -> str:
    result = run(
        [
            "docker",
            "run",
            "--rm",
            "caddy:2-alpine",
            "caddy",
            "hash-password",
            "--plaintext",
            password,
        ],
        capture=True,
    )
    value = result.stdout.strip()
    if not value.startswith("$2"):
        raise DeployError("Failed to generate a Caddy bcrypt password hash")
    return value


def generate_files(config: dict[str, Any], token: str) -> tuple[Path, str]:
    stack = section(config, "stack")
    domains = section(config, "domains")
    ports = section(config, "ports")
    panel = section(config, "panel")
    docker = section(config, "docker")

    stack_dir = Path(str(stack["install_dir"])).resolve()
    create_directories(stack_dir)
    backup_generated_files(stack_dir)

    password = str(panel.get("basic_auth_password", "")).strip() or random_password()
    password_hash = bcrypt_hash(password)
    panel_path = normalize_path(str(panel.get("path", "/")), "panel.path")
    sub_path = normalize_path(
        str(panel.get("subscription_path", "/sub")), "panel.subscription_path"
    )

    write_file(
        stack_dir / ".env",
        textwrap.dedent(
            f"""\
            TZ={stack.get('timezone', 'UTC')}
            CLOUDFLARE_API_TOKEN={token}
            XUI_IMAGE={docker.get('xui_image')}
            CADDY_IMAGE={docker.get('caddy_image')}
            PROXY_PORT={ports.get('proxy')}
            PANEL_PUBLIC_PORT={ports.get('panel_public')}
            """
        ),
    )

    udp_line = (
        '      - "${PROXY_PORT}:${PROXY_PORT}/udp"\n'
        if bool(ports.get("publish_proxy_udp", False))
        else ""
    )
    ipv6_lines = ""
    if bool(docker.get("enable_ipv6", True)):
        ipv6_lines += "    enable_ipv6: true\n"
        subnet = str(docker.get("ipv6_subnet", "")).strip()
        if subnet:
            ipv6_lines += f'    ipam:\n      config:\n        - subnet: "{subnet}"\n'

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
    build:
      context: ./caddy-build
    image: ${{CADDY_IMAGE}}
    container_name: caddy-panel
    restart: unless-stopped
    environment:
      TZ: ${{TZ}}
      CLOUDFLARE_API_TOKEN: ${{CLOUDFLARE_API_TOKEN}}
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - ./caddy/data:/data
      - ./caddy/config:/config
    ports:
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

    write_file(
        stack_dir / "caddy-build" / "Dockerfile",
        """\
FROM caddy:2-builder-alpine AS builder
RUN xcaddy build --with github.com/caddy-dns/cloudflare
FROM caddy:2-alpine
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
""",
        0o644,
    )

    cidrs = " ".join(str(item) for item in panel.get("allowed_cidrs", []))
    whitelist = ""
    if cidrs:
        whitelist = f'        @panel_denied not remote_ip {cidrs}\n        respond @panel_denied "Not Found" 404\n\n'

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

    caddyfile = f"""\
{{
    email {domains['acme_email']}
}}

{domains['panel']}:{ports['panel_public']} {{
    encode zstd gzip
    tls {{
        dns cloudflare {{env.CLOUDFLARE_API_TOKEN}}
        resolvers 1.1.1.1 1.0.0.1
    }}

{subscription_route}
{panel_route}
}}
"""
    write_file(stack_dir / "Caddyfile", caddyfile, 0o600)

    secrets_file = f"""\
Panel URL: https://{domains['panel']}:{ports['panel_public']}{panel_path}
Subscription base: https://{domains['panel']}:{ports['panel_public']}{sub_path}/
Node address: {domains['node']}:{ports['proxy']}
Caddy BasicAuth user: {panel['basic_auth_user']}
Caddy BasicAuth password: {password}

3x-ui required settings:
  Panel listen IP: 0.0.0.0 or blank
  Panel internal port: {ports['panel_internal']}
  Panel URI path: {panel_path}
  Subscription internal port: {ports['subscription_internal']}
  Subscription URI path: {sub_path}
  Subscription external scheme/domain/port: https / {domains['panel']} / {ports['panel_public']}
  VLESS inbound: TCP + Reality + xtls-rprx-vision on {ports['proxy']}
"""
    write_file(stack_dir / "secrets.txt", secrets_file, 0o600)
    return stack_dir, password


def build_caddy_if_needed(config: dict[str, Any], stack_dir: Path) -> None:
    docker_cfg = section(config, "docker")
    image = str(docker_cfg["caddy_image"])
    force = bool(docker_cfg.get("force_rebuild_caddy", False))
    inspect = run(["docker", "image", "inspect", image], check=False, capture=True)
    module_ok = False
    if inspect.returncode == 0 and not force:
        modules = run(
            ["docker", "run", "--rm", image, "caddy", "list-modules"],
            check=False,
            capture=True,
        )
        module_ok = "dns.providers.cloudflare" in modules.stdout
    if force or inspect.returncode != 0 or not module_ok:
        log("Building Caddy with the Cloudflare DNS module")
        run(["docker", "compose", "build", "--pull", "caddy"], cwd=stack_dir)
    else:
        log("Existing Caddy Cloudflare image is valid; skipping build")


def validate_caddy(config: dict[str, Any], stack_dir: Path) -> None:
    image = str(section(config, "docker")["caddy_image"])
    run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{stack_dir / 'Caddyfile'}:/etc/caddy/Caddyfile",
            image,
            "caddy",
            "fmt",
            "--overwrite",
            "/etc/caddy/Caddyfile",
        ]
    )
    run(
        [
            "docker",
            "run",
            "--rm",
            "--env-file",
            str(stack_dir / ".env"),
            "-v",
            f"{stack_dir / 'Caddyfile'}:/etc/caddy/Caddyfile:ro",
            image,
            "caddy",
            "validate",
            "--config",
            "/etc/caddy/Caddyfile",
        ]
    )


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
        if not source.exists() or source.stat().st_size == 0:
            raise DeployError("/root/.ssh/authorized_keys is empty; refusing SSH lockout risk")
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

    current_port = int(cfg["current_port"])
    new_port = int(cfg["new_port"])
    if current_port != new_port and port_is_listening(new_port):
        raise DeployError(f"New SSH port {new_port} is already in use")

    dropin_dir = Path("/etc/ssh/sshd_config.d")
    dropin_dir.mkdir(parents=True, exist_ok=True)
    dropin = dropin_dir / "99-vps-hardening.conf"
    backup = dropin.with_suffix(f".backup-{dt.datetime.now(dt.UTC).strftime('%Y%m%dT%H%M%SZ')}")
    if dropin.exists():
        shutil.copy2(dropin, backup)

    lines = [
        "# Generated by init_deploy_outbond",
        f"Port {new_port}",
        "PubkeyAuthentication yes",
        "PermitEmptyPasswords no",
        "StrictModes yes",
        f"MaxAuthTries {int(cfg.get('max_auth_tries', 3))}",
        f"LoginGraceTime {int(cfg.get('login_grace_time', 30))}",
        f"ClientAliveInterval {int(cfg.get('client_alive_interval', 300))}",
        f"ClientAliveCountMax {int(cfg.get('client_alive_count_max', 2))}",
        "UseDNS no",
        "PermitRootLogin no" if cfg.get("disable_root_login") else "PermitRootLogin prohibit-password",
    ]
    if cfg.get("disable_password_auth"):
        lines += [
            "PasswordAuthentication no",
            "KbdInteractiveAuthentication no",
            "ChallengeResponseAuthentication no",
        ]
    allow_users = [str(item) for item in cfg.get("allow_users", [])]
    if allow_users:
        lines.append("AllowUsers " + " ".join(allow_users))
    if cfg.get("disable_tcp_forwarding"):
        lines += ["AllowTcpForwarding no", "PermitTunnel no", "GatewayPorts no"]
    if cfg.get("disable_agent_forwarding"):
        lines.append("AllowAgentForwarding no")
    if cfg.get("disable_x11_forwarding"):
        lines.append("X11Forwarding no")
    write_file(dropin, "\n".join(lines), 0o600)

    test = run(["sshd", "-t"], check=False)
    if test.returncode != 0:
        if backup.exists():
            shutil.copy2(backup, dropin)
        else:
            dropin.unlink(missing_ok=True)
        raise DeployError("New SSH configuration failed validation and was rolled back")

    socket_active = run(["systemctl", "is-active", "ssh.socket"], check=False, capture=True)
    socket_enabled = run(["systemctl", "is-enabled", "ssh.socket"], check=False, capture=True)
    if socket_active.returncode == 0 or socket_enabled.returncode == 0:
        override_dir = Path("/etc/systemd/system/ssh.socket.d")
        override_dir.mkdir(parents=True, exist_ok=True)
        write_file(
            override_dir / "override.conf",
            f"[Socket]\nListenStream=\nListenStream={new_port}",
            0o644,
        )
        run(["systemctl", "daemon-reload"])
        run(["systemctl", "restart", "ssh.socket"])

    reload_result = run(["systemctl", "reload", "ssh"], check=False)
    if reload_result.returncode != 0:
        run(["systemctl", "reload", "sshd"])
    if not port_is_listening(new_port):
        raise DeployError(
            f"SSH is not listening on {new_port}. Keep the current session open and inspect ssh.service."
        )
    warn(
        f"Before closing this session, test a new login: ssh -p {new_port} "
        f"{cfg.get('admin_user')}@SERVER"
    )


def configure_fail2ban(config: dict[str, Any]) -> None:
    hardening = section(config, "hardening")
    cfg = section(config, "hardening.fail2ban")
    if not (hardening.get("enabled") and cfg.get("enabled")):
        return
    ssh_port = int(section(config, "hardening.ssh")["new_port"])
    run(["apt-get", "install", "-y", "fail2ban"])
    ignore = " ".join(["127.0.0.1/8", "::1", *map(str, cfg.get("ignore_ips", []))])
    write_file(
        Path("/etc/fail2ban/jail.d/sshd-hardening.local"),
        textwrap.dedent(
            f"""\
            [sshd]
            enabled = true
            port = {ssh_port}
            backend = systemd
            maxretry = {int(cfg.get('max_retry', 5))}
            findtime = {cfg.get('find_time', '10m')}
            bantime = {cfg.get('ban_time', '1h')}
            ignoreip = {ignore}
            """
        ),
        0o644,
    )
    run(["fail2ban-client", "-t"])
    run(["systemctl", "enable", "--now", "fail2ban"])
    run(["systemctl", "restart", "fail2ban"])


def configure_unattended_upgrades(config: dict[str, Any]) -> None:
    hardening = section(config, "hardening")
    cfg = section(config, "hardening.unattended_upgrades")
    if not (hardening.get("enabled") and cfg.get("enabled")):
        return
    run(["apt-get", "install", "-y", "unattended-upgrades", "apt-listchanges"])
    write_file(
        Path("/etc/apt/apt.conf.d/20auto-upgrades"),
        'APT::Periodic::Update-Package-Lists "1";\n'
        'APT::Periodic::Unattended-Upgrade "1";\n'
        'APT::Periodic::AutocleanInterval "7";',
        0o644,
    )
    reboot = "true" if cfg.get("automatic_reboot") else "false"
    write_file(
        Path("/etc/apt/apt.conf.d/52proxy-stack-unattended"),
        f'Unattended-Upgrade::Automatic-Reboot "{reboot}";\n'
        f'Unattended-Upgrade::Automatic-Reboot-Time "{cfg.get("reboot_time", "04:30")}";\n'
        'Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";\n'
        'Unattended-Upgrade::Remove-Unused-Dependencies "true";',
        0o644,
    )
    run(["systemctl", "enable", "--now", "unattended-upgrades.service"], check=False)


def configure_system_hardening(config: dict[str, Any]) -> None:
    hardening = section(config, "hardening")
    cfg = section(config, "hardening.system")
    if not hardening.get("enabled"):
        return
    if cfg.get("disable_apport"):
        run(["systemctl", "disable", "--now", "apport.service", "apport-autoreport.path"], check=False)
        apport = Path("/etc/default/apport")
        if apport.exists():
            text = re.sub(r"^enabled=.*$", "enabled=0", apport.read_text(), flags=re.MULTILINE)
            write_file(apport, text, 0o644)
    if not cfg.get("enable_sysctl"):
        return
    values = [
        "net.ipv4.conf.all.accept_source_route = 0",
        "net.ipv4.conf.default.accept_source_route = 0",
        "net.ipv6.conf.all.accept_source_route = 0",
        "net.ipv6.conf.default.accept_source_route = 0",
        "net.ipv4.conf.all.log_martians = 1",
        "net.ipv4.conf.default.log_martians = 1",
        "net.ipv4.tcp_syncookies = 1",
        "kernel.kptr_restrict = 2",
        "kernel.dmesg_restrict = 1",
        "kernel.perf_event_paranoid = 3",
        "kernel.unprivileged_bpf_disabled = 1",
        "fs.protected_fifos = 2",
        "fs.protected_regular = 2",
        "fs.protected_hardlinks = 1",
        "fs.protected_symlinks = 1",
    ]
    if cfg.get("disable_redirects"):
        values += [
            "net.ipv4.conf.all.accept_redirects = 0",
            "net.ipv4.conf.default.accept_redirects = 0",
            "net.ipv4.conf.all.secure_redirects = 0",
            "net.ipv4.conf.default.secure_redirects = 0",
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
    token = get_cloudflare_token(config)
    stack_dir, _ = generate_files(config, token)
    build_caddy_if_needed(config, stack_dir)
    validate_caddy(config, stack_dir)
    start_stack(config, stack_dir)

    create_admin_user(config)
    configure_ssh(config)
    configure_fail2ban(config)
    configure_unattended_upgrades(config)
    configure_system_hardening(config)

    domains = section(config, "domains")
    ports = section(config, "ports")
    panel = section(config, "panel")
    print("\nDeployment complete")
    print(
        f"Panel: https://{domains['panel']}:{ports['panel_public']}"
        f"{normalize_path(str(panel.get('path', '/')), 'panel.path')}"
    )
    print(f"Secrets: {stack_dir / 'secrets.txt'}")
    print(f"Logs: cd {stack_dir} && docker compose logs -f")
    print("VPS firewall should allow the SSH port, proxy TCP port and panel public port only.")
    print("Do not expose the internal panel or subscription ports.")


def status(config: dict[str, Any]) -> None:
    stack_dir = Path(str(section(config, "stack")["install_dir"])).resolve()
    if not stack_dir.exists():
        raise DeployError(f"Stack directory does not exist: {stack_dir}")
    run(["docker", "compose", "ps"], cwd=stack_dir)
    run(["ss", "-lntup"], check=False)
    network_name = str(section(config, "docker")["network_name"])
    run(["docker", "network", "inspect", network_name], check=False)


def update(config: dict[str, Any]) -> None:
    require_root()
    stack_dir = Path(str(section(config, "stack")["install_dir"])).resolve()
    run(["docker", "compose", "pull", "3x-ui"], cwd=stack_dir)
    if bool(section(config, "docker").get("force_rebuild_caddy", False)):
        run(["docker", "compose", "build", "--pull", "caddy"], cwd=stack_dir)
    run(["docker", "compose", "up", "-d", "--remove-orphans"], cwd=stack_dir)
    run(["docker", "image", "prune", "-f"])


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("config.toml"))
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("deploy", help="Generate configuration and deploy the stack")
    subparsers.add_parser("status", help="Show container, port and network status")
    subparsers.add_parser("update", help="Update 3x-ui and optionally rebuild Caddy")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        config = load_config(args.config)
        if args.command == "deploy":
            deploy(config)
        elif args.command == "status":
            status(config)
        elif args.command == "update":
            update(config)
        else:  # pragma: no cover
            raise DeployError(f"Unknown command: {args.command}")
        return 0
    except (DeployError, subprocess.CalledProcessError, OSError) as exc:
        print(f"\033[1;31m[-] {exc}\033[0m", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
