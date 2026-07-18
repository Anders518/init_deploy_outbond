from __future__ import annotations

import os
import shlex
import subprocess
import sys
from pathlib import Path


class DeployError(RuntimeError):
    """Expected deployment failure with a user-facing message."""


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
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    print("$", shlex.join(command))
    return subprocess.run(
        command,
        check=check,
        text=True,
        capture_output=capture,
        cwd=cwd,
        input=input_text,
    )


def require_root() -> None:
    if os.geteuid() != 0:
        raise DeployError(
            "Run as root, for example: "
            "sudo uv run --no-dev --frozen python deploy.py deploy"
        )


def write_file(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(content.rstrip() + "\n", encoding="utf-8")
    temporary.chmod(mode)
    os.replace(temporary, path)


def port_is_listening(port: int) -> bool:
    result = run(["ss", "-H", "-ltn", f"sport = :{port}"], check=False, capture=True)
    return bool(result.stdout.strip())
