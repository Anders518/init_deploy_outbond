from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class DeployError(RuntimeError):
    pass


def run(
    command: list[str],
    *,
    check: bool = True,
    capture: bool = False,
    cwd: Path | None = None,
    input_text: str | None = None,
    redact_values: set[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    redacted = [
        '********' if redact_values and value in redact_values else value
        for value in command
    ]
    print('$', shlex.join(redacted))
    return subprocess.run(
        command,
        check=check,
        text=True,
        capture_output=capture,
        cwd=cwd,
        input=input_text,
    )


def section(config: dict[str, Any], dotted: str) -> dict[str, Any]:
    value: Any = config
    for key in dotted.split('.'):
        if not isinstance(value, dict) or key not in value:
            raise DeployError(f'Missing configuration section: {dotted}')
        value = value[key]
    if not isinstance(value, dict):
        raise DeployError(f'Configuration section is not a table: {dotted}')
    return value


def write_file(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.rstrip() + '\n', encoding='utf-8')
    path.chmod(mode)


def read_secret_file(value: Any, label: str) -> str:
    raw = str(value or '').strip()
    if not raw:
        return ''
    path = Path(raw).expanduser().resolve()
    if not path.is_file():
        raise DeployError(f'{label} file does not exist: {path}')
    if path.stat().st_mode & 0o077:
        raise DeployError(f'{label} file must not be readable by group or other users: {path}')
    secret = path.read_text(encoding='utf-8').strip()
    if not secret:
        raise DeployError(f'{label} file is empty: {path}')
    return secret


@dataclass
class DeploymentContext:
    config: dict[str, Any]
    dry_run: bool = False
    state: dict[str, Any] = field(default_factory=dict)

    @property
    def stack_dir(self) -> Path:
        return Path(str(section(self.config, 'stack')['install_dir'])).resolve()


class Task:
    name = 'task'

    def enabled(self, context: DeploymentContext) -> bool:
        return True

    def validate(self, context: DeploymentContext) -> None:
        pass

    def apply(self, context: DeploymentContext) -> None:
        pass

    def verify(self, context: DeploymentContext) -> None:
        pass

    def execute(self, context: DeploymentContext) -> None:
        if not self.enabled(context):
            print(f'[skip] {self.name}')
            return
        print(f'[task] {self.name}')
        self.validate(context)
        if context.dry_run:
            return
        self.apply(context)
        self.verify(context)
