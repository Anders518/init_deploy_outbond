from __future__ import annotations

import shlex
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class DeployError(RuntimeError):
    pass


@dataclass
class FileSnapshot:
    path: Path
    existed: bool
    content: bytes = b''
    mode: int = 0o600

    @classmethod
    def capture(cls, path: Path) -> 'FileSnapshot':
        if not path.exists():
            return cls(path, False)
        return cls(path, True, path.read_bytes(), path.stat().st_mode & 0o777)

    def restore(self) -> None:
        if not self.existed:
            self.path.unlink(missing_ok=True)
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f'.{self.path.name}.vpsdeploy-rollback')
        temporary.write_bytes(self.content)
        temporary.chmod(self.mode)
        temporary.replace(self.path)


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


def run_retry(
    command: list[str], *, attempts: int = 6, interval: float = 1.0,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Retry short-lived runtime failures while preserving the final detail."""
    last: subprocess.CompletedProcess[str] | None = None
    for attempt in range(max(attempts, 1)):
        last = run(command, check=False, capture=True, cwd=cwd)
        if last.returncode == 0:
            return last
        if attempt + 1 < max(attempts, 1):
            time.sleep(interval)
    detail = ((last.stderr if last else '') or (last.stdout if last else '')).strip()
    raise DeployError(f'Command failed after {max(attempts, 1)} attempts: {detail or shlex.join(command)}')


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

    def prepare_rollback(self, context: DeploymentContext) -> Any:
        return None

    def rollback(self, context: DeploymentContext, snapshot: Any) -> None:
        pass

    def execute(self, context: DeploymentContext) -> None:
        if not self.enabled(context):
            print(f'[skip] {self.name}')
            return
        print(f'[task] {self.name}')
        self.validate(context)
        if context.dry_run:
            return
        snapshot = self.prepare_rollback(context)
        try:
            self.apply(context)
            self.verify(context)
        except Exception as exc:
            try:
                self.rollback(context, snapshot)
            except Exception as rollback_exc:
                raise DeployError(
                    f'{self.name} failed ({exc}); automatic rollback also failed: {rollback_exc}'
                ) from exc
            if snapshot is not None:
                print(f'[rollback] {self.name} restored its previous state')
            raise
