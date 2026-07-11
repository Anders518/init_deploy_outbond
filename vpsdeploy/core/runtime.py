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
) -> subprocess.CompletedProcess[str]:
    print('$', shlex.join(command))
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
