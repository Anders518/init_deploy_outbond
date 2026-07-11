from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from vpsdeploy.core.runtime import DeploymentContext


@dataclass(frozen=True)
class TLSMaterial:
    mode: str
    certificate: Path | None = None
    private_key: Path | None = None
    requires_custom_caddy: bool = False
    environment: dict[str, str] | None = None


class TLSProvider(Protocol):
    def validate(self, context: DeploymentContext) -> None: ...
    def obtain(self, context: DeploymentContext) -> TLSMaterial: ...
