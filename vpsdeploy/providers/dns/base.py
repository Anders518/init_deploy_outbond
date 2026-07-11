from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from vpsdeploy.core.runtime import DeploymentContext


@dataclass(frozen=True)
class DNSRecordSpec:
    name: str
    record_type: str
    content: str
    proxied: bool
    ttl: int = 1


class DNSProvider(Protocol):
    def validate(self, context: DeploymentContext) -> None: ...

    def reconcile(self, context: DeploymentContext, records: list[DNSRecordSpec]) -> None: ...

    def verify(self, context: DeploymentContext, records: list[DNSRecordSpec]) -> None: ...
