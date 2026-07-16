from __future__ import annotations

from pathlib import Path

from vpsdeploy.core.runtime import DeploymentContext, run
from vpsdeploy.tasks.proxy_stack import ProxyStackTask as BaseProxyStackTask


class ProxyStackTask(BaseProxyStackTask):
    """Proxy stack task that always refreshes Caddy bind mounts before validation.

    Docker Compose may leave a running Caddy container attached to stale certificate
    or private-key inodes when TLS material is replaced on the host. Recreating only
    Caddy after the normal compose reconciliation guarantees that the container sees
    the current certificate/key pair without restarting 3x-ui.
    """

    _stack_dir: Path | None = None

    def apply(self, context: DeploymentContext) -> None:
        self._stack_dir = context.stack_dir
        super().apply(context)

    def _reload_caddy(self) -> None:
        if self._stack_dir is None:
            raise RuntimeError('Proxy stack directory was not initialized')

        run(
            [
                'docker', 'compose', 'up', '-d', '--force-recreate',
                '--no-deps', 'caddy',
            ],
            cwd=self._stack_dir,
        )
        super()._reload_caddy()
