from __future__ import annotations

from vpsdeploy.core.runtime import DeployError, DeploymentContext, Task, section
from vpsdeploy.providers.tls.acme_dns import AcmeDNSProvider
from vpsdeploy.providers.tls.cloudflare_origin import CloudflareOriginProvider


class CertificateTask(Task):
    name = 'certificate'

    def _provider(self, context: DeploymentContext):
        mode = str(section(context.config, 'panel.tls').get('mode', 'cloudflare_origin'))
        if mode == 'cloudflare_origin':
            return CloudflareOriginProvider()
        if mode == 'acme_dns':
            return AcmeDNSProvider()
        raise DeployError(f'Unsupported TLS mode: {mode}')

    def validate(self, context: DeploymentContext) -> None:
        self._provider(context).validate(context)

    def apply(self, context: DeploymentContext) -> None:
        context.state['tls'] = self._provider(context).obtain(context)

    def verify(self, context: DeploymentContext) -> None:
        material = context.state['tls']
        if material.certificate and not material.certificate.is_file():
            raise DeployError('TLS certificate was not created')
        if material.private_key and not material.private_key.is_file():
            raise DeployError('TLS private key was not created')
