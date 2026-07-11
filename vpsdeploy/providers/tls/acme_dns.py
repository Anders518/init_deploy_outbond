from __future__ import annotations

import os

from vpsdeploy.core.runtime import DeployError, DeploymentContext, section
from vpsdeploy.providers.tls.base import TLSMaterial


class AcmeDNSProvider:
    def validate(self, context: DeploymentContext) -> None:
        if not str(section(context.config, 'domains').get('acme_email', '')).strip():
            raise DeployError('domains.acme_email is required for acme_dns mode')

    def obtain(self, context: DeploymentContext) -> TLSMaterial:
        token = os.environ.get('CLOUDFLARE_API_TOKEN', '').strip()
        if not token:
            token = str(section(context.config, 'cloudflare').get('api_token', '')).strip()
        if not token:
            raise DeployError('Set CLOUDFLARE_API_TOKEN for acme_dns mode')
        return TLSMaterial(
            mode='acme_dns',
            requires_custom_caddy=True,
            environment={'CLOUDFLARE_API_TOKEN': token},
        )
