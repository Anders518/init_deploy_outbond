from __future__ import annotations

import os

from vpsdeploy.core.runtime import DeployError, DeploymentContext, read_secret_file, section
from vpsdeploy.providers.tls.base import TLSMaterial


class AcmeDNSProvider:
    def validate(self, context: DeploymentContext) -> None:
        if not str(section(context.config, 'domains').get('acme_email', '')).strip():
            raise DeployError('domains.acme_email is required for acme_dns mode')

    def obtain(self, context: DeploymentContext) -> TLSMaterial:
        token = os.environ.get('CLOUDFLARE_API_TOKEN', '').strip()
        if not token:
            cfg = section(context.config, 'cloudflare')
            token = str(cfg.get('api_token', '')).strip()
            token = token or read_secret_file(cfg.get('api_token_file', ''), 'Cloudflare API token')
        if not token:
            raise DeployError('Set CLOUDFLARE_API_TOKEN, cloudflare.api_token, or cloudflare.api_token_file for acme_dns mode')
        return TLSMaterial(
            mode='acme_dns',
            requires_custom_caddy=True,
            environment={'CLOUDFLARE_API_TOKEN': token},
        )
