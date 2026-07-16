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
        mode = str(section(context.config, 'panel.tls').get('mode', 'cloudflare_origin'))
        domains = section(context.config, 'domains')
        panel_domain = str(domains['panel']).strip().lower()
        subscription_domain = str(domains.get('subscription', panel_domain)).strip().lower() or panel_domain
        dns_cfg = section(context.config, 'dns')
        dns_subscription = dns_cfg.get('subscription', {})
        if not isinstance(dns_subscription, dict):
            raise DeployError('dns.subscription must be a TOML table')

        subscription_is_direct = (
            subscription_domain != panel_domain
            and bool(dns_subscription.get('enabled', True))
            and not bool(dns_subscription.get('proxied', False))
        )
        if subscription_is_direct and mode != 'acme_dns':
            raise DeployError(
                'A DNS-only subscription host requires panel.tls.mode="acme_dns" so Mihomo, '
                'Loon, and browsers receive a publicly trusted certificate. Cloudflare Origin CA '
                'certificates are only intended for proxied Cloudflare-to-origin traffic.'
            )

        self._provider(context).validate(context)

    def apply(self, context: DeploymentContext) -> None:
        context.state['tls'] = self._provider(context).obtain(context)

    def verify(self, context: DeploymentContext) -> None:
        material = context.state['tls']
        if material.certificate and not material.certificate.is_file():
            raise DeployError('TLS certificate was not created')
        if material.private_key and not material.private_key.is_file():
            raise DeployError('TLS private key was not created')
