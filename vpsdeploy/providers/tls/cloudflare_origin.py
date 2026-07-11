from __future__ import annotations

import json
import os
import shutil
import urllib.error
import urllib.request
from pathlib import Path

from vpsdeploy.core.runtime import DeployError, DeploymentContext, run, section, write_file
from vpsdeploy.providers.tls.base import TLSMaterial


class CloudflareOriginProvider:
    def validate(self, context: DeploymentContext) -> None:
        cfg = section(context.config, 'panel.tls')
        auto = bool(cfg.get('auto_create', False))
        if not auto:
            cert = Path(str(cfg.get('certificate_file', ''))).expanduser()
            key = Path(str(cfg.get('private_key_file', ''))).expanduser()
            if not cert.is_file() or not key.is_file():
                raise DeployError('Origin CA certificate/key files are missing')

    def obtain(self, context: DeploymentContext) -> TLSMaterial:
        cfg = section(context.config, 'panel.tls')
        target_dir = context.stack_dir / 'secrets'
        target_dir.mkdir(parents=True, exist_ok=True)
        cert_target = target_dir / 'cloudflare-origin.crt'
        key_target = target_dir / 'cloudflare-origin.key'

        if cert_target.is_file() and key_target.is_file() and not bool(cfg.get('force_reissue', False)):
            return TLSMaterial('cloudflare_origin', cert_target, key_target)

        if bool(cfg.get('auto_create', False)):
            self._create(context, cert_target, key_target)
        else:
            shutil.copy2(Path(str(cfg['certificate_file'])).expanduser(), cert_target)
            shutil.copy2(Path(str(cfg['private_key_file'])).expanduser(), key_target)
            cert_target.chmod(0o644)
            key_target.chmod(0o600)
        return TLSMaterial('cloudflare_origin', cert_target, key_target)

    def _create(self, context: DeploymentContext, cert: Path, key: Path) -> None:
        cfg = section(context.config, 'panel.tls')
        token = os.environ.get('CLOUDFLARE_ORIGIN_CA_TOKEN', '').strip() or str(cfg.get('api_token', '')).strip()
        if not token:
            raise DeployError('Set CLOUDFLARE_ORIGIN_CA_TOKEN for automatic Origin CA creation')
        hostname = str(section(context.config, 'domains')['panel'])
        csr = cert.with_suffix('.csr')
        run(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(csr), '-subj', f'/CN={hostname}'])
        payload = json.dumps({
            'hostnames': [hostname],
            'requested_validity': int(cfg.get('validity_days', 5475)),
            'request_type': 'origin-rsa',
            'csr': csr.read_text(encoding='utf-8'),
        }).encode()
        request = urllib.request.Request(
            'https://api.cloudflare.com/client/v4/certificates', data=payload, method='POST',
            headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'},
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                body = json.loads(response.read().decode())
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise DeployError(f'Cloudflare Origin CA request failed: {exc}') from exc
        if not body.get('success') or not body.get('result', {}).get('certificate'):
            raise DeployError(f"Cloudflare Origin CA error: {body.get('errors', body)}")
        write_file(cert, body['result']['certificate'], 0o644)
        key.chmod(0o600)
        csr.unlink(missing_ok=True)
