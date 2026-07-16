from __future__ import annotations

import ipaddress
import urllib.error
import urllib.request

from vpsdeploy.core.runtime import DeployError, DeploymentContext, Task, section
from vpsdeploy.providers.dns.base import DNSRecordSpec
from vpsdeploy.providers.dns.cloudflare import CloudflareDNSProvider


class DNSRecordsTask(Task):
    name = "dns-records"

    def enabled(self, context: DeploymentContext) -> bool:
        return bool(section(context.config, "dns").get("enabled", False))

    def validate(self, context: DeploymentContext) -> None:
        cfg = section(context.config, "dns")
        if str(cfg.get("provider", "cloudflare")) != "cloudflare":
            raise DeployError("dns.provider currently supports only cloudflare")
        ttl = int(cfg.get("ttl", 1))
        if ttl != 1 and not 60 <= ttl <= 86400:
            raise DeployError("dns.ttl must be 1 (automatic) or between 60 and 86400")
        self._provider(context).validate(context)
        context.state["dns_records"] = self._records(context)

    def apply(self, context: DeploymentContext) -> None:
        self._provider(context).reconcile(context, context.state["dns_records"])

    def verify(self, context: DeploymentContext) -> None:
        self._provider(context).verify(context, context.state["dns_records"])

    @staticmethod
    def _provider(context: DeploymentContext) -> CloudflareDNSProvider:
        provider = context.state.get("dns_provider")
        if provider is None:
            provider = CloudflareDNSProvider()
            context.state["dns_provider"] = provider
        return provider

    def _records(self, context: DeploymentContext) -> list[DNSRecordSpec]:
        cfg = section(context.config, "dns")
        domains = section(context.config, "domains")
        ttl = int(cfg.get("ttl", 1))
        ipv4 = self._address(cfg, 4)
        ipv6 = self._address(cfg, 6)
        records: list[DNSRecordSpec] = []
        panel_domain = str(domains["panel"])
        subscription_domain = str(domains.get("subscription", panel_domain)).strip() or panel_domain
        targets: list[tuple[str, str, dict]] = [
            ("panel", panel_domain, section(context.config, "dns.panel")),
            ("subscription", subscription_domain, section(context.config, "dns.subscription")),
            ("node", str(domains["node"]), section(context.config, "dns.node")),
        ]
        sub2api = context.config.get('sub2api', {})
        dns_sub2api = cfg.get('sub2api', {})
        if isinstance(sub2api, dict) and bool(sub2api.get('enabled', False)):
            if not isinstance(dns_sub2api, dict):
                raise DeployError('dns.sub2api must be a TOML table')
            targets.append(('sub2api', str(sub2api.get('domain', '')), dns_sub2api))

        seen: set[tuple[str, str]] = set()
        for label, hostname, target in targets:
            if not bool(target.get("enabled", True)):
                continue
            if not hostname or '.' not in hostname:
                raise DeployError(f'{label} DNS hostname must be a fully qualified domain name')
            proxied = bool(target.get("proxied", label != "node"))
            if label == "node" and proxied:
                raise DeployError("dns.node.proxied must be false for a Reality node")
            if ipv4 and bool(cfg.get("create_ipv4", True)) and (hostname, "A") not in seen:
                records.append(DNSRecordSpec(hostname, "A", ipv4, proxied, ttl))
                seen.add((hostname, "A"))
            if ipv6 and bool(cfg.get("create_ipv6", True)) and (hostname, "AAAA") not in seen:
                records.append(DNSRecordSpec(hostname, "AAAA", ipv6, proxied, ttl))
                seen.add((hostname, "AAAA"))
        if not records:
            raise DeployError("DNS task produced no records; configure an address or enable auto detection")
        return records

    def _address(self, cfg: dict, version: int) -> str | None:
        configured = str(cfg.get(f"ipv{version}_address", "")).strip()
        if configured:
            return self._validate_address(configured, version)
        if not bool(cfg.get("auto_detect_addresses", True)):
            return None
        url = str(cfg.get(f"ipv{version}_detection_url", f"https://api{version}.ipify.org"))
        try:
            with urllib.request.urlopen(url, timeout=10) as response:
                detected = response.read().decode().strip()
        except (urllib.error.URLError, TimeoutError) as exc:
            if version == 6:
                print(f"[dns] IPv6 detection skipped: {exc}")
                return None
            raise DeployError(f"Unable to detect public IPv{version}: {exc}") from exc
        return self._validate_address(detected, version)

    @staticmethod
    def _validate_address(value: str, version: int) -> str:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise DeployError(f"Invalid IPv{version} address: {value}") from exc
        if address.version != version or not address.is_global:
            raise DeployError(f"Address is not a global IPv{version} address: {value}")
        return str(address)
