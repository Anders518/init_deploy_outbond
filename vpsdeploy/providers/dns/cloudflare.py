from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from vpsdeploy.core.runtime import DeployError, DeploymentContext, read_secret_file, section
from vpsdeploy.providers.dns.base import DNSRecordSpec


class CloudflareDNSProvider:
    api_base = "https://api.cloudflare.com/client/v4"

    def validate(self, context: DeploymentContext) -> None:
        self._token(context)

    def reconcile(self, context: DeploymentContext, records: list[DNSRecordSpec]) -> None:
        token = self._token(context)
        zones = self._list_zones(token)
        for record in records:
            zone = self._find_zone(record.name, zones)
            self._upsert(token, zone["id"], record)

    def verify(self, context: DeploymentContext, records: list[DNSRecordSpec]) -> None:
        token = self._token(context)
        zones = self._list_zones(token)
        for expected in records:
            zone = self._find_zone(expected.name, zones)
            existing = self._list_records(token, zone["id"], expected.name, expected.record_type)
            if len(existing) != 1:
                raise DeployError(
                    f"Expected exactly one {expected.record_type} record for {expected.name}, found {len(existing)}"
                )
            actual = existing[0]
            if str(actual.get("content")) != expected.content:
                raise DeployError(f"DNS verification failed for {expected.name}: unexpected content")
            if bool(actual.get("proxied", False)) != expected.proxied:
                raise DeployError(f"DNS verification failed for {expected.name}: unexpected proxy state")

    def delete_managed_records(self, context: DeploymentContext, names: list[str], record_type: str) -> None:
        token = self._token(context)
        zones = self._list_zones(token)
        for name in names:
            zone = self._find_zone(name, zones)
            records = self._list_records(token, zone['id'], name, record_type)
            for record in records:
                if str(record.get('comment', '')) != 'Managed by init_deploy_outbond':
                    print(f'[dns] preserving unmanaged {record_type} record for {name}')
                    continue
                self._request(token, 'DELETE', f"/zones/{zone['id']}/dns_records/{record['id']}")
                print(f'[dns] removed managed {record_type} {name} during fallback')

    def _token(self, context: DeploymentContext) -> str:
        cfg = section(context.config, "dns")
        token = os.environ.get("CLOUDFLARE_DNS_API_TOKEN", "").strip()
        token = token or str(cfg.get("api_token", "")).strip()
        token = token or read_secret_file(cfg.get("api_token_file", ""), "Cloudflare DNS token")
        if not token:
            cloudflare = section(context.config, "cloudflare")
            token = str(cloudflare.get("api_token", "")).strip()
            token = token or read_secret_file(cloudflare.get("api_token_file", ""), "Cloudflare API token")
        if not token:
            raise DeployError("Set CLOUDFLARE_DNS_API_TOKEN, dns.api_token_file, or cloudflare.api_token_file")
        return token

    def _request(
        self,
        token: str,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        query: dict[str, str | int] | None = None,
    ) -> dict[str, Any]:
        url = self.api_base + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        data = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                body = json.loads(response.read().decode())
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode(errors="replace")
            try:
                detail = json.loads(raw).get("errors", raw)
            except json.JSONDecodeError:
                detail = raw
            raise DeployError(f"Cloudflare DNS HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise DeployError(f"Cloudflare DNS request failed: {exc}") from exc
        if not body.get("success"):
            raise DeployError(f"Cloudflare DNS API error: {body.get('errors', body)}")
        return body

    def _list_zones(self, token: str) -> list[dict[str, Any]]:
        zones: list[dict[str, Any]] = []
        page = 1
        while True:
            body = self._request(token, "GET", "/zones", query={"page": page, "per_page": 50})
            zones.extend(body.get("result", []))
            info = body.get("result_info", {})
            if page >= int(info.get("total_pages", 1)):
                break
            page += 1
        if not zones:
            raise DeployError("The DNS token cannot access any Cloudflare zones")
        return zones

    @staticmethod
    def _find_zone(hostname: str, zones: list[dict[str, Any]]) -> dict[str, Any]:
        matches = [z for z in zones if hostname == z.get("name") or hostname.endswith("." + str(z.get("name")))]
        if not matches:
            raise DeployError(f"No accessible Cloudflare zone contains hostname {hostname}")
        return max(matches, key=lambda item: len(str(item.get("name", ""))))

    def _list_records(self, token: str, zone_id: str, name: str, record_type: str) -> list[dict[str, Any]]:
        body = self._request(
            token,
            "GET",
            f"/zones/{zone_id}/dns_records",
            query={"name": name, "type": record_type, "per_page": 100},
        )
        return list(body.get("result", []))

    def _upsert(self, token: str, zone_id: str, spec: DNSRecordSpec) -> None:
        existing = self._list_records(token, zone_id, spec.name, spec.record_type)
        if len(existing) > 1:
            raise DeployError(f"Refusing to modify duplicate {spec.record_type} records for {spec.name}")
        payload = {
            "type": spec.record_type,
            "name": spec.name,
            "content": spec.content,
            "ttl": spec.ttl,
            "proxied": spec.proxied,
            "comment": "Managed by init_deploy_outbond",
        }
        if not existing:
            self._request(token, "POST", f"/zones/{zone_id}/dns_records", payload)
            print(f"[dns] created {spec.record_type} {spec.name} -> {spec.content}")
            return
        current = existing[0]
        unchanged = (
            str(current.get("content")) == spec.content
            and bool(current.get("proxied", False)) == spec.proxied
            and int(current.get("ttl", 1)) == spec.ttl
        )
        if unchanged:
            print(f"[dns] unchanged {spec.record_type} {spec.name}")
            return
        self._request(token, "PATCH", f"/zones/{zone_id}/dns_records/{current['id']}", payload)
        print(f"[dns] updated {spec.record_type} {spec.name} -> {spec.content}")
