from __future__ import annotations

import ipaddress
import json
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vpsdeploy.core.runtime import DeployError, DeploymentContext, Task, run, section, write_file


@dataclass
class FileSnapshot:
    path: Path
    existed: bool
    content: bytes = b''
    mode: int = 0o600

    @classmethod
    def capture(cls, path: Path) -> 'FileSnapshot':
        if not path.exists():
            return cls(path, False)
        return cls(path, True, path.read_bytes(), path.stat().st_mode & 0o777)

    def restore(self) -> None:
        if self.existed:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_name(f'.{self.path.name}.ipv6-rollback')
            temporary.write_bytes(self.content)
            temporary.chmod(self.mode)
            temporary.replace(self.path)
        else:
            self.path.unlink(missing_ok=True)


def _ipv6_config(context: DeploymentContext) -> dict[str, Any]:
    value = context.config.get('ipv6', {})
    if not isinstance(value, dict):
        raise DeployError('ipv6 must be a TOML table')
    return value


class IPv6ConnectivityTask(Task):
    name = 'ipv6-connectivity'

    def enabled(self, context: DeploymentContext) -> bool:
        return bool(_ipv6_config(context).get('enabled', True))

    def validate(self, context: DeploymentContext) -> None:
        cfg = _ipv6_config(context)
        if not bool(cfg.get('rollback_on_failure', True)):
            raise DeployError('ipv6.rollback_on_failure must remain true for automatic repair')
        timeout = int(cfg.get('timeout', 15))
        if not 3 <= timeout <= 120:
            raise DeployError('ipv6.timeout must be between 3 and 120 seconds')

    def apply(self, context: DeploymentContext) -> None:
        cfg = _ipv6_config(context)
        stack = context.stack_dir
        (stack / 'state').mkdir(parents=True, exist_ok=True)
        report_path = stack / 'state/ipv6.json'
        detected = self._global_address()
        if detected is None:
            report = {'ready': False, 'repaired': False, 'reason': 'no_global_ipv6', 'checked_at': int(time.time())}
            context.state['ipv6_ready'] = False
            write_file(report_path, json.dumps(report, indent=2), 0o600)
            print('[ipv6] no global host IPv6 address; using IPv4-only DNS')
            return

        address, interface = detected
        if self._host_probe(cfg) and self._docker_probe(context, cfg):
            sysctl_path = Path(str(cfg.get('sysctl_file', '/etc/sysctl.d/90-vpsdeploy-ipv6.conf')))
            snapshot = FileSnapshot.capture(sysctl_path)
            runtime = self._runtime_values(interface)
            try:
                self._write_sysctl(sysctl_path, interface)
                run(['sysctl', '--load', str(sysctl_path)])
                self._wait_default_route(int(cfg.get('route_wait_seconds', 20)))
                if not self._host_probe(cfg) or not self._docker_probe(context, cfg):
                    raise DeployError('IPv6 probe failed after loading persistent sysctl settings')
            except Exception as exc:
                rollback_error = self._rollback([snapshot], runtime, interface, False)
                if rollback_error:
                    raise DeployError(f'IPv6 persistence failed and rollback also failed: {rollback_error}') from exc
                self._fallback(context, address, interface, f'persistence_failed: {type(exc).__name__}')
                return
            report = {'ready': True, 'repaired': False, 'persistent': True, 'address': address,
                      'interface': interface, 'checked_at': int(time.time())}
            context.state.update({'ipv6_ready': True, 'ipv6_address': address})
            write_file(report_path, json.dumps(report, indent=2), 0o600)
            print(f'[ipv6] host, Docker and persistent RA settings verified: {address}')
            return

        if not bool(cfg.get('auto_repair', True)):
            self._fallback(context, address, interface, 'probe_failed_auto_repair_disabled')
            return

        sysctl_path = Path(str(cfg.get('sysctl_file', '/etc/sysctl.d/90-vpsdeploy-ipv6.conf')))
        daemon_path = Path('/etc/docker/daemon.json')
        snapshots = [FileSnapshot.capture(sysctl_path), FileSnapshot.capture(daemon_path)]
        runtime = self._runtime_values(interface)
        docker_changed = False
        try:
            self._write_sysctl(sysctl_path, interface)
            run(['sysctl', '--load', str(sysctl_path)])
            self._wait_default_route(int(cfg.get('route_wait_seconds', 20)))
            if not self._host_probe(cfg):
                raise DeployError('host IPv6 HTTPS probe still fails after RA repair')
            if not self._docker_probe(context, cfg):
                docker_changed = self._enable_docker_ipv6(context, daemon_path)
                if docker_changed:
                    run(['systemctl', 'restart', 'docker'])
                if not self._docker_probe(context, cfg):
                    raise DeployError('Docker IPv6 HTTPS probe still fails after daemon repair')
            report = {'ready': True, 'repaired': True, 'address': address,
                      'interface': interface, 'checked_at': int(time.time())}
            context.state.update({'ipv6_ready': True, 'ipv6_address': address})
            write_file(report_path, json.dumps(report, indent=2), 0o600)
            print(f'[ipv6] repair committed after host and Docker validation: {address}')
        except Exception as exc:
            rollback_error = self._rollback(snapshots, runtime, interface, docker_changed)
            if rollback_error:
                raise DeployError(f'IPv6 repair failed and rollback also failed: {rollback_error}') from exc
            self._fallback(context, address, interface, f'repair_failed: {type(exc).__name__}')

    def verify(self, context: DeploymentContext) -> None:
        path = context.stack_dir / 'state/ipv6.json'
        if not path.is_file() or path.stat().st_mode & 0o077:
            raise DeployError('IPv6 state report is missing or has unsafe permissions')
        if context.state.get('ipv6_ready'):
            cfg = _ipv6_config(context)
            if not self._host_probe(cfg):
                raise DeployError('IPv6 became unavailable immediately after commit')

    @staticmethod
    def _global_address() -> tuple[str, str] | None:
        result = run(['ip', '-j', '-6', 'address', 'show', 'scope', 'global'], capture=True)
        try:
            rows = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise DeployError('Unable to parse host IPv6 addresses') from exc
        candidates: list[tuple[str, str, bool]] = []
        for row in rows:
            interface = str(row.get('ifname', ''))
            for info in row.get('addr_info', []):
                value = str(info.get('local', ''))
                try:
                    address = ipaddress.ip_address(value)
                except ValueError:
                    continue
                if address.version == 6 and address.is_global:
                    candidates.append((str(address), interface, bool(info.get('temporary', False))))
        if not candidates:
            return None
        address, interface, _ = sorted(candidates, key=lambda item: item[2])[0]
        return address, interface

    @staticmethod
    def _host_probe(cfg: dict[str, Any]) -> bool:
        result = run([
            'curl', '-6', '--silent', '--show-error', '--max-time', str(int(cfg.get('timeout', 15))),
            str(cfg.get('test_url', 'https://api6.ipify.org')),
        ], check=False, capture=True)
        if result.returncode != 0:
            return False
        try:
            return ipaddress.ip_address(result.stdout.strip()).version == 6
        except ValueError:
            return False

    def _docker_probe(self, context: DeploymentContext, cfg: dict[str, Any]) -> bool:
        network = 'vpsdeploy-ipv6-check'
        container = 'vpsdeploy-ipv6-check'
        subnet = str(cfg.get('test_subnet', 'fd42:6d6f:6465::/64'))
        image = str(cfg.get('test_image', 'curlimages/curl:8.16.0'))
        run(['docker', 'rm', '-f', container], check=False, capture=True)
        run(['docker', 'network', 'rm', network], check=False, capture=True)
        try:
            created = run(
                ['docker', 'network', 'create', '--ipv6', '--subnet', subnet, network],
                check=False, capture=True,
            )
            if created.returncode != 0:
                return False
            result = run([
                'docker', 'run', '--rm', '--name', container, '--network', network,
                image, '-6', '--silent', '--show-error', '--max-time',
                str(int(cfg.get('timeout', 15))), str(cfg.get('test_url', 'https://api6.ipify.org')),
            ], check=False, capture=True)
            if result.returncode != 0:
                return False
            try:
                return ipaddress.ip_address(result.stdout.strip()).version == 6
            except ValueError:
                return False
        finally:
            run(['docker', 'rm', '-f', container], check=False, capture=True)
            run(['docker', 'network', 'rm', network], check=False, capture=True)

    @staticmethod
    def _runtime_values(interface: str) -> dict[str, str]:
        keys = [
            'net.ipv6.conf.all.disable_ipv6', 'net.ipv6.conf.default.disable_ipv6',
            'net.ipv6.conf.all.forwarding', f'net.ipv6.conf.{interface}.accept_ra',
        ]
        values: dict[str, str] = {}
        for key in keys:
            result = run(['sysctl', '-n', key], check=False, capture=True)
            if result.returncode == 0:
                values[key] = result.stdout.strip()
        return values

    @staticmethod
    def _write_sysctl(path: Path, interface: str) -> None:
        write_file(path, '\n'.join([
            'net.ipv6.conf.all.disable_ipv6 = 0',
            'net.ipv6.conf.default.disable_ipv6 = 0',
            'net.ipv6.conf.all.forwarding = 1',
            f'net.ipv6.conf.{interface}.accept_ra = 2',
        ]), 0o644)

    @staticmethod
    def _wait_default_route(timeout: int) -> None:
        for _ in range(max(timeout, 1)):
            result = run(['ip', '-6', 'route', 'show', 'default'], check=False, capture=True)
            if result.stdout.strip():
                return
            time.sleep(1)
        raise DeployError('IPv6 default route did not return after enabling RA acceptance')

    @staticmethod
    def _enable_docker_ipv6(context: DeploymentContext, path: Path) -> bool:
        data: dict[str, Any] = {}
        if path.is_file() and path.read_text(encoding='utf-8').strip():
            try:
                loaded = json.loads(path.read_text(encoding='utf-8'))
            except json.JSONDecodeError as exc:
                raise DeployError(f'Cannot safely merge invalid Docker daemon JSON: {path}') from exc
            if not isinstance(loaded, dict):
                raise DeployError(f'Docker daemon configuration must be a JSON object: {path}')
            data = loaded
        desired_subnet = str(section(context.config, 'docker').get('ipv6_subnet', '')).strip() or 'fd42:646f:636b::/64'
        changed = (
            data.get('ipv6') is not True
            or data.get('ip6tables') is not True
            or data.get('fixed-cidr-v6') != desired_subnet
        )
        data['ipv6'] = True
        data['ip6tables'] = True
        data['fixed-cidr-v6'] = desired_subnet
        write_file(path, json.dumps(data, indent=2), 0o644)
        run(['dockerd', '--validate', '--config-file', str(path)])
        return changed

    @staticmethod
    def _rollback(snapshots: list[FileSnapshot], runtime: dict[str, str],
                  interface: str, docker_changed: bool) -> str:
        try:
            for snapshot in snapshots:
                snapshot.restore()
            for key, value in runtime.items():
                run(['sysctl', '-w', f'{key}={value}'])
            if docker_changed:
                run(['systemctl', 'restart', 'docker'])
            return ''
        except Exception as exc:  # rollback errors must be surfaced, not hidden by fallback
            return f'{type(exc).__name__}: {exc}'

    def _fallback(self, context: DeploymentContext, address: str, interface: str, reason: str) -> None:
        report = {'ready': False, 'repaired': False, 'rolled_back': True, 'address': address,
                  'interface': interface, 'reason': reason, 'checked_at': int(time.time())}
        context.state['ipv6_ready'] = False
        write_file(context.stack_dir / 'state/ipv6.json', json.dumps(report, indent=2), 0o600)
        print(f'[ipv6] repair unavailable; rollback complete, continuing IPv4-only ({reason})')
