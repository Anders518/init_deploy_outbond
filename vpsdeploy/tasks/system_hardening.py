from __future__ import annotations

from pathlib import Path

from vpsdeploy.core.runtime import DeployError, DeploymentContext, FileSnapshot, Task, run, section, write_file


class SystemHardeningTask(Task):
    name = 'system-hardening'

    def enabled(self, context: DeploymentContext) -> bool:
        return bool(section(context.config, 'hardening').get('enabled'))

    def apply(self, context: DeploymentContext) -> None:
        cfg = section(context.config, 'hardening.system')
        if cfg.get('disable_apport'):
            run(['systemctl', 'disable', '--now', 'apport.service', 'apport-autoreport.path'], check=False)
        if not cfg.get('enable_sysctl'):
            return
        values = [
            'net.ipv4.conf.all.accept_source_route = 0',
            'net.ipv4.conf.default.accept_source_route = 0',
            'net.ipv6.conf.all.accept_source_route = 0',
            'net.ipv6.conf.default.accept_source_route = 0',
            'net.ipv4.tcp_syncookies = 1',
            'kernel.kptr_restrict = 2',
            'kernel.dmesg_restrict = 1',
            'kernel.unprivileged_bpf_disabled = 1',
            'fs.protected_hardlinks = 1',
            'fs.protected_symlinks = 1',
        ]
        if cfg.get('disable_redirects'):
            values += [
                'net.ipv4.conf.all.accept_redirects = 0',
                'net.ipv4.conf.default.accept_redirects = 0',
                'net.ipv6.conf.all.accept_redirects = 0',
                'net.ipv6.conf.default.accept_redirects = 0',
                'net.ipv4.conf.all.send_redirects = 0',
                'net.ipv4.conf.default.send_redirects = 0',
            ]
        if cfg.get('tcp_mtu_probing', True):
            values.append('net.ipv4.tcp_mtu_probing = 1')
        syn_backlog = int(cfg.get('tcp_max_syn_backlog', 1024))
        values.append(f'net.ipv4.tcp_max_syn_backlog = {syn_backlog}')
        write_file(Path('/etc/sysctl.d/99-vps-hardening.conf'), '\n'.join(values), 0o644)
        run(['sysctl', '--system'])

    def prepare_rollback(self, context: DeploymentContext) -> dict:
        keys = [
            'net.ipv4.conf.all.accept_source_route', 'net.ipv4.conf.default.accept_source_route',
            'net.ipv6.conf.all.accept_source_route', 'net.ipv6.conf.default.accept_source_route',
            'net.ipv4.tcp_syncookies', 'kernel.kptr_restrict', 'kernel.dmesg_restrict',
            'kernel.unprivileged_bpf_disabled', 'fs.protected_hardlinks', 'fs.protected_symlinks',
            'net.ipv4.conf.all.accept_redirects', 'net.ipv4.conf.default.accept_redirects',
            'net.ipv6.conf.all.accept_redirects', 'net.ipv6.conf.default.accept_redirects',
            'net.ipv4.conf.all.send_redirects', 'net.ipv4.conf.default.send_redirects',
            'net.ipv4.tcp_mtu_probing', 'net.ipv4.tcp_max_syn_backlog',
        ]
        values: dict[str, str] = {}
        for key in keys:
            result = run(['sysctl', '-n', key], check=False, capture=True)
            if result.returncode == 0:
                values[key] = result.stdout.strip()
        apport = {
            unit: run(['systemctl', 'is-active', '--quiet', unit], check=False).returncode == 0
            for unit in ('apport.service', 'apport-autoreport.path')
        }
        return {'file': FileSnapshot.capture(Path('/etc/sysctl.d/99-vps-hardening.conf')),
                'values': values, 'apport': apport}

    def validate(self, context: DeploymentContext) -> None:
        cfg = section(context.config, 'hardening.system')
        backlog = cfg.get('tcp_max_syn_backlog', 1024)
        if not isinstance(backlog, int) or not 128 <= backlog <= 65535:
            raise DeployError('hardening.system.tcp_max_syn_backlog must be between 128 and 65535')

    def verify(self, context: DeploymentContext) -> None:
        cfg = section(context.config, 'hardening.system')
        if not cfg.get('enable_sysctl'):
            return
        expected = {'net.ipv4.tcp_max_syn_backlog': str(int(cfg.get('tcp_max_syn_backlog', 1024)))}
        if cfg.get('tcp_mtu_probing', True):
            expected['net.ipv4.tcp_mtu_probing'] = '1'
        for key, value in expected.items():
            actual = run(['sysctl', '-n', key], capture=True).stdout.strip()
            if actual != value:
                raise DeployError(f'{key} is {actual}, expected {value}')

    def rollback(self, context: DeploymentContext, snapshot: dict) -> None:
        snapshot['file'].restore()
        for key, value in snapshot['values'].items():
            run(['sysctl', '-w', f'{key}={value}'])
        for unit, active in snapshot['apport'].items():
            run(['systemctl', 'start' if active else 'stop', unit], check=False)
