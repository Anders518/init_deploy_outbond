from __future__ import annotations

from pathlib import Path

from vpsdeploy.core.runtime import DeploymentContext, Task, run, section, write_file


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
        write_file(Path('/etc/sysctl.d/99-vps-hardening.conf'), '\n'.join(values), 0o644)
        run(['sysctl', '--system'])
