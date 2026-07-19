from __future__ import annotations

import curses
import getpass
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable

from vpsdeploy.core.runtime import DeployError


_SECTION = re.compile(r'^\s*\[([^]]+)]\s*(?:#.*)?$')


def set_toml_value(text: str, section: str, key: str, value: object) -> str:
    """Replace or add one scalar TOML value without reformatting the user's file."""
    rendered = json.dumps(value, ensure_ascii=False) if isinstance(value, str) else str(value).lower()
    lines = text.splitlines()
    start: int | None = None
    end = len(lines)
    for index, line in enumerate(lines):
        match = _SECTION.match(line)
        if not match:
            continue
        if start is not None:
            end = index
            break
        if match.group(1).strip() == section:
            start = index + 1
    assignment = f'{key} = {rendered}'
    if start is None:
        suffix = '' if not lines or lines[-1] == '' else '\n'
        return '\n'.join(lines) + suffix + f'[{section}]\n{assignment}\n'
    pattern = re.compile(rf'^(\s*){re.escape(key)}\s*=')
    for index in range(start, end):
        match = pattern.match(lines[index])
        if match:
            comment = ''
            # Preserve a simple trailing comment without attempting to parse quoted #.
            if ' #' in lines[index]:
                comment = ' #' + lines[index].split(' #', 1)[1]
            lines[index] = match.group(1) + assignment + comment
            return '\n'.join(lines) + '\n'
    lines.insert(end, assignment)
    return '\n'.join(lines) + '\n'


def apply_core_config(text: str, values: dict[str, object]) -> str:
    mapping = {
        'panel_domain': ('domains', 'panel'),
        'subscription_domain': ('domains', 'subscription'),
        'node_domain': ('domains', 'node'),
        'acme_email': ('domains', 'acme_email'),
        'backend': ('panel', 'backend'),
        'tls_mode': ('panel.tls', 'mode'),
        'panel_public_port': ('ports', 'panel_public'),
        'client_name': ('node', 'client_name'),
    }
    for name, (section, key) in mapping.items():
        if name in values:
            text = set_toml_value(text, section, key, values[name])
    return text


def apply_sub2api_config(text: str, values: dict[str, object]) -> str:
    for key in ('enabled', 'domain', 'admin_email'):
        if key in values:
            text = set_toml_value(text, 'sub2api', key, values[key])
    if values.get('enabled'):
        text = set_toml_value(text, 'sub2api', 'admin_password_mode', 'generate')
    return text


def apply_hardening_config(text: str, values: dict[str, object]) -> str:
    mapping = {
        'enabled': ('hardening', 'enabled'),
        'ssh_enabled': ('hardening.ssh', 'enabled'),
        'ssh_current_port': ('hardening.ssh', 'current_port'),
        'ssh_new_port': ('hardening.ssh', 'new_port'),
        'ssh_keep_current_port': ('hardening.ssh', 'keep_current_port'),
        'ssh_disable_root_login': ('hardening.ssh', 'disable_root_login'),
        'ssh_disable_password_auth': ('hardening.ssh', 'disable_password_auth'),
        'ufw_enabled': ('hardening.ufw', 'enabled'),
        'fail2ban_enabled': ('hardening.fail2ban', 'enabled'),
        'unattended_upgrades_enabled': ('hardening.unattended_upgrades', 'enabled'),
        'automatic_reboot': ('hardening.unattended_upgrades', 'automatic_reboot'),
        'system_sysctl_enabled': ('hardening.system', 'enable_sysctl'),
        'disable_apport': ('hardening.system', 'disable_apport'),
    }
    for name, (section, key) in mapping.items():
        if name in values:
            text = set_toml_value(text, section, key, values[name])
    return text


def apply_wg_easy_config(text: str, values: dict[str, object]) -> str:
    for key in ('enabled', 'web_port', 'wireguard_port', 'admin_username', 'ipv4_cidr', 'ipv6_cidr'):
        if key in values:
            text = set_toml_value(text, 'wg_easy', key, values[key])
    if values.get('enabled'):
        text = set_toml_value(text, 'wg_easy', 'admin_password_mode', 'generate')
    return text


def _atomic_write(path: Path, text: str) -> None:
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o600
    temporary = path.with_name(f'.{path.name}.tui.tmp')
    temporary.write_text(text, encoding='utf-8')
    temporary.chmod(min(mode, 0o600))
    os.replace(temporary, path)


class DeploymentTUI:
    def __init__(self, screen: curses.window, config_path: Path):
        self.screen = screen
        self.config_path = config_path.resolve()
        self.message = '使用 ↑/↓ 选择，Enter 确认，q 退出'

    def run(self) -> None:
        curses.curs_set(0)
        self.screen.keypad(True)
        while True:
            backend = self._backend()
            options: list[tuple[str, Callable[[], None] | None]] = [
                ('交互式生成/更新核心配置', self._configure_core),
                ('完整部署并自动验收', self._full_deploy),
                (f'切换节点协议（当前：{self._protocol_name(backend)}）', self._switch_backend),
                ('修改网关与面板账号密码', self._change_credentials),
                ('轮换当前节点客户端凭据', self._rotate_node),
                ('运行 Mihomo + sing-box 验收', self._verify_node),
                ('检测/修复 IPv6（失败自动回退）', self._repair_ipv6),
                ('配置并部署系统加固（失败自动回退）', self._configure_hardening),
                ('配置并部署 wg-easy（仅经代理可达）', self._configure_wg_easy),
                ('配置并部署 Sub2API', self._configure_sub2api),
                ('查看服务状态', self._status),
                ('显示当前凭据（敏感）', self._credentials),
                ('退出', None),
            ]
            selected = self._menu('init_deploy_outbond', [label for label, _ in options])
            if selected is None or options[selected][1] is None:
                return
            options[selected][1]()

    def _backend(self) -> str:
        import tomllib
        with self.config_path.open('rb') as handle:
            config = tomllib.load(handle)
        return str(config.get('panel', {}).get('backend', '3x-ui')).strip().lower()

    @staticmethod
    def _protocol_name(backend: str) -> str:
        return 'AnyTLS / S-UI' if backend == 's-ui' else 'VLESS Reality / 3x-ui'

    def _menu(self, title: str, entries: list[str]) -> int | None:
        position = 0
        while True:
            self.screen.erase()
            height, width = self.screen.getmaxyx()
            self._add(1, 2, title, curses.A_BOLD)
            self._add(3, 2, f'配置：{self.config_path}')
            for index, entry in enumerate(entries):
                marker = '› ' if index == position else '  '
                attr = curses.A_REVERSE if index == position else curses.A_NORMAL
                self._add(5 + index, 4, marker + entry, attr)
            self._add(min(height - 2, 6 + len(entries)), 2, self.message[:max(width - 4, 1)], curses.A_DIM)
            self.screen.refresh()
            key = self.screen.getch()
            if key in (ord('q'), 27):
                return None
            if key in (curses.KEY_UP, ord('k')):
                position = (position - 1) % len(entries)
            elif key in (curses.KEY_DOWN, ord('j')):
                position = (position + 1) % len(entries)
            elif key in (curses.KEY_ENTER, 10, 13):
                return position

    def _add(self, y: int, x: int, value: str, attr: int = curses.A_NORMAL) -> None:
        height, width = self.screen.getmaxyx()
        if 0 <= y < height and x < width:
            try:
                self.screen.addstr(y, x, value[:max(width - x - 1, 0)], attr)
            except curses.error:
                pass

    def _shell(self, args: list[str], *, env: dict[str, str] | None = None,
               config_text: str | None = None) -> int:
        temporary_name = ''
        command = [sys.executable, str(Path(__file__).resolve().parents[1] / 'deploy.py')]
        if config_text is not None:
            handle = tempfile.NamedTemporaryFile(
                mode='w', encoding='utf-8', prefix='vpsdeploy-tui-', suffix='.toml', delete=False,
            )
            try:
                handle.write(config_text)
                handle.close()
                os.chmod(handle.name, 0o600)
                temporary_name = handle.name
                command.extend(['--config', temporary_name])
            except Exception:
                Path(handle.name).unlink(missing_ok=True)
                raise
        else:
            command.extend(['--config', str(self.config_path)])
        command.extend(args)
        curses.endwin()
        try:
            result = subprocess.run(command, env={**os.environ, **(env or {})})
            input('\n按 Enter 返回菜单…')
            return result.returncode
        finally:
            if temporary_name:
                Path(temporary_name).unlink(missing_ok=True)
            self.screen.refresh()

    def _full_deploy(self) -> None:
        code = self._shell(['deploy'])
        self.message = '完整部署成功' if code == 0 else f'完整部署失败，退出码 {code}'

    def _load_config(self) -> dict:
        import tomllib
        with self.config_path.open('rb') as handle:
            return tomllib.load(handle)

    @staticmethod
    def _ask(prompt: str, current: object) -> str:
        value = input(f'{prompt} [{current}]: ').strip()
        return value or str(current)

    def _configure_core(self) -> None:
        config = self._load_config()
        domains, panel = config.get('domains', {}), config.get('panel', {})
        ports, node = config.get('ports', {}), config.get('node', {})
        tls = panel.get('tls', {})
        curses.endwin()
        try:
            values: dict[str, object] = {
                'panel_domain': self._ask('面板域名', domains.get('panel', 'panel.example.net')),
                'subscription_domain': self._ask('订阅域名', domains.get('subscription', 'sub.example.net')),
                'node_domain': self._ask('节点域名', domains.get('node', 'node.example.net')),
                'acme_email': self._ask('ACME 邮箱', domains.get('acme_email', 'admin@example.net')),
                'client_name': self._ask('节点显示名称', node.get('client_name', 'primary')),
            }
            backend = self._ask('面板后端（3x-ui/s-ui）', panel.get('backend', '3x-ui')).lower()
            tls_mode = self._ask('TLS 模式（acme_dns/cloudflare_origin）', tls.get('mode', 'acme_dns')).lower()
            port_text = self._ask('面板公网 HTTPS 端口', ports.get('panel_public', 8443))
            if backend not in {'3x-ui', 's-ui'} or tls_mode not in {'acme_dns', 'cloudflare_origin'}:
                raise ValueError('面板后端或 TLS 模式无效')
            values.update(backend=backend, tls_mode=tls_mode, panel_public_port=int(port_text))
            changed = apply_core_config(self.config_path.read_text(encoding='utf-8'), values)
            code = self._shell(['deploy'], config_text=changed)
            if code == 0:
                _atomic_write(self.config_path, changed)
                self.message = '核心配置已生成并完成部署验收'
            else:
                self.message = '核心配置部署失败，主配置未修改'
        except (ValueError, OSError) as exc:
            input(f'配置无效：{exc}。按 Enter 返回…')
            self.message = '核心配置未修改'
        finally:
            self.screen.refresh()

    def _configure_sub2api(self) -> None:
        config = self._load_config()
        current = config.get('sub2api', {})
        curses.endwin()
        try:
            enabled_text = self._ask('启用 Sub2API（yes/no）', 'yes' if current.get('enabled') else 'no').lower()
            enabled = enabled_text in {'y', 'yes', '1', 'true', '是'}
            if not enabled:
                self.message = '已取消 Sub2API 配置；停用不会自动删除现有服务或数据'
                return
            domain = self._ask('Sub2API 域名', current.get('domain', 'api.example.net'))
            email = self._ask('Sub2API 管理员邮箱', current.get('admin_email', 'admin@example.net'))
            password = getpass.getpass('初始管理员密码（留空则安全生成）: ')
            if password and password != getpass.getpass('确认初始管理员密码: '):
                input('密码不一致。按 Enter 返回…')
                return
            changed = apply_sub2api_config(self.config_path.read_text(encoding='utf-8'), {
                'enabled': True, 'domain': domain, 'admin_email': email,
            })
            env: dict[str, str] = {}
            if password:
                temporary = set_toml_value(changed, 'sub2api', 'admin_password_mode', 'environment')
                env['VPSDEPLOY_SUB2API_ADMIN_PASSWORD'] = password
            else:
                temporary = changed
            code = self._shell([
                'deploy', '--task', 'dns-records', '--task', 'certificate',
                '--task', 'proxy-stack', '--task', 'sub2api',
            ], env=env, config_text=temporary)
            if code == 0:
                _atomic_write(self.config_path, changed)
                self.message = 'Sub2API 已配置、部署并通过健康检查'
            else:
                self.message = 'Sub2API 部署失败，主配置未修改'
        finally:
            self.screen.refresh()

    @staticmethod
    def _parse_bool(value: str, name: str) -> bool:
        normalized = value.strip().lower()
        if normalized in {'y', 'yes', '1', 'true', 'on', '是'}:
            return True
        if normalized in {'n', 'no', '0', 'false', 'off', '否'}:
            return False
        raise ValueError(f'{name} 必须为 yes 或 no')

    def _ask_bool(self, prompt: str, current: object) -> bool:
        default = 'yes' if bool(current) else 'no'
        return self._parse_bool(self._ask(f'{prompt}（yes/no）', default), prompt)

    def _configure_hardening(self) -> None:
        config = self._load_config()
        hardening = config.get('hardening', {})
        ssh = hardening.get('ssh', {})
        ufw = hardening.get('ufw', {})
        fail2ban = hardening.get('fail2ban', {})
        upgrades = hardening.get('unattended_upgrades', {})
        system = hardening.get('system', {})
        curses.endwin()
        try:
            enabled = self._ask_bool('启用系统加固总开关', hardening.get('enabled', False))
            values: dict[str, object] = {'enabled': enabled}
            if enabled:
                ssh_enabled = self._ask_bool('启用 SSH 加固', ssh.get('enabled', False))
                values['ssh_enabled'] = ssh_enabled
                if ssh_enabled:
                    current_port = int(self._ask('当前 SSH 端口', ssh.get('current_port', 22)))
                    new_port = int(self._ask('新 SSH 端口', ssh.get('new_port', 4522)))
                    if not (1 <= current_port <= 65535 and 1 <= new_port <= 65535):
                        raise ValueError('SSH 端口必须在 1..65535 之间')
                    values.update(
                        ssh_current_port=current_port,
                        ssh_new_port=new_port,
                        ssh_keep_current_port=self._ask_bool(
                            '迁移期间保留当前 SSH 端口', ssh.get('keep_current_port', True),
                        ),
                        ssh_disable_root_login=self._ask_bool(
                            '禁止 root SSH 登录', ssh.get('disable_root_login', False),
                        ),
                        ssh_disable_password_auth=self._ask_bool(
                            '禁止 SSH 密码认证（仅密钥）', ssh.get('disable_password_auth', True),
                        ),
                    )
                values.update(
                    ufw_enabled=self._ask_bool(
                        '启用 UFW（请先确认云防火墙）', ufw.get('enabled', False),
                    ),
                    fail2ban_enabled=self._ask_bool('启用 Fail2Ban', fail2ban.get('enabled', True)),
                    unattended_upgrades_enabled=self._ask_bool(
                        '启用自动安全更新', upgrades.get('enabled', True),
                    ),
                    automatic_reboot=self._ask_bool(
                        '自动更新后允许自动重启', upgrades.get('automatic_reboot', False),
                    ),
                    system_sysctl_enabled=self._ask_bool(
                        '启用安全 sysctl', system.get('enable_sysctl', True),
                    ),
                    disable_apport=self._ask_bool('禁用 Apport', system.get('disable_apport', True)),
                )
            changed = apply_hardening_config(self.config_path.read_text(encoding='utf-8'), values)
            tasks = ['ssh-hardening', 'ufw', 'fail2ban', 'unattended-upgrades', 'system-hardening']
            args = ['deploy'] + [item for task in tasks for item in ('--task', task)]
            code = self._shell(args, config_text=changed)
            if code == 0:
                _atomic_write(self.config_path, changed)
                self.message = '系统加固配置已保存，部署与验证成功'
            else:
                self.message = '系统加固失败并已尝试回退，主配置未修改'
        except (ValueError, OSError) as exc:
            input(f'配置无效：{exc}。按 Enter 返回…')
            self.message = '系统加固配置未修改'
        finally:
            self.screen.refresh()

    def _configure_wg_easy(self) -> None:
        config = self._load_config()
        current = config.get('wg_easy', {})
        curses.endwin()
        try:
            enabled = self._ask_bool('启用 wg-easy 私有覆盖网络', current.get('enabled', False))
            values: dict[str, object] = {'enabled': enabled}
            if enabled:
                values.update(
                    web_port=int(self._ask('本机 Web UI 端口（仅 127.0.0.1）', current.get('web_port', 51821))),
                    wireguard_port=int(self._ask('私网 WireGuard UDP 端口', current.get('wireguard_port', 51820))),
                    admin_username=self._ask('wg-easy 管理员用户名', current.get('admin_username', 'admin')),
                    ipv4_cidr=self._ask('WireGuard IPv4 网段', current.get('ipv4_cidr', '10.66.66.0/24')),
                    ipv6_cidr=self._ask('WireGuard IPv6 网段', current.get('ipv6_cidr', 'fd42:66:66::/64')),
                )
            changed = apply_wg_easy_config(self.config_path.read_text(encoding='utf-8'), values)
            code = self._shell(['deploy', '--task', 'wg-easy'], config_text=changed)
            if code == 0:
                _atomic_write(self.config_path, changed)
                self.message = 'wg-easy 已部署；UDP 未公开，必须经 AnyTLS 代理访问'
            else:
                self.message = 'wg-easy 部署失败并已尝试回退，主配置未修改'
        except (ValueError, OSError) as exc:
            input(f'配置无效：{exc}。按 Enter 返回…')
            self.message = 'wg-easy 配置未修改'
        finally:
            self.screen.refresh()

    def _switch_backend(self) -> None:
        current = self._backend()
        target = '3x-ui' if current == 's-ui' else 's-ui'
        if not self._confirm(f'切换到 {self._protocol_name(target)}？当前节点会被替换'):
            return
        original = self.config_path.read_text(encoding='utf-8')
        changed = set_toml_value(original, 'panel', 'backend', target)
        code = self._shell([
            'deploy', '--task', 'certificate', '--task', 'proxy-stack',
            '--task', 'node-config', '--task', 'node-verify',
        ], config_text=changed)
        if code == 0:
            _atomic_write(self.config_path, changed)
            self.message = f'已切换到 {self._protocol_name(target)}'
        else:
            self.message = '切换失败，主配置未修改'

    def _change_credentials(self) -> None:
        backend = self._backend()
        backend_section = 'panel.sui' if backend == 's-ui' else 'panel.xui'
        backend_env = 'VPSDEPLOY_SUI_PASSWORD' if backend == 's-ui' else 'VPSDEPLOY_XUI_PASSWORD'
        values = self._credential_prompts(backend)
        if values is None:
            return
        gateway_user, panel_user, gateway_password, panel_password = values
        original = self.config_path.read_text(encoding='utf-8')
        changed = set_toml_value(original, 'panel', 'basic_auth_user', gateway_user)
        changed = set_toml_value(changed, backend_section, 'username', panel_user)
        env: dict[str, str] = {}
        if gateway_password:
            changed = set_toml_value(changed, 'panel', 'basic_auth_password_mode', 'environment')
            env['VPSDEPLOY_CADDY_PASSWORD'] = gateway_password
        if panel_password:
            changed = set_toml_value(changed, backend_section, 'password_mode', 'environment')
            env[backend_env] = panel_password
        code = self._shell([
            'deploy', '--task', 'certificate', '--task', 'proxy-stack',
            '--task', 'node-config', '--task', 'node-verify',
        ], env=env, config_text=changed)
        if code == 0:
            # Persist usernames only. Passwords remain in the root-only runtime state.
            persisted = set_toml_value(original, 'panel', 'basic_auth_user', gateway_user)
            persisted = set_toml_value(persisted, backend_section, 'username', panel_user)
            _atomic_write(self.config_path, persisted)
            self.message = '账号密码已修改并通过重启验证'
        else:
            self.message = '账号密码修改失败，主配置未修改'

    def _credential_prompts(self, backend: str) -> tuple[str, str, str, str] | None:
        import tomllib
        with self.config_path.open('rb') as handle:
            config = tomllib.load(handle)
        panel = config.get('panel', {})
        key = 'sui' if backend == 's-ui' else 'xui'
        current_gateway = str(panel.get('basic_auth_user', 'gateway-admin'))
        current_panel = str(panel.get(key, {}).get('username', f'{key}-admin'))
        curses.endwin()
        try:
            gateway = input(f'Caddy BasicAuth 用户名 [{current_gateway}]: ').strip() or current_gateway
            panel_user = input(f'{self._protocol_name(backend)} 面板用户名 [{current_panel}]: ').strip() or current_panel
            gateway_password = getpass.getpass('新 Caddy 密码（留空保持不变）: ')
            panel_password = getpass.getpass('新面板密码（留空保持不变）: ')
            if gateway_password and gateway_password != getpass.getpass('确认新 Caddy 密码: '):
                input('Caddy 密码不一致。按 Enter 返回…')
                return None
            if panel_password and panel_password != getpass.getpass('确认新面板密码: '):
                input('面板密码不一致。按 Enter 返回…')
                return None
            return gateway, panel_user, gateway_password, panel_password
        finally:
            self.screen.refresh()

    def _rotate_node(self) -> None:
        if not self._confirm('轮换节点客户端凭据？现有客户端配置会立即失效'):
            return
        text = set_toml_value(
            self.config_path.read_text(encoding='utf-8'), 'node', 'rotate_client_secret', True,
        )
        code = self._shell(
            ['deploy', '--task', 'node-config', '--task', 'node-verify'], config_text=text,
        )
        self.message = '节点凭据已轮换' if code == 0 else '节点凭据轮换失败'

    def _verify_node(self) -> None:
        code = self._shell(['deploy', '--task', 'node-verify'])
        self.message = '节点验收成功' if code == 0 else '节点验收失败'

    def _repair_ipv6(self) -> None:
        code = self._shell([
            'deploy', '--task', 'ipv6-connectivity', '--task', 'dns-records',
            '--task', 'node-verify',
        ])
        self.message = 'IPv6 检测/修复完成' if code == 0 else 'IPv6 检测或回退失败'

    def _status(self) -> None:
        self._shell(['status'])
        self.message = '状态检查完成'

    def _credentials(self) -> None:
        if self._confirm('将在终端显示明文凭据，继续？'):
            self._shell(['credentials'])
            self.message = '凭据显示完成'

    def _confirm(self, prompt: str) -> bool:
        selected = self._menu(prompt, ['确认', '取消'])
        return selected == 0


def run_tui(config_path: Path) -> None:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise DeployError('The TUI requires an interactive terminal')
    if not config_path.is_file():
        raise DeployError(f'Configuration file not found: {config_path}')
    curses.wrapper(lambda screen: DeploymentTUI(screen, config_path).run())
