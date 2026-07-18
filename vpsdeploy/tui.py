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
                ('完整部署并自动验收', self._full_deploy),
                (f'切换节点协议（当前：{self._protocol_name(backend)}）', self._switch_backend),
                ('修改网关与面板账号密码', self._change_credentials),
                ('轮换当前节点客户端凭据', self._rotate_node),
                ('运行 Mihomo + sing-box 验收', self._verify_node),
                ('检测/修复 IPv6（失败自动回退）', self._repair_ipv6),
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
