from copy import deepcopy
import json
import subprocess
from pathlib import Path

import pytest

from vpsdeploy.config import validate_config
from vpsdeploy.core.runtime import DeployError, DeploymentContext
from vpsdeploy.providers.tls.base import TLSMaterial
from vpsdeploy.tasks import proxy_stack
from vpsdeploy.tasks.proxy_stack import ProxyStackTask
from vpsdeploy.templates.render import render_caddy, render_compose
from vpsdeploy.tasks.node_config import NodeConfigTask, _anytls_subscription
from vpsdeploy.core import runtime
from vpsdeploy.tui import apply_core_config, apply_hardening_config, apply_sub2api_config, set_toml_value
from vpsdeploy.tasks.ipv6_connectivity import FileSnapshot
from vpsdeploy.tasks.ufw import UFWTask
from vpsdeploy.tasks import ufw


def base_config(tmp_path: Path) -> dict:
    return {
        'stack': {'install_dir': str(tmp_path)},
        'domains': {
            'panel': 'panel.example.net',
            'subscription': 'sub.example.net',
            'node': 'node.example.net',
            'acme_email': 'admin@example.net',
        },
        'ports': {
            'proxy': 443,
            'panel_public': 8443,
            'panel_internal': 2053,
            'subscription_internal': 2096,
        },
        'node': {
            'enabled': True,
            'client_name': 'primary',
            'verify': {
                'enabled': True,
                'mihomo_image': 'metacubex/mihomo:v1.19.28',
                'singbox_image': 'ghcr.io/sagernet/sing-box:v1.13.12',
            },
        },
        'panel': {
            'backend': '3x-ui',
            'path': '/',
            'subscription_path': '/sub',
            'allowed_cidrs': [],
            'basic_auth_user': 'gateway-admin',
            'xui': {},
            'sui': {},
            'tls': {'mode': 'acme_dns'},
        },
        'docker': {
            'xui_image': 'ghcr.io/mhsanaei/3x-ui:latest',
            'sui_image': 'alireza7/s-ui:v1.5.3',
            'caddy_image': 'caddy:2-alpine',
            'enable_ipv6': False,
        },
        'hardening': {
            'ssh': {'new_port': 4522, 'current_port': 22, 'keep_current_port': True},
        },
    }


def test_xui_is_the_backward_compatible_default(tmp_path: Path) -> None:
    config = base_config(tmp_path)
    del config['panel']['backend']
    context = DeploymentContext(config)
    compose = render_compose(context, TLSMaterial(mode='acme_dns'))
    caddy = render_caddy(context, TLSMaterial(mode='acme_dns'), '$2a$hash')

    assert '  3x-ui:' in compose
    assert '  s-ui:' not in compose
    assert 'reverse_proxy 3x-ui:2053' in caddy
    assert 'reverse_proxy 3x-ui:2096' in caddy


def test_sui_backend_is_exclusive_and_receives_all_routes(tmp_path: Path) -> None:
    config = base_config(tmp_path)
    config['panel']['backend'] = 's-ui'
    context = DeploymentContext(config)
    compose = render_compose(context, TLSMaterial(mode='acme_dns'))
    caddy = render_caddy(context, TLSMaterial(mode='acme_dns'), '$2a$hash')

    assert '  s-ui:' in compose
    assert '  3x-ui:' not in compose
    assert '${PROXY_PORT}:${PROXY_PORT}/tcp' in compose
    assert 'depends_on: [s-ui]' in compose
    assert 'reverse_proxy s-ui:2053' in caddy
    assert 'reverse_proxy s-ui:2096' in caddy
    assert 'reverse_proxy 3x-ui:' not in caddy
    assert 'node.example.net:8443' in caddy
    assert 'AnyTLS certificate endpoint' in caddy
    assert './s-ui/cert:/root/cert' in compose


def test_backend_validation_rejects_unknown_value(tmp_path: Path) -> None:
    config = base_config(tmp_path)
    config['panel']['backend'] = 'other'

    with pytest.raises(DeployError, match='panel.backend'):
        validate_config(config)


def test_sui_requires_its_image(tmp_path: Path) -> None:
    config = deepcopy(base_config(tmp_path))
    config['panel']['backend'] = 's-ui'
    config['docker']['sui_image'] = ''

    with pytest.raises(DeployError, match='docker.sui_image'):
        validate_config(config)


def test_sui_requires_public_acme_certificate(tmp_path: Path) -> None:
    config = deepcopy(base_config(tmp_path))
    config['panel']['backend'] = 's-ui'
    config['panel']['tls']['mode'] = 'cloudflare_origin'

    with pytest.raises(DeployError, match='AnyTLS certificate'):
        validate_config(config)


@pytest.mark.parametrize('protocol', ['vless-reality', 'anytls'])
def test_client_configs_include_both_validation_cores(tmp_path: Path, protocol: str) -> None:
    config = base_config(tmp_path)
    context = DeploymentContext(config)
    if protocol == 'vless-reality':
        client = {
            'protocol': protocol, 'address': 'node.example.net', 'port': 443,
            'uuid': '00000000-0000-0000-0000-000000000001', 'flow': 'xtls-rprx-vision',
            'server_name': 'www.cloudflare.com', 'public_key': 'public', 'short_id': '0011223344556677',
            'fingerprint': 'chrome',
        }
    else:
        client = {
            'protocol': protocol, 'address': 'node.example.net', 'port': 443,
            'password': 'secret', 'server_name': 'node.example.net', 'fingerprint': 'chrome',
        }

    NodeConfigTask()._write_client_configs(context, client)

    mihomo = json.loads((tmp_path / 'state/mihomo-test.yaml').read_text())
    singbox = json.loads((tmp_path / 'state/sing-box-test.json').read_text())
    expected = 'vless' if protocol == 'vless-reality' else 'anytls'
    assert mihomo['proxies'][0]['type'] == expected
    assert singbox['outbounds'][0]['type'] == expected


def test_ipv6_client_configs_enable_mihomo_ipv6(tmp_path: Path) -> None:
    context = DeploymentContext(base_config(tmp_path))
    client = {
        'protocol': 'anytls', 'address': '2001:db8::10', 'port': 443,
        'password': 'secret', 'server_name': 'node.example.net', 'fingerprint': 'chrome',
    }

    NodeConfigTask()._write_client_configs(context, client)

    mihomo = json.loads((tmp_path / 'state/mihomo-test.yaml').read_text())
    assert mihomo['ipv6'] is True
    assert mihomo['proxies'][0]['server'] == '2001:db8::10'


def test_anytls_subscription_is_external_opaque_and_persistent(tmp_path: Path) -> None:
    config = base_config(tmp_path)
    config['panel']['backend'] = 's-ui'
    context = DeploymentContext(config)

    generated, base = _anytls_subscription(context, {})
    reused, repeated_base = _anytls_subscription(context, {'subscription_id': generated})

    assert base == 'https://sub.example.net:8443/sub/'
    assert repeated_base == base
    assert reused == generated
    assert generated != 'primary'
    assert len(generated) >= 24


def test_command_log_redacts_password(monkeypatch: pytest.MonkeyPatch,
                                      capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(
        runtime.subprocess,
        'run',
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, '', ''),
    )

    runtime.run(['tool', '--password', 'top-secret'], redact_values={'top-secret'})

    output = capsys.readouterr().out
    assert 'top-secret' not in output
    assert '********' in output


def test_sui_error_redacts_password(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        proxy_stack,
        'run',
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 1, '', 'failed'),
    )

    with pytest.raises(DeployError) as raised:
        ProxyStackTask()._run_sui(
            '/app/sui', 'admin', '-password', 'top-secret',
            redact_values={'top-secret'},
        )

    assert 'top-secret' not in str(raised.value)


def test_tui_updates_existing_toml_value_without_reformatting() -> None:
    source = '[panel]\nbackend = "3x-ui" # keep\npath = "/"\n\n[node]\nenabled = true\n'

    changed = set_toml_value(source, 'panel', 'backend', 's-ui')

    assert 'backend = "s-ui" # keep' in changed
    assert 'path = "/"' in changed
    assert changed.count('[panel]') == 1


def test_tui_adds_missing_toml_key_and_section() -> None:
    source = '[panel]\nbackend = "3x-ui"\n'

    changed = set_toml_value(source, 'panel', 'basic_auth_user', 'owner')
    changed = set_toml_value(changed, 'node', 'rotate_client_secret', True)

    assert 'basic_auth_user = "owner"' in changed
    assert '[node]\nrotate_client_secret = true' in changed


def test_tui_core_wizard_updates_deployment_fields() -> None:
    changed = apply_core_config('[domains]\npanel = "old.example.net"\n', {
        'panel_domain': 'panel.example.net', 'subscription_domain': 'sub.example.net',
        'node_domain': 'node.example.net', 'acme_email': 'admin@example.net',
        'backend': 's-ui', 'tls_mode': 'acme_dns', 'panel_public_port': 8443,
        'client_name': 'home',
    })

    assert 'panel = "panel.example.net"' in changed
    assert 'subscription = "sub.example.net"' in changed
    assert '[panel]\nbackend = "s-ui"' in changed
    assert '[panel.tls]\nmode = "acme_dns"' in changed
    assert '[ports]\npanel_public = 8443' in changed


def test_tui_hardening_wizard_updates_security_sections() -> None:
    changed = apply_hardening_config('[hardening]\nenabled = false\n', {
        'enabled': True, 'ssh_enabled': True, 'ssh_current_port': 22,
        'ssh_new_port': 4522, 'ssh_keep_current_port': True,
        'ssh_disable_root_login': False, 'ssh_disable_password_auth': True,
        'ufw_enabled': True, 'fail2ban_enabled': True,
        'unattended_upgrades_enabled': True, 'automatic_reboot': False,
        'system_sysctl_enabled': True, 'disable_apport': True,
    })

    assert '[hardening]\nenabled = true' in changed
    assert '[hardening.ssh]\nenabled = true' in changed
    assert 'new_port = 4522' in changed
    assert 'keep_current_port = true' in changed
    assert '[hardening.ufw]\nenabled = true' in changed
    assert '[hardening.fail2ban]\nenabled = true' in changed
    assert '[hardening.unattended_upgrades]\nenabled = true' in changed
    assert '[hardening.system]\nenable_sysctl = true' in changed


def test_tui_sub2api_wizard_never_persists_plaintext_password() -> None:
    changed = apply_sub2api_config('[sub2api]\nenabled = false\n', {
        'enabled': True, 'domain': 'api.example.net', 'admin_email': 'admin@example.net',
    })

    assert 'enabled = true' in changed
    assert 'domain = "api.example.net"' in changed
    assert 'admin_password_mode = "generate"' in changed
    assert 'admin_password =' not in changed


def test_ipv6_file_snapshot_restores_existing_and_removes_created(tmp_path: Path) -> None:
    existing = tmp_path / 'existing.conf'
    existing.write_text('before\n')
    existing.chmod(0o640)
    old = FileSnapshot.capture(existing)
    existing.write_text('after\n')
    old.restore()

    created = tmp_path / 'created.conf'
    absent = FileSnapshot.capture(created)
    created.write_text('temporary\n')
    absent.restore()

    assert existing.read_text() == 'before\n'
    assert existing.stat().st_mode & 0o777 == 0o640
    assert not created.exists()


def test_ufw_is_opt_in_and_allows_required_ports_before_enable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = base_config(tmp_path)
    config['hardening']['enabled'] = True
    config['hardening']['ufw'] = {'enabled': False}
    context = DeploymentContext(config)
    assert UFWTask().enabled(context) is False

    config['hardening']['ufw']['enabled'] = True
    commands: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        status = 'Status: active\nufw allow 22/tcp\nufw allow 443/tcp\nufw allow 8443/tcp\n'
        return subprocess.CompletedProcess(command, 0, status, '')

    monkeypatch.setattr(ufw, 'run', fake_run)
    UFWTask().execute(context)

    assert ['apt-get', '-o', 'Dpkg::Options::=--force-confmiss', 'install', '-y', 'ufw'] in commands
    enable_index = commands.index(['ufw', '--force', 'enable'])
    assert commands.index(['ufw', 'allow', '22/tcp', 'comment', 'vpsdeploy SSH']) < enable_index
    assert commands.index(['ufw', 'allow', '443/tcp', 'comment', 'vpsdeploy proxy']) < enable_index
    assert commands.index(['ufw', 'allow', '8443/tcp', 'comment', 'vpsdeploy panel and subscription']) < enable_index


def test_ufw_keeps_old_ssh_port_during_migration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = base_config(tmp_path)
    config['hardening'].update(enabled=True, ufw={'enabled': True})
    config['hardening']['ssh']['enabled'] = True
    commands: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        status = 'Status: active\nufw allow 22/tcp\nufw allow 4522/tcp\nufw allow 443/tcp\nufw allow 8443/tcp\n'
        return subprocess.CompletedProcess(command, 0, status, '')

    monkeypatch.setattr(ufw, 'run', fake_run)
    monkeypatch.setattr(ufw.shutil, 'which', lambda name: '/usr/sbin/ufw')
    UFWTask().execute(DeploymentContext(config))

    assert ['ufw', 'allow', '22/tcp', 'comment', 'vpsdeploy SSH transition'] in commands
    assert ['ufw', 'allow', '4522/tcp', 'comment', 'vpsdeploy SSH'] in commands
