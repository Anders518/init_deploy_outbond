from pathlib import Path

from vpsdeploy.application import DEPLOY_TASKS
from vpsdeploy.core.runtime import DeploymentContext
from vpsdeploy.tasks.certificates import CertificateTask


def config(tmp_path: Path) -> dict:
    return {
        "stack": {"install_dir": str(tmp_path)},
        "panel": {"tls": {"mode": "acme_dns"}},
        "domains": {
            "panel": "panel.example.net",
            "node": "node.example.net",
            "acme_email": "a@example.net",
        },
        "cloudflare": {"api_token": "token"},
        "dns": {
            "enabled": False,
            "provider": "cloudflare",
            "panel": {"enabled": True, "proxied": True},
            "node": {"enabled": True, "proxied": False},
        },
        "hardening": {
            "enabled": False,
            "ssh": {"enabled": False},
            "fail2ban": {"enabled": False},
            "unattended_upgrades": {"enabled": False},
            "system": {},
        },
    }


def test_task_names_are_unique() -> None:
    names = [task.name for task in DEPLOY_TASKS]
    assert len(names) == len(set(names))
    assert names[:5] == [
        "prerequisites", "ipv6-connectivity", "dns-records", "certificate", "proxy-stack",
    ]


def test_certificate_provider_selection(tmp_path: Path) -> None:
    task = CertificateTask()
    provider = task._provider(DeploymentContext(config(tmp_path)))
    assert provider.__class__.__name__ == "AcmeDNSProvider"
