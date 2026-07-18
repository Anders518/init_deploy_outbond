from pathlib import Path

from vpsdeploy.application import DEPLOY_TASKS
import pytest

from vpsdeploy.core.runtime import DeploymentContext, DeployError, Task
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


def test_task_rolls_back_when_post_apply_verification_fails(tmp_path: Path) -> None:
    events: list[str] = []

    class FailingTask(Task):
        name = 'failing-hardening'

        def prepare_rollback(self, context: DeploymentContext) -> str:
            events.append('snapshot')
            return 'before'

        def apply(self, context: DeploymentContext) -> None:
            events.append('apply')

        def verify(self, context: DeploymentContext) -> None:
            events.append('verify')
            raise DeployError('verification failed')

        def rollback(self, context: DeploymentContext, snapshot: str) -> None:
            assert snapshot == 'before'
            events.append('rollback')

    with pytest.raises(DeployError, match='verification failed'):
        FailingTask().execute(DeploymentContext(config(tmp_path)))

    assert events == ['snapshot', 'apply', 'verify', 'rollback']


def test_task_reports_rollback_failure_without_hiding_original_error(tmp_path: Path) -> None:
    class BrokenRollbackTask(Task):
        name = 'broken-rollback'

        def prepare_rollback(self, context: DeploymentContext) -> bool:
            return True

        def apply(self, context: DeploymentContext) -> None:
            raise DeployError('apply failed')

        def rollback(self, context: DeploymentContext, snapshot: bool) -> None:
            raise OSError('restore failed')

    with pytest.raises(DeployError, match='apply failed.*restore failed'):
        BrokenRollbackTask().execute(DeploymentContext(config(tmp_path)))
