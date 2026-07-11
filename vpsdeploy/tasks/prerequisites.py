from __future__ import annotations

import os
import shutil
from pathlib import Path

from vpsdeploy.core.runtime import DeployError, DeploymentContext, Task, run, section


class PrerequisitesTask(Task):
    name = 'prerequisites'

    def validate(self, context: DeploymentContext) -> None:
        if os.geteuid() != 0:
            raise DeployError('Run as root')
        if shutil.which('apt-get') is None:
            raise DeployError('Only Debian and Ubuntu are supported')

    def apply(self, context: DeploymentContext) -> None:
        run(['apt-get', 'update'])
        run(['apt-get', 'install', '-y', 'ca-certificates', 'curl', 'openssl', 'iproute2'])
        if shutil.which('docker') and run(['docker', 'compose', 'version'], check=False).returncode == 0:
            return
        if not bool(section(context.config, 'stack').get('install_docker', True)):
            raise DeployError('Docker is missing and stack.install_docker is false')
        script = Path('/tmp/get-docker.sh')
        run(['curl', '-fsSL', 'https://get.docker.com', '-o', str(script)])
        run(['sh', str(script)])
        script.unlink(missing_ok=True)
        run(['systemctl', 'enable', '--now', 'docker'])
