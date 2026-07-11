from __future__ import annotations

from vpsdeploy.core.runtime import DeploymentContext, Task, run, section


class DiagnosticsTask(Task):
    name = 'diagnostics'

    def apply(self, context: DeploymentContext) -> None:
        run(['docker', 'compose', 'ps'], cwd=context.stack_dir)
        run(['ss', '-lntup'], check=False)
        run(['docker', 'network', 'inspect', str(section(context.config, 'docker')['network_name'])], check=False)
