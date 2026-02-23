"""pspy tool wrapper."""
from __future__ import annotations
from typing import Any
from arsenal.tools.base import KaliTool, ExecutionMode


class PspyTool(KaliTool):
    name = "pspy_monitor"
    binary_name = "pspy64"
    category = "post"
    description = "Monitor Linux processes without root — find cron jobs and scripts"
    execution_mode = ExecutionMode.BACKGROUND

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        cmd = [self.binary_name]
        if kwargs.get("print_commands", True):
            cmd.append("-p")
        if kwargs.get("file_events", False):
            cmd.append("-f")
        return cmd

    def parse_output(self, stdout: str, stderr: str) -> Any:
        processes = []
        for line in stdout.splitlines():
            if "CMD:" in line:
                processes.append(line.strip())
        return {"processes": processes, "count": len(processes)}
