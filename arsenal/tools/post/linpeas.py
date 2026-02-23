"""LinPEAS tool wrapper."""
from __future__ import annotations
from typing import Any
from arsenal.tools.base import KaliTool, ExecutionMode


class LinpeasTool(KaliTool):
    name = "linpeas_enum"
    binary_name = "linpeas.sh"
    category = "post"
    description = "Linux privilege escalation enumeration script"
    execution_mode = ExecutionMode.BACKGROUND

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        cmd = [self.binary_name]
        if checks := kwargs.get("checks", ""):
            cmd.extend(["-s", checks])
        if kwargs.get("quiet", False):
            cmd.append("-q")
        return cmd

    def parse_output(self, stdout: str, stderr: str) -> Any:
        highlights = []
        for line in stdout.splitlines():
            if any(marker in line for marker in ["95%", "99%", "RED/YELLOW"]):
                highlights.append(line.strip())
        return {"highlights": highlights, "raw_length": len(stdout)}
