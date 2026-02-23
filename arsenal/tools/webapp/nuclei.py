"""Nuclei tool wrapper."""
from __future__ import annotations
from typing import Any
from arsenal.parsers.nuclei import parse_nuclei
from arsenal.tools.base import KaliTool


class NucleiTool(KaliTool):
    name = "nuclei_scan"
    binary_name = "nuclei"
    category = "webapp"
    description = "Fast vulnerability scanner using YAML templates"

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        cmd = [self.binary_name, "-u", target, "-jsonl"]
        if templates := kwargs.get("templates", ""):
            cmd.extend(["-t", templates])
        if severity := kwargs.get("severity", ""):
            cmd.extend(["-severity", severity])
        if tags := kwargs.get("tags", ""):
            cmd.extend(["-tags", tags])
        if kwargs.get("new_templates", False):
            cmd.append("-nt")
        if rate := kwargs.get("rate_limit", ""):
            cmd.extend(["-rl", str(rate)])
        return cmd

    def parse_output(self, stdout: str, stderr: str) -> Any:
        return parse_nuclei(stdout, stderr)
