"""Nikto tool wrapper."""
from __future__ import annotations
from typing import Any
from arsenal.tools.base import KaliTool


class NiktoTool(KaliTool):
    name = "nikto_scan"
    binary_name = "nikto"
    category = "webapp"
    description = "Web server scanner — misconfigurations, outdated software, dangerous files"

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        cmd = [self.binary_name, "-h", target]
        if tuning := kwargs.get("tuning", ""):
            cmd.extend(["-Tuning", tuning])
        if kwargs.get("ssl", False):
            cmd.append("-ssl")
        if output := kwargs.get("output", ""):
            cmd.extend(["-o", output, "-Format", "json"])
        return cmd

    def parse_output(self, stdout: str, stderr: str) -> Any:
        vulns = []
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith("+ ") and ":" in line:
                vulns.append(line[2:])
        return {"vulnerabilities": vulns, "count": len(vulns), "raw": stdout}
