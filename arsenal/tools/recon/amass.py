"""Amass tool wrapper."""
from __future__ import annotations
from typing import Any
from arsenal.tools.base import KaliTool


class AmassTool(KaliTool):
    name = "amass_enum"
    binary_name = "amass"
    category = "recon"
    description = "In-depth subdomain enumeration and network mapping"

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        cmd = [self.binary_name, "enum", "-d", target]
        if kwargs.get("passive_only", False):
            cmd.append("-passive")
        if timeout := kwargs.get("timeout", ""):
            cmd.extend(["-timeout", str(timeout)])
        return cmd

    def parse_output(self, stdout: str, stderr: str) -> Any:
        subs = [line.strip() for line in stdout.splitlines() if line.strip() and not line.startswith("OWASP")]
        return {"subdomains": subs, "count": len(subs)}
