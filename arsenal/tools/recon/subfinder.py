"""Subfinder tool wrapper."""
from __future__ import annotations
from typing import Any
from arsenal.tools.base import KaliTool


class SubfinderTool(KaliTool):
    name = "subfinder_enum"
    binary_name = "subfinder"
    category = "recon"
    description = "Subdomain enumeration using passive sources"

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        cmd = [self.binary_name, "-d", target, "-silent"]
        if kwargs.get("recursive", False):
            cmd.append("-recursive")
        if sources := kwargs.get("sources", ""):
            cmd.extend(["-sources", sources])
        return cmd

    def parse_output(self, stdout: str, stderr: str) -> Any:
        subs = [line.strip() for line in stdout.splitlines() if line.strip()]
        return {"subdomains": subs, "count": len(subs)}
