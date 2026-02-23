"""Shodan CLI tool wrapper."""
from __future__ import annotations
from typing import Any
from arsenal.tools.base import KaliTool


class ShodanTool(KaliTool):
    name = "shodan_search"
    binary_name = "shodan"
    category = "recon"
    description = "Shodan search engine CLI — query for hosts and services"

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        subcmd = kwargs.get("subcmd", "search")
        cmd = [self.binary_name, subcmd]
        if subcmd == "search":
            limit = kwargs.get("limit", 10)
            cmd.extend(["--limit", str(limit)])
            cmd.append(target)
        elif subcmd == "host":
            cmd.append(target)
        else:
            cmd.append(target)
        return cmd

    def parse_output(self, stdout: str, stderr: str) -> Any:
        results = []
        for line in stdout.splitlines():
            if line.strip():
                results.append(line.strip())
        return {"results": results, "count": len(results)}
