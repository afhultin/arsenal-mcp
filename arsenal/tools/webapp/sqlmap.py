"""SQLMap tool wrapper."""
from __future__ import annotations
from typing import Any
from arsenal.parsers.sqlmap import parse_sqlmap
from arsenal.tools.base import KaliTool


class SqlmapTool(KaliTool):
    name = "sqlmap_scan"
    binary_name = "sqlmap"
    category = "webapp"
    description = "Automatic SQL injection detection and exploitation"

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        cmd = [self.binary_name, "-u", target]
        if param := kwargs.get("parameter", ""):
            cmd.extend(["-p", param])
        if level := kwargs.get("level", ""):
            cmd.extend(["--level", str(level)])
        if risk := kwargs.get("risk", ""):
            cmd.extend(["--risk", str(risk)])
        if kwargs.get("batch", True):
            cmd.append("--batch")
        if kwargs.get("dbs", False):
            cmd.append("--dbs")
        if kwargs.get("tables", False):
            cmd.append("--tables")
        if db_name := kwargs.get("database", ""):
            cmd.extend(["-D", db_name])
        if extra := kwargs.get("extra_args", ""):
            cmd.extend(extra.split())
        return cmd

    def parse_output(self, stdout: str, stderr: str) -> Any:
        return parse_sqlmap(stdout, stderr)
