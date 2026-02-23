"""Wifite tool wrapper."""
from __future__ import annotations
from typing import Any
from arsenal.tools.base import KaliTool, ExecutionMode


class WifiteTool(KaliTool):
    name = "wifite_attack"
    binary_name = "wifite"
    category = "wireless"
    description = "Automated wireless network auditor"
    execution_mode = ExecutionMode.INTERACTIVE

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        cmd = [self.binary_name]
        if iface := kwargs.get("interface", ""):
            cmd.extend(["-i", iface])
        if kwargs.get("wpa", False):
            cmd.append("--wpa")
        if kwargs.get("wep", False):
            cmd.append("--wep")
        if bssid := kwargs.get("bssid", ""):
            cmd.extend(["--bssid", bssid])
        return cmd

    def parse_output(self, stdout: str, stderr: str) -> Any:
        return {"raw": stdout}
