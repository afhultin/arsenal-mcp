"""Bettercap tool wrapper."""
from __future__ import annotations
from typing import Any
from arsenal.tools.base import KaliTool, ExecutionMode


class BettercapTool(KaliTool):
    name = "bettercap_attack"
    binary_name = "bettercap"
    category = "network"
    description = "Network attack and monitoring framework"
    execution_mode = ExecutionMode.INTERACTIVE

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        cmd = [self.binary_name]
        if iface := kwargs.get("interface", ""):
            cmd.extend(["-iface", iface])
        if caplet := kwargs.get("caplet", ""):
            cmd.extend(["-caplet", caplet])
        if eval_cmd := kwargs.get("eval", ""):
            cmd.extend(["-eval", eval_cmd])
        return cmd

    def parse_output(self, stdout: str, stderr: str) -> Any:
        return {"raw": stdout}
