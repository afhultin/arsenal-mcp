"""Arpspoof tool wrapper."""
from __future__ import annotations
from typing import Any
from arsenal.tools.base import KaliTool, ExecutionMode


class ArpspoofTool(KaliTool):
    name = "arpspoof_attack"
    binary_name = "arpspoof"
    category = "network"
    description = "ARP spoofing for MITM attacks"
    execution_mode = ExecutionMode.BACKGROUND

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        cmd = [self.binary_name]
        if iface := kwargs.get("interface", ""):
            cmd.extend(["-i", iface])
        gateway = kwargs.get("gateway", "")
        if gateway:
            cmd.extend(["-t", target, gateway])
        else:
            cmd.append(target)
        return cmd

    def parse_output(self, stdout: str, stderr: str) -> Any:
        return {"raw": stdout}
