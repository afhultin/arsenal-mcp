"""Responder tool wrapper."""
from __future__ import annotations
from typing import Any
from arsenal.tools.base import KaliTool, ExecutionMode


class ResponderTool(KaliTool):
    name = "responder_listen"
    binary_name = "responder"
    category = "network"
    description = "LLMNR/NBT-NS/MDNS poisoner for credential capture"
    execution_mode = ExecutionMode.BACKGROUND

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        cmd = [self.binary_name, "-I", target]
        if kwargs.get("analyze", False):
            cmd.append("-A")
        if kwargs.get("wpad", False):
            cmd.append("-w")
        return cmd

    def parse_output(self, stdout: str, stderr: str) -> Any:
        hashes = []
        for line in stdout.splitlines():
            if "NTLMv" in line or "Hash" in line:
                hashes.append(line.strip())
        return {"captured_hashes": hashes, "count": len(hashes)}
