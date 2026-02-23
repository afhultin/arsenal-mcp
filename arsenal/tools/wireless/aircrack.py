"""Aircrack-ng tool wrapper."""
from __future__ import annotations
from typing import Any
from arsenal.tools.base import KaliTool


class AircrackTool(KaliTool):
    name = "aircrack_crack"
    binary_name = "aircrack-ng"
    category = "wireless"
    description = "WiFi WEP/WPA-PSK key cracker"

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        cmd = [self.binary_name]
        if wordlist := kwargs.get("wordlist", ""):
            cmd.extend(["-w", wordlist])
        if bssid := kwargs.get("bssid", ""):
            cmd.extend(["-b", bssid])
        cmd.append(target)
        return cmd

    def parse_output(self, stdout: str, stderr: str) -> Any:
        key_found = None
        for line in stdout.splitlines():
            if "KEY FOUND" in line:
                key_found = line.strip()
        return {"key_found": key_found, "raw": stdout}
