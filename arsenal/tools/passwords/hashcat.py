"""Hashcat tool wrapper."""
from __future__ import annotations
from typing import Any
from arsenal.tools.base import KaliTool


class HashcatTool(KaliTool):
    name = "hashcat_crack"
    binary_name = "hashcat"
    category = "passwords"
    description = "GPU-accelerated password hash cracker"

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        cmd = [self.binary_name]
        hash_type = kwargs.get("hash_type", "")
        if hash_type:
            cmd.extend(["-m", str(hash_type)])
        attack_mode = kwargs.get("attack_mode", "0")
        cmd.extend(["-a", str(attack_mode)])
        if kwargs.get("show", False):
            cmd.append("--show")
        cmd.append(target)
        if wordlist := kwargs.get("wordlist", ""):
            cmd.append(wordlist)
        if rules := kwargs.get("rules", ""):
            cmd.extend(["-r", rules])
        return cmd

    def parse_output(self, stdout: str, stderr: str) -> Any:
        cracked = []
        for line in stdout.splitlines():
            if ":" in line and not line.startswith("Session") and not line.startswith("Hash"):
                cracked.append(line.strip())
        return {"cracked": cracked, "count": len(cracked), "raw": stdout}
