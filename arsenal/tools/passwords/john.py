"""John the Ripper tool wrapper."""
from __future__ import annotations
from typing import Any
from arsenal.tools.base import KaliTool


class JohnTool(KaliTool):
    name = "john_crack"
    binary_name = "john"
    category = "passwords"
    description = "Password hash cracker — supports many hash formats"

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        cmd = [self.binary_name]
        if wordlist := kwargs.get("wordlist", ""):
            cmd.append("--wordlist=" + wordlist)
        if fmt := kwargs.get("format", ""):
            cmd.append("--format=" + fmt)
        if rules := kwargs.get("rules", ""):
            cmd.append("--rules=" + rules)
        if kwargs.get("show", False):
            cmd.append("--show")
        cmd.append(target)
        return cmd

    def parse_output(self, stdout: str, stderr: str) -> Any:
        cracked = []
        for line in stdout.splitlines():
            if ":" in line and not line.startswith("Using") and not line.startswith("Loaded"):
                cracked.append(line.strip())
        return {"cracked": cracked, "count": len(cracked), "raw": stdout}
