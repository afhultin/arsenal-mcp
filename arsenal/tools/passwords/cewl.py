"""CeWL tool wrapper."""
from __future__ import annotations
from typing import Any
from arsenal.tools.base import KaliTool


class CewlTool(KaliTool):
    name = "cewl_wordlist"
    binary_name = "cewl"
    category = "passwords"
    description = "Custom wordlist generator from website content"

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        cmd = [self.binary_name, target]
        if depth := kwargs.get("depth", ""):
            cmd.extend(["-d", str(depth)])
        if min_length := kwargs.get("min_length", ""):
            cmd.extend(["-m", str(min_length)])
        if kwargs.get("with_numbers", False):
            cmd.append("--with-numbers")
        if kwargs.get("emails", False):
            cmd.append("-e")
        if output := kwargs.get("output", ""):
            cmd.extend(["-w", output])
        return cmd

    def parse_output(self, stdout: str, stderr: str) -> Any:
        words = [line.strip() for line in stdout.splitlines() if line.strip()]
        return {"words": words, "count": len(words)}
