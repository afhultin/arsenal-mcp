"""Whois tool wrapper."""
from __future__ import annotations
from typing import Any
from arsenal.tools.base import KaliTool


class WhoisTool(KaliTool):
    name = "whois_lookup"
    binary_name = "whois"
    category = "recon"
    description = "WHOIS domain/IP registration lookup"

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        return [self.binary_name, target]

    def parse_output(self, stdout: str, stderr: str) -> Any:
        data: dict[str, str] = {}
        for line in stdout.splitlines():
            if ":" in line and not line.startswith("%") and not line.startswith("#"):
                key, _, value = line.partition(":")
                key = key.strip().lower().replace(" ", "_")
                value = value.strip()
                if key and value:
                    data[key] = value
        return {"raw": stdout, "parsed_fields": data}
