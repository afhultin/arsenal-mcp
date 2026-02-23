"""Dig tool wrapper."""
from __future__ import annotations
from typing import Any
from arsenal.tools.base import KaliTool


class DigTool(KaliTool):
    name = "dig_lookup"
    binary_name = "dig"
    category = "recon"
    description = "DNS lookup utility"

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        cmd = [self.binary_name]
        cmd.append(target)
        record_type = kwargs.get("record_type", "")
        if record_type:
            cmd.append(record_type)
        if kwargs.get("short", False):
            cmd.append("+short")
        return cmd

    def parse_output(self, stdout: str, stderr: str) -> Any:
        records = []
        in_answer = False
        for line in stdout.splitlines():
            if ";; ANSWER SECTION:" in line:
                in_answer = True
                continue
            if in_answer:
                if line.startswith(";;") or not line.strip():
                    in_answer = False
                    continue
                parts = line.split()
                if len(parts) >= 5:
                    records.append({
                        "name": parts[0], "ttl": parts[1],
                        "class": parts[2], "type": parts[3],
                        "value": " ".join(parts[4:]),
                    })
        return {"records": records, "count": len(records), "raw": stdout}
