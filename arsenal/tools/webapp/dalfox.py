"""DalFox XSS scanner tool wrapper."""
from __future__ import annotations
from typing import Any
from arsenal.tools.base import KaliTool


class DalfoxTool(KaliTool):
    name = "dalfox_xss"
    binary_name = "dalfox"
    category = "webapp"
    description = "XSS vulnerability scanner and parameter analysis"

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        cmd = [self.binary_name, "url", target]
        if param := kwargs.get("parameter", ""):
            cmd.extend(["-p", param])
        if kwargs.get("blind", ""):
            cmd.extend(["--blind", kwargs["blind"]])
        if kwargs.get("output_json", False):
            cmd.extend(["--format", "json"])
        return cmd

    def parse_output(self, stdout: str, stderr: str) -> Any:
        vulns = []
        findings = []
        for line in stdout.splitlines():
            line = line.strip()
            if "[POC]" in line or "[V]" in line:
                vulns.append(line)
                findings.append({
                    "title": "XSS Vulnerability Found",
                    "severity": "high",
                    "finding_type": "vulnerability",
                    "evidence": line,
                    "cwe": "CWE-79",
                })
        return {"vulnerabilities": vulns, "count": len(vulns), "findings": findings}
