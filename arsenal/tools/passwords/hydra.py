"""Hydra tool wrapper."""
from __future__ import annotations
from typing import Any
from arsenal.tools.base import KaliTool


class HydraTool(KaliTool):
    name = "hydra_brute"
    binary_name = "hydra"
    category = "passwords"
    description = "Online password brute-forcer for network services"

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        cmd = [self.binary_name]
        if username := kwargs.get("username", ""):
            cmd.extend(["-l", username])
        elif username_list := kwargs.get("username_list", ""):
            cmd.extend(["-L", username_list])
        if password := kwargs.get("password", ""):
            cmd.extend(["-p", password])
        elif password_list := kwargs.get("password_list", ""):
            cmd.extend(["-P", password_list])
        if threads := kwargs.get("threads", ""):
            cmd.extend(["-t", str(threads)])
        if kwargs.get("verbose", False):
            cmd.append("-V")
        service = kwargs.get("service", "ssh")
        cmd.append(target)
        cmd.append(service)
        if service_args := kwargs.get("service_args", ""):
            cmd.append(service_args)
        return cmd

    def parse_output(self, stdout: str, stderr: str) -> Any:
        creds = []
        findings = []
        for line in stdout.splitlines():
            if "login:" in line and "password:" in line:
                creds.append(line.strip())
                findings.append({
                    "title": "Valid credentials found",
                    "severity": "critical",
                    "finding_type": "credential",
                    "evidence": line.strip(),
                })
        return {"credentials": creds, "count": len(creds), "findings": findings}
