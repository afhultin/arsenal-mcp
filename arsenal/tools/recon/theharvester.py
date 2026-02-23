"""theHarvester tool wrapper."""
from __future__ import annotations
from typing import Any
from arsenal.tools.base import KaliTool


class TheHarvesterTool(KaliTool):
    name = "theharvester_scan"
    binary_name = "theHarvester"
    category = "recon"
    description = "Email, subdomain, and name harvester from public sources"

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        cmd = [self.binary_name, "-d", target]
        source = kwargs.get("source", "all")
        cmd.extend(["-b", source])
        if limit := kwargs.get("limit", ""):
            cmd.extend(["-l", str(limit)])
        return cmd

    def parse_output(self, stdout: str, stderr: str) -> Any:
        emails: list[str] = []
        hosts: list[str] = []
        section = None
        for line in stdout.splitlines():
            if "Emails found:" in line:
                section = "emails"
                continue
            elif "Hosts found:" in line:
                section = "hosts"
                continue
            elif line.startswith("[*]") or line.startswith("---"):
                section = None
                continue
            stripped = line.strip()
            if stripped:
                if section == "emails":
                    emails.append(stripped)
                elif section == "hosts":
                    hosts.append(stripped)
        return {"emails": emails, "hosts": hosts, "email_count": len(emails), "host_count": len(hosts)}
