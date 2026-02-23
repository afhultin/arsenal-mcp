"""Nmap output parser — parses standard nmap text output into structured data."""
from __future__ import annotations

import re
from typing import Any


def parse_nmap(stdout: str, stderr: str) -> dict[str, Any]:
    """Parse nmap text output into structured host/port data."""
    hosts: list[dict[str, Any]] = []
    current_host: dict[str, Any] | None = None
    findings: list[dict] = []

    for line in stdout.splitlines():
        # Host line
        host_match = re.match(r"Nmap scan report for (.+?)(?:\s+\((.+?)\))?$", line)
        if host_match:
            if current_host:
                hosts.append(current_host)
            hostname = host_match.group(1)
            ip = host_match.group(2) or hostname
            current_host = {"host": hostname, "ip": ip, "ports": [], "os": None}
            continue

        # Port line
        port_match = re.match(
            r"(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)\s*(.*)?", line
        )
        if port_match and current_host is not None:
            port_info = {
                "port": int(port_match.group(1)),
                "protocol": port_match.group(2),
                "state": port_match.group(3),
                "service": port_match.group(4),
                "version": (port_match.group(5) or "").strip(),
            }
            current_host["ports"].append(port_info)

            if port_info["state"] == "open":
                findings.append({
                    "title": f"Open port {port_info['port']}/{port_info['protocol']} ({port_info['service']})",
                    "severity": "info",
                    "finding_type": "service",
                    "target": current_host["ip"],
                    "evidence": line.strip(),
                })
            continue

        # OS detection
        os_match = re.match(r"OS details:\s*(.+)", line)
        if os_match and current_host is not None:
            current_host["os"] = os_match.group(1).strip()

    if current_host:
        hosts.append(current_host)

    total_open = sum(
        len([p for p in h["ports"] if p["state"] == "open"]) for h in hosts
    )

    return {
        "hosts": hosts,
        "host_count": len(hosts),
        "total_open_ports": total_open,
        "findings": findings,
    }
