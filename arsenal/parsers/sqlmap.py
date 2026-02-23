"""SQLMap output parser."""
from __future__ import annotations

import re
from typing import Any


def parse_sqlmap(stdout: str, stderr: str) -> dict[str, Any]:
    """Parse sqlmap text output for injection points and data."""
    injections: list[dict[str, str]] = []
    databases: list[str] = []
    findings: list[dict] = []

    in_databases_section = False

    for line in stdout.splitlines():
        # Injection type detection
        inj_match = re.search(r"Type:\s*(.+)", line)
        if inj_match:
            injections.append({"type": inj_match.group(1).strip()})

        # Parameter detection
        param_match = re.search(r"Parameter:\s*(\S+)\s*\((.+?)\)", line)
        if param_match:
            findings.append({
                "title": f"SQL Injection in parameter '{param_match.group(1)}'",
                "severity": "high",
                "finding_type": "vulnerability",
                "parameter": param_match.group(1),
                "evidence": line.strip(),
                "cwe": "CWE-89",
            })

        # Database enumeration
        if "available databases" in line:
            in_databases_section = True
            continue

        if in_databases_section:
            db_match = re.match(r"\[\*\]\s+(\S+)", line)
            if db_match:
                databases.append(db_match.group(1))
            elif line.strip():
                in_databases_section = False

    return {
        "injections": injections,
        "databases": databases,
        "vulnerable": len(findings) > 0,
        "findings": findings,
    }
