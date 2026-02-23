"""Nuclei output parser — parses JSONL output into structured findings."""
from __future__ import annotations

import json
from typing import Any


def parse_nuclei(stdout: str, stderr: str) -> dict[str, Any]:
    """Parse nuclei JSON-lines output."""
    results: list[dict[str, Any]] = []
    findings: list[dict] = []

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            # Fallback: parse text output like "[severity] [template-id] url"
            if line.startswith("["):
                results.append({"raw": line})
            continue

        info = item.get("info", {})
        result = {
            "template_id": item.get("template-id", item.get("templateID", "")),
            "name": info.get("name", ""),
            "severity": info.get("severity", "info"),
            "matched_at": item.get("matched-at", item.get("matched", "")),
            "matcher_name": item.get("matcher-name", ""),
            "description": info.get("description", ""),
            "type": item.get("type", ""),
        }
        results.append(result)

        sev = result["severity"]
        findings.append({
            "title": f"[{sev.upper()}] {result['name']} ({result['template_id']})",
            "severity": "info" if sev == "unknown" else sev,
            "finding_type": "vulnerability",
            "url": result["matched_at"],
            "evidence": json.dumps(result, indent=2),
            "description": result["description"],
        })

    return {
        "results": results,
        "result_count": len(results),
        "findings": findings,
        "severity_summary": _severity_summary(results),
    }


def _severity_summary(results: list[dict]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for r in results:
        sev = r.get("severity", "info")
        summary[sev] = summary.get(sev, 0) + 1
    return summary
