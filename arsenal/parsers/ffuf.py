"""FFUF output parser — parses JSON output."""
from __future__ import annotations

import json
from typing import Any


def parse_ffuf(stdout: str, stderr: str) -> dict[str, Any]:
    """Parse ffuf JSON output."""
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        # Fallback to text parsing
        return _parse_text(stdout)

    results = []
    for result in data.get("results", []):
        results.append({
            "url": result.get("url", ""),
            "status": result.get("status", 0),
            "length": result.get("length", 0),
            "words": result.get("words", 0),
            "lines": result.get("lines", 0),
            "input": result.get("input", {}),
        })

    return {
        "results": results,
        "result_count": len(results),
        "command_line": data.get("commandline", ""),
    }


def _parse_text(stdout: str) -> dict[str, Any]:
    """Fallback text parser for ffuf output."""
    results = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("["):
            continue
        # Typical ffuf text output: "word [Status: 200, Size: 1234, Words: 56, Lines: 78]"
        parts = line.split("[Status:")
        if len(parts) == 2:
            word = parts[0].strip()
            results.append({"input": word, "raw": line})

    return {"results": results, "result_count": len(results)}
