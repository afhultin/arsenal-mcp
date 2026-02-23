"""Generic output parser — returns lines as structured data."""
from __future__ import annotations

from typing import Any


def parse_lines(stdout: str, stderr: str) -> dict[str, Any]:
    """Parse output as simple line list."""
    lines = [line for line in stdout.strip().splitlines() if line.strip()]
    stripped_stderr = stderr.strip() if stderr else None
    return {
        "lines": lines,
        "line_count": len(lines),
        "stderr": stripped_stderr if stripped_stderr else None,
    }


def parse_table(stdout: str, stderr: str) -> dict[str, Any]:
    """Parse tab/space-delimited table output."""
    lines = stdout.strip().splitlines()
    stripped_stderr = stderr.strip() if stderr else None
    if not lines:
        return {"rows": [], "stderr": stripped_stderr if stripped_stderr else None}

    rows = []
    for line in lines:
        cols = line.split()
        if cols:
            rows.append(cols)

    return {
        "rows": rows,
        "row_count": len(rows),
        "stderr": stripped_stderr if stripped_stderr else None,
    }
