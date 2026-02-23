"""Agent memory system — persists workflows, lessons, and target notes across sessions."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


MEMORY_DB_PATH = Path.home() / ".arsenal" / "memory.db"

_SCHEMA = """\
CREATE TABLE IF NOT EXISTS workflows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_domain TEXT NOT NULL,
    tool_chain TEXT NOT NULL,       -- JSON list of tool names
    finding_type TEXT NOT NULL,     -- e.g. XSS, RCE, SQLi, info-disclosure
    severity TEXT NOT NULL,         -- critical, high, medium, low, info
    description TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS lessons (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    content TEXT NOT NULL,
    category TEXT NOT NULL,         -- recon, webapp, exploit, general
    source_target TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS target_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    tech_stack TEXT,                -- JSON list
    findings_summary TEXT,
    notes TEXT,
    last_tested TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""

class MemoryStore:
    """SQLite-backed memory store at ~/.arsenal/memory.db."""

    def __init__(self, db_path: Path = MEMORY_DB_PATH) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __del__(self) -> None:
        self.close()

    # ── Save methods ─────────────────────────────────────────────

    def save_workflow(
        self,
        target_domain: str,
        tool_chain: list[str],
        finding_type: str,
        severity: str,
        description: str,
    ) -> None:
        self._conn.execute(
            "INSERT INTO workflows (target_domain, tool_chain, finding_type, severity, description, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (target_domain, json.dumps(tool_chain), finding_type, severity.lower(), description, _now()),
        )
        self._conn.commit()

    def save_lesson(self, content: str, category: str, source_target: str | None = None) -> None:
        self._conn.execute(
            "INSERT INTO lessons (content, category, source_target, created_at) VALUES (?, ?, ?, ?)",
            (content, category.lower(), source_target, _now()),
        )
        self._conn.commit()

    def save_target_note(
        self,
        domain: str,
        tech_stack: list[str] | None = None,
        findings_summary: str | None = None,
        notes: str | None = None,
    ) -> None:
        now = _now()
        tech_json = json.dumps(tech_stack) if tech_stack else None
        # Upsert — update if domain already exists
        existing = self._conn.execute(
            "SELECT id FROM target_notes WHERE domain = ?", (domain,)
        ).fetchone()
        if existing:
            parts, params = [], []
            if tech_stack is not None:
                parts.append("tech_stack = ?")
                params.append(tech_json)
            if findings_summary is not None:
                parts.append("findings_summary = ?")
                params.append(findings_summary)
            if notes is not None:
                parts.append("notes = ?")
                params.append(notes)
            parts.append("last_tested = ?")
            params.append(now)
            params.append(existing["id"])
            self._conn.execute(f"UPDATE target_notes SET {', '.join(parts)} WHERE id = ?", params)
        else:
            self._conn.execute(
                "INSERT INTO target_notes (domain, tech_stack, findings_summary, notes, last_tested, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (domain, tech_json, findings_summary, notes, now, now),
            )
        self._conn.commit()

    # ── Query methods ────────────────────────────────────────────

    def get_relevant_memories(self, target: str | None = None, limit: int = 20) -> str:
        """Build a formatted memory block for the system prompt."""
        sections: list[str] = []

        # 1. Recent lessons
        lessons = self._conn.execute(
            "SELECT content, category FROM lessons ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        if lessons:
            lines = [f"- [{row['category']}] {row['content']}" for row in lessons]
            sections.append("### Lessons Learned\n" + "\n".join(lines))

        # 2. Target-specific notes
        if target:
            # Match exact domain or subdomains
            rows = self._conn.execute(
                "SELECT domain, tech_stack, findings_summary, notes, last_tested "
                "FROM target_notes WHERE domain = ? OR domain LIKE ? OR ? LIKE '%.' || domain "
                "ORDER BY last_tested DESC LIMIT 5",
                (target, f"%.{target}", target),
            ).fetchall()
            for row in rows:
                parts = [f"### Target Knowledge: {row['domain']}"]
                if row["tech_stack"]:
                    try:
                        stack = json.loads(row["tech_stack"])
                        parts.append(f"- Tech stack: {', '.join(stack)}")
                    except json.JSONDecodeError:
                        pass
                parts.append(f"- Last tested: {row['last_tested']}")
                if row["findings_summary"]:
                    parts.append(f"- Previous findings: {row['findings_summary']}")
                if row["notes"]:
                    parts.append(f"- Notes: {row['notes']}")
                sections.append("\n".join(parts))

        # 3. Top workflows by severity
        workflows = self._conn.execute(
            "SELECT target_domain, tool_chain, finding_type, severity, description "
            "FROM workflows ORDER BY "
            "CASE severity "
            "  WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "  WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, "
            "created_at DESC LIMIT 10",
        ).fetchall()
        if workflows:
            lines = []
            for row in workflows:
                try:
                    chain = json.loads(row["tool_chain"])
                    chain_str = " → ".join(chain)
                except json.JSONDecodeError:
                    chain_str = row["tool_chain"]
                sev = row["severity"].upper()
                lines.append(f"- [{sev}] {chain_str} → {row['description']}")
            sections.append("### Effective Workflows\n" + "\n".join(lines))

        if not sections:
            return ""
        return "## Memory\n\n" + "\n\n".join(sections)

    def list_memories(self) -> dict[str, Any]:
        """Return a summary dict for the `memory` CLI command."""
        lessons = self._conn.execute(
            "SELECT id, content, category, source_target, created_at FROM lessons ORDER BY created_at DESC"
        ).fetchall()
        workflows = self._conn.execute(
            "SELECT id, target_domain, tool_chain, finding_type, severity, description, created_at "
            "FROM workflows ORDER BY created_at DESC"
        ).fetchall()
        targets = self._conn.execute(
            "SELECT id, domain, tech_stack, findings_summary, notes, last_tested FROM target_notes ORDER BY last_tested DESC"
        ).fetchall()
        return {
            "lessons": [dict(r) for r in lessons],
            "workflows": [dict(r) for r in workflows],
            "target_notes": [dict(r) for r in targets],
        }

    def clear(self) -> None:
        """Delete all memory data."""
        self._conn.execute("DELETE FROM workflows")
        self._conn.execute("DELETE FROM lessons")
        self._conn.execute("DELETE FROM target_notes")
        self._conn.commit()


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
