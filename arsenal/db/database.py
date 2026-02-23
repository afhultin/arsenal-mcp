"""SQLite database via aiosqlite for sessions, findings, and tool runs."""
from __future__ import annotations

import aiosqlite

from arsenal.config.settings import settings
from arsenal.db.models import Finding, ToolRun

_db: aiosqlite.Connection | None = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    scope_targets TEXT DEFAULT '[]',
    scope_exclusions TEXT DEFAULT '[]',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tool_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER DEFAULT 1,
    tool_name TEXT NOT NULL,
    target TEXT NOT NULL,
    command TEXT NOT NULL,
    stdout TEXT DEFAULT '',
    stderr TEXT DEFAULT '',
    exit_code INTEGER,
    duration_seconds REAL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER DEFAULT 1,
    title TEXT NOT NULL,
    severity TEXT DEFAULT 'info',
    finding_type TEXT DEFAULT 'information',
    target TEXT DEFAULT '',
    url TEXT DEFAULT '',
    parameter TEXT DEFAULT '',
    evidence TEXT DEFAULT '',
    description TEXT DEFAULT '',
    cwe TEXT DEFAULT '',
    cvss REAL,
    tool TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

"""


async def get_db() -> aiosqlite.Connection:
    global _db
    if _db is None:
        db_path = settings.database.resolved_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        _db = await aiosqlite.connect(str(db_path))
        _db.row_factory = aiosqlite.Row
        await _db.executescript(SCHEMA)
        await _db.commit()
    return _db


async def close_db() -> None:
    global _db
    if _db is not None:
        await _db.close()
        _db = None


async def save_tool_run(run: ToolRun) -> int:
    db = await get_db()
    cursor = await db.execute(
        """INSERT INTO tool_runs
           (session_id, tool_name, target, command, stdout, stderr, exit_code, duration_seconds, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            run.session_id,
            run.tool_name,
            run.target,
            run.command,
            run.stdout,
            run.stderr,
            run.exit_code,
            run.duration_seconds,
            run.created_at,
        ),
    )
    await db.commit()
    return cursor.lastrowid  # type: ignore[return-value]


async def save_finding(finding: Finding) -> int:
    db = await get_db()
    cursor = await db.execute(
        """INSERT INTO findings
           (session_id, title, severity, finding_type, target, url, parameter, evidence, description, cwe, cvss, tool, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            finding.session_id,
            finding.title,
            finding.severity,
            finding.finding_type,
            finding.target,
            finding.url,
            finding.parameter,
            finding.evidence,
            finding.description,
            finding.cwe,
            finding.cvss,
            finding.tool,
            finding.created_at,
        ),
    )
    await db.commit()
    return cursor.lastrowid  # type: ignore[return-value]


async def get_findings(
    session_id: int | None = None,
    severity: str | None = None,
    tool: str | None = None,
    target: str | None = None,
    limit: int = 100,
) -> list[dict]:
    db = await get_db()
    query = "SELECT * FROM findings WHERE 1=1"
    params: list = []

    if session_id is not None:
        query += " AND session_id = ?"
        params.append(session_id)
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if tool:
        query += " AND tool = ?"
        params.append(tool)
    if target:
        query += " AND target LIKE ?"
        params.append(f"%{target}%")

    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    cursor = await db.execute(query, params)
    rows = await cursor.fetchall()
    return [dict(row) for row in rows]


async def get_tool_runs(
    session_id: int | None = None,
    tool_name: str | None = None,
    limit: int = 50,
) -> list[dict]:
    db = await get_db()
    query = "SELECT id, tool_name, target, command, exit_code, duration_seconds, created_at FROM tool_runs WHERE 1=1"
    params: list = []

    if session_id is not None:
        query += " AND session_id = ?"
        params.append(session_id)
    if tool_name:
        query += " AND tool_name = ?"
        params.append(tool_name)

    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    cursor = await db.execute(query, params)
    rows = await cursor.fetchall()
    return [dict(row) for row in rows]
