"""Agent memory system — persists workflows, lessons, and target notes across sessions.

Includes StrategyBandit for reward-based tool selection using Thompson Sampling.
"""

from __future__ import annotations

import json
import random
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


MEMORY_DB_PATH = Path.home() / ".arsenal" / "memory.db"

# Reward values for different finding severities
SEVERITY_REWARDS = {
    "critical": 10.0,
    "high": 5.0,
    "medium": 2.0,
    "low": 0.5,
    "info": 0.1,
}

# Tool categories for smarter recommendations
TOOL_CATEGORIES = {
    "recon": ["subfinder_enum", "amass_enum", "whois_lookup", "dig_lookup", "theharvester_scan", "shodan_search", "nmap_scan"],
    "webapp": ["nikto_scan", "nuclei_scan", "ffuf_fuzz", "gobuster_dir", "whatweb_fingerprint", "js_analyze", "dalfox_xss"],
    "exploit": ["sqlmap_scan", "searchsploit_search", "msf_search", "msf_run"],
    "network": ["nmap_scan", "crackmapexec_scan"],
    "bruteforce": ["hydra_brute", "medusa_brute", "john_crack", "hashcat_crack"],
}

# Which tools are appropriate for which task types
TOOL_TASK_AFFINITY = {
    "subfinder_enum": ["recon"],
    "amass_enum": ["recon"],
    "whois_lookup": ["recon"],
    "dig_lookup": ["recon"],
    "theharvester_scan": ["recon"],
    "shodan_search": ["recon"],
    "nmap_scan": ["recon", "network"],
    "nikto_scan": ["webapp"],
    "nuclei_scan": ["webapp", "recon"],
    "ffuf_fuzz": ["webapp", "recon"],
    "gobuster_dir": ["webapp", "recon"],
    "whatweb_fingerprint": ["webapp", "recon"],
    "js_analyze": ["webapp"],
    "dalfox_xss": ["webapp", "exploit"],
    "sqlmap_scan": ["webapp", "exploit"],
    "searchsploit_search": ["exploit"],
    "msf_search": ["exploit"],
    "msf_run": ["exploit"],
    "crackmapexec_scan": ["network", "exploit"],
    "hydra_brute": ["bruteforce"],
    "medusa_brute": ["bruteforce"],
    "john_crack": ["bruteforce"],
    "hashcat_crack": ["bruteforce"],
}

# Tools that produce findings (rewards are tracked for these)
FINDING_TOOLS = {
    "nmap_scan", "nuclei_scan", "nikto_scan", "sqlmap_scan", "ffuf_fuzz",
    "gobuster_dir", "js_analyze", "dalfox_xss", "whatweb_fingerprint",
    "subfinder_enum", "amass_enum", "theharvester_scan", "shodan_search",
}

_SCHEMA = """\
CREATE TABLE IF NOT EXISTS workflows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_domain TEXT NOT NULL,
    tool_chain TEXT NOT NULL,
    finding_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS lessons (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    content TEXT NOT NULL,
    category TEXT NOT NULL,
    source_target TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS target_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    tech_stack TEXT,
    findings_summary TEXT,
    notes TEXT,
    last_tested TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tool_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool_name TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT 'general',
    task_type TEXT NOT NULL DEFAULT 'general',
    successes REAL NOT NULL DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 0,
    total_reward REAL NOT NULL DEFAULT 0,
    last_used TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(tool_name, target_type, task_type)
);

CREATE TABLE IF NOT EXISTS tool_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool_name TEXT NOT NULL,
    target TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT 'general',
    task_type TEXT NOT NULL DEFAULT 'general',
    context_tags TEXT,
    reward REAL NOT NULL DEFAULT 0,
    findings_count INTEGER NOT NULL DEFAULT 0,
    run_time_seconds REAL,
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

        lessons = self._conn.execute(
            "SELECT content, category FROM lessons ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        if lessons:
            lines = [f"- [{row['category']}] {row['content']}" for row in lessons]
            sections.append("### Lessons Learned\n" + "\n".join(lines))

        if target:
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
                    chain_str = " -> ".join(chain)
                except json.JSONDecodeError:
                    chain_str = row["tool_chain"]
                lines.append(f"- [{row['severity'].upper()}] {chain_str} -> {row['description']}")
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


class StrategyBandit:
    """Multi-Armed Bandit for tool selection using Thompson Sampling.

    Tracks which tools find vulnerabilities and recommends tools that
    historically perform well, while still exploring new options.

    Uses Beta(alpha, beta) conjugate prior for Bernoulli success/failure:
      alpha = prior_alpha + observed_successes
      beta  = prior_beta  + observed_failures

    High variance with little data drives exploration; low variance with
    lots of data drives exploitation. Stats are tracked per
    (tool, target_type, task_type) for context-aware learning.
    """

    # Seed priors with domain knowledge
    INITIAL_PRIORS = {
        "js_analyze": (3.0, 1.0),       # Usually finds endpoints/secrets
        "nuclei_scan": (4.0, 2.0),      # Good CVE detection
        "nmap_scan": (2.0, 1.0),        # Essential recon
        "ffuf_fuzz": (2.0, 2.0),        # Hit or miss
        "subfinder_enum": (2.0, 1.0),   # Good for subdomains
        "_default": (1.0, 1.0),         # Uniform prior
    }

    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = db_path or MEMORY_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __del__(self) -> None:
        self.close()

    def _get_prior(self, tool_name: str) -> tuple[float, float]:
        """Get initial prior (alpha, beta) for a tool."""
        return self.INITIAL_PRIORS.get(tool_name, self.INITIAL_PRIORS["_default"])

    def record_run(
        self,
        tool_name: str,
        target: str,
        findings: list[dict[str, Any]],
        run_time_seconds: float | None = None,
        target_type: str = "general",
        task_type: str = "general",
        context_tags: list[str] | None = None,
    ) -> float:
        """Record a tool run and update stats. Returns the reward earned."""
        reward = sum(SEVERITY_REWARDS.get(f.get("severity", "info").lower(), 0.1) for f in findings)
        findings_count = len(findings)
        now = _now()
        tags_json = json.dumps(context_tags) if context_tags else None

        self._conn.execute(
            "INSERT INTO tool_runs (tool_name, target, target_type, task_type, context_tags, "
            "reward, findings_count, run_time_seconds, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (tool_name, target, target_type, task_type, tags_json, reward, findings_count, run_time_seconds, now),
        )

        # Update aggregate stats — only store observed data, priors added at sample time
        success_delta = 1.0 if findings_count > 0 else 0.0
        existing = self._conn.execute(
            "SELECT id FROM tool_stats WHERE tool_name = ? AND target_type = ? AND task_type = ?",
            (tool_name, target_type, task_type),
        ).fetchone()

        if existing:
            self._conn.execute(
                "UPDATE tool_stats SET successes = successes + ?, attempts = attempts + 1, "
                "total_reward = total_reward + ?, last_used = ? WHERE id = ?",
                (success_delta, reward, now, existing["id"]),
            )
        else:
            self._conn.execute(
                "INSERT INTO tool_stats (tool_name, target_type, task_type, successes, attempts, "
                "total_reward, last_used, created_at) VALUES (?, ?, ?, ?, 1, ?, ?, ?)",
                (tool_name, target_type, task_type, success_delta, reward, now, now),
            )

        self._conn.commit()
        return reward

    def get_tool_stats(self, tool_name: str, target_type: str = "general", task_type: str = "general") -> dict[str, Any]:
        """Get stats for a specific tool in a specific context."""
        row = self._conn.execute(
            "SELECT * FROM tool_stats WHERE tool_name = ? AND target_type = ? AND task_type = ?",
            (tool_name, target_type, task_type),
        ).fetchone()

        if row:
            return dict(row)

        # Fall back to aggregated stats across task types
        agg = self._conn.execute(
            "SELECT SUM(successes) as successes, SUM(attempts) as attempts, SUM(total_reward) as total_reward "
            "FROM tool_stats WHERE tool_name = ? AND target_type = ?",
            (tool_name, target_type),
        ).fetchone()

        if agg and agg["attempts"] and agg["attempts"] > 0:
            return {
                "tool_name": tool_name, "target_type": target_type, "task_type": task_type,
                "successes": agg["successes"] or 0, "attempts": agg["attempts"],
                "total_reward": agg["total_reward"] or 0,
            }

        return {"tool_name": tool_name, "target_type": target_type, "task_type": task_type,
                "successes": 0.0, "attempts": 0, "total_reward": 0.0}

    def sample_thompson(self, tool_name: str, target_type: str = "general", task_type: str = "general") -> float:
        """Sample from Beta(prior_alpha + successes, prior_beta + failures)."""
        stats = self.get_tool_stats(tool_name, target_type, task_type)
        prior_alpha, prior_beta = self._get_prior(tool_name)
        alpha = max(0.01, prior_alpha + stats["successes"])
        beta = max(0.01, prior_beta + stats["attempts"] - stats["successes"])
        return random.betavariate(alpha, beta)

    def rank_tools(
        self,
        available_tools: list[str],
        target_type: str = "general",
        task_type: str = "general",
        top_k: int = 10,
    ) -> list[tuple[str, float, dict[str, Any]]]:
        """Rank tools using Thompson Sampling. Returns [(name, score, stats)]."""
        results = []
        for tool in available_tools:
            if task_type != "general":
                affinity = TOOL_TASK_AFFINITY.get(tool, ["general"])
                # Penalize tools outside their affinity but don't exclude (exploration)
                score = self.sample_thompson(tool, target_type, task_type)
                if task_type not in affinity and "general" not in affinity:
                    score *= 0.3
            else:
                score = self.sample_thompson(tool, target_type, task_type)

            stats = self.get_tool_stats(tool, target_type, task_type)
            results.append((tool, score, stats))

        results.sort(key=lambda x: x[1], reverse=True)
        return results[:top_k]

    def get_recommendations(
        self,
        available_tools: list[str],
        target_type: str = "general",
        task_type: str = "general",
        top_k: int = 5,
    ) -> str:
        """Get ranked tool recommendations as a formatted string for the system prompt."""
        ranked = self.rank_tools(available_tools, target_type, task_type, top_k)
        if not ranked:
            return ""

        lines = ["## Tool Recommendations (Thompson Sampling)", ""]
        context_parts = []
        if target_type != "general":
            context_parts.append(f"target: {target_type}")
        if task_type != "general":
            context_parts.append(f"task: {task_type}")
        context_str = f" ({', '.join(context_parts)})" if context_parts else ""
        lines.append(f"Ranked by historical success rate{context_str}:")
        lines.append("")

        for i, (tool, score, stats) in enumerate(ranked, 1):
            attempts = stats.get("attempts", 0)
            affinity = TOOL_TASK_AFFINITY.get(tool, ["general"])
            affinity_str = f" [{', '.join(affinity)}]"

            if attempts > 0:
                successes = stats.get("successes", 0)
                rate = (successes / attempts) * 100
                avg_reward = stats.get("total_reward", 0) / attempts
                lines.append(f"{i}. **{tool}**{affinity_str} - {rate:.0f}% hit rate ({attempts} runs), avg {avg_reward:.1f} reward/run")
            else:
                lines.append(f"{i}. **{tool}**{affinity_str} - No data yet (exploration candidate)")

        lines.append("")
        lines.append("Occasionally try unlisted tools to discover new strategies.")
        return "\n".join(lines)

    def get_all_stats(self, min_attempts: int = 0) -> list[dict[str, Any]]:
        """Get all tool stats, optionally filtered by minimum attempts."""
        rows = self._conn.execute(
            "SELECT * FROM tool_stats WHERE attempts >= ? ORDER BY total_reward DESC",
            (min_attempts,),
        ).fetchall()
        return [dict(r) for r in rows]

    def decay_old_stats(self, days: int = 30, decay_factor: float = 0.9) -> int:
        """Apply time decay to stats older than `days`. Returns count of records decayed."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
        result = self._conn.execute(
            "UPDATE tool_stats SET successes = successes * ?, total_reward = total_reward * ? "
            "WHERE last_used < ?",
            (decay_factor, decay_factor, cutoff),
        )
        self._conn.commit()
        return result.rowcount


def parse_findings_from_output(output: str) -> list[dict[str, Any]]:
    """Parse findings from tool output to calculate rewards."""
    findings = []

    severity_patterns = [
        (r'\[CRITICAL\]', 'critical'),
        (r'\[HIGH\]', 'high'),
        (r'\[MEDIUM\]', 'medium'),
        (r'\[LOW\]', 'low'),
        (r'\[INFO\]', 'info'),
        (r'severity["\s:]+critical', 'critical'),
        (r'severity["\s:]+high', 'high'),
        (r'severity["\s:]+medium', 'medium'),
        (r'severity["\s:]+low', 'low'),
        (r'severity["\s:]+info', 'info'),
    ]

    for pattern, severity in severity_patterns:
        for _ in re.findall(pattern, output, re.IGNORECASE):
            findings.append({"severity": severity})

    # JS analyzer patterns
    secrets_match = re.search(r'SECRETS FOUND \((\d+)\)', output)
    if secrets_match:
        for _ in range(int(secrets_match.group(1))):
            findings.append({"severity": "high"})

    endpoints_match = re.search(r'ENDPOINTS FOUND \((\d+)\)', output)
    if endpoints_match:
        for _ in range(int(endpoints_match.group(1))):
            findings.append({"severity": "medium"})

    # Nuclei-style: [severity] [template-id]
    for sev in re.findall(r'\[(\w+)\]\s+\[', output):
        if sev.lower() in ('critical', 'high', 'medium', 'low', 'info'):
            findings.append({"severity": sev.lower()})

    return findings


def infer_task_type(tool_name: str) -> str:
    """Infer the task type from the tool being used."""
    affinity = TOOL_TASK_AFFINITY.get(tool_name, [])
    if affinity:
        return affinity[0]
    for category, tools in TOOL_CATEGORIES.items():
        if tool_name in tools:
            return category
    return "general"


def detect_target_type(target: str) -> str:
    """Detect the type of target from its name/URL."""
    target_lower = target.lower()
    if any(x in target_lower for x in ["api.", "/api/", "graphql"]):
        return "api"
    if any(x in target_lower for x in ["wordpress", "wp-", "blog."]):
        return "wordpress"
    if any(x in target_lower for x in ["shop.", "store.", "cart", "checkout"]):
        return "ecommerce"
    if any(x in target_lower for x in [".gov", "government"]):
        return "government"
    if any(x in target_lower for x in [".bank", "finance", "trading"]):
        return "finance"
    return "webapp"


def update_context_tags(tags: list[str], output: str) -> None:
    """Extract technology indicators from tool output."""
    output_lower = output.lower()
    checks = [
        ("has_js", ["react", "angular", "vue", "webpack", "node"]),
        ("has_api", ["/api/", "graphql", "rest", "json"]),
        ("wordpress", ["wordpress", "wp-content", "wp-admin"]),
        ("has_auth", ["login", "signin", "auth", "session"]),
        ("has_upload", ["upload", "file-upload", "multipart"]),
        ("has_db", ["sql", "mysql", "postgres", "database"]),
    ]
    for tag, indicators in checks:
        if tag not in tags and any(x in output_lower for x in indicators):
            tags.append(tag)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
