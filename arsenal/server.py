"""FastMCP entry point — registers all MCP tools and starts the server."""
from __future__ import annotations

import argparse
import asyncio
import json
import logging

from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse

from arsenal.config.settings import settings
from arsenal.core.jobs import job_manager
from arsenal.core.runner import runner
from arsenal.core.scope import scope_guard
from arsenal.db import database as db
from arsenal.db.models import Finding, Severity, FindingType, ToolResult, ToolRun
from arsenal.plugins.loader import load_plugins
from arsenal.tools.base import KaliTool

# --- Tool registry -----------------------------------------------------------

from arsenal.tools.recon.nmap import NmapTool
from arsenal.tools.recon.subfinder import SubfinderTool
from arsenal.tools.recon.amass import AmassTool
from arsenal.tools.recon.whois import WhoisTool
from arsenal.tools.recon.dig import DigTool
from arsenal.tools.recon.theharvester import TheHarvesterTool
from arsenal.tools.recon.shodan import ShodanTool

from arsenal.tools.webapp.nikto import NiktoTool
from arsenal.tools.webapp.sqlmap import SqlmapTool
from arsenal.tools.webapp.ffuf import FfufTool
from arsenal.tools.webapp.gobuster import GobusterTool
from arsenal.tools.webapp.nuclei import NucleiTool
from arsenal.tools.webapp.dalfox import DalfoxTool
from arsenal.tools.webapp.whatweb import WhatWebTool
from arsenal.tools.webapp.js_analyzer import JSAnalyzerTool

from arsenal.tools.exploit.metasploit import MsfSearchTool, MsfRunTool, MsfVenomTool
from arsenal.tools.exploit.searchsploit import SearchsploitTool
from arsenal.tools.exploit.crackmapexec import CrackMapExecTool

from arsenal.tools.passwords.hydra import HydraTool
from arsenal.tools.passwords.john import JohnTool
from arsenal.tools.passwords.hashcat import HashcatTool
from arsenal.tools.passwords.medusa import MedusaTool
from arsenal.tools.passwords.cewl import CewlTool

from arsenal.tools.network.responder import ResponderTool
from arsenal.tools.network.bettercap import BettercapTool
from arsenal.tools.network.arpspoof import ArpspoofTool

from arsenal.tools.wireless.aircrack import AircrackTool
from arsenal.tools.wireless.wifite import WifiteTool

from arsenal.tools.post.linpeas import LinpeasTool
from arsenal.tools.post.bloodhound import BloodhoundTool
from arsenal.tools.post.pspy import PspyTool

logger = logging.getLogger(__name__)

# All tool instances
TOOLS: list[KaliTool] = [
    NmapTool(), SubfinderTool(), AmassTool(), WhoisTool(), DigTool(),
    TheHarvesterTool(), ShodanTool(),
    NiktoTool(), SqlmapTool(), FfufTool(), GobusterTool(), NucleiTool(),
    DalfoxTool(), WhatWebTool(), JSAnalyzerTool(),
    MsfSearchTool(), MsfRunTool(), MsfVenomTool(), SearchsploitTool(),
    CrackMapExecTool(),
    HydraTool(), JohnTool(), HashcatTool(), MedusaTool(), CewlTool(),
    ResponderTool(), BettercapTool(), ArpspoofTool(),
    AircrackTool(), WifiteTool(),
    LinpeasTool(), BloodhoundTool(), PspyTool(),
]

TOOL_MAP: dict[str, KaliTool] = {t.name: t for t in TOOLS}

# --- FastMCP app --------------------------------------------------------------

def _parse_server_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Arsenal MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "streamable-http"],
        default="stdio",
        help="MCP transport type (default: stdio)",
    )
    parser.add_argument("--host", default="0.0.0.0", help="HTTP host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8080, help="HTTP port (default: 8080)")
    return parser.parse_known_args()[0]

_server_args = _parse_server_args()

mcp = FastMCP(
    "Arsenal MCP",
    instructions="Kali Linux pentesting MCP server — exposes the full Kali toolset as MCP tools. Call configure_scope first before running any tools.",
    host=_server_args.host,
    port=_server_args.port,
)


# ── Health endpoint (used by Docker HEALTHCHECK and readiness probes) ────────


@mcp.custom_route("/health", methods=["GET"])
async def health_check(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


# ── Helper to serialize ToolResult ────────────────────────────────────────────

def _result_to_str(result: ToolResult) -> str:
    """Convert ToolResult to a readable string for MCP responses."""
    parts = [f"Tool: {result.tool}", f"Target: {result.target}", f"Command: {result.command}"]
    if result.job_id:
        parts.append(f"Job ID: {result.job_id}")
    if result.exit_code is not None:
        parts.append(f"Exit code: {result.exit_code}")
    if result.duration_seconds is not None:
        parts.append(f"Duration: {result.duration_seconds:.1f}s")
    parts.append(f"\n{result.raw_output}")
    if result.stderr:
        parts.append(f"\nSTDERR:\n{result.stderr}")
    if result.parsed:
        try:
            parts.append(f"\nParsed:\n{json.dumps(result.parsed, indent=2, default=str)}")
        except (TypeError, ValueError):
            parts.append(f"\nParsed:\n{result.parsed}")
    if result.findings:
        parts.append(f"\nFindings ({len(result.findings)}):")
        for finding in result.findings:
            parts.append(f"  [{finding.severity}] {finding.title}")
    return "\n".join(parts)


# ── Infrastructure tools ─────────────────────────────────────────────────────

@mcp.tool()
async def configure_scope(
    targets: list[str],
    exclusions: list[str] | None = None,
    session_name: str = "",
) -> str:
    """Configure authorized scope. MUST be called before any tool execution.

    Args:
        targets: List of in-scope targets (domains, IPs, CIDR ranges, wildcards like *.example.com)
        exclusions: Optional list of targets to exclude
        session_name: Optional session name for tracking
    """
    scope_guard.configure(targets, exclusions)
    name = session_name or settings.session_name
    return (
        f"Scope configured for session '{name}'.\n"
        f"Targets: {', '.join(scope_guard.targets)}\n"
        f"Exclusions: {', '.join(scope_guard.exclusions) or 'none'}"
    )


@mcp.tool()
async def check_scope(target: str) -> str:
    """Check if a target is within the configured scope.

    Args:
        target: The target to check (domain, IP, URL, CIDR)
    """
    allowed, reason = scope_guard.validate(target)
    status = "IN SCOPE" if allowed else "OUT OF SCOPE"
    return f"{status}: {target}\n{reason}"


@mcp.tool()
async def list_tools() -> str:
    """List all available Kali tools and their installation status."""
    categories: dict[str, list[dict]] = {}
    for tool in TOOLS:
        cat = tool.category
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(tool.get_info())

    lines = ["Arsenal MCP — Available Tools\n"]
    for cat, tools in sorted(categories.items()):
        lines.append(f"\n## {cat.upper()}")
        for t in tools:
            status = "✓" if t["available"] else "✗"
            lines.append(f"  [{status}] {t['name']} ({t['binary']}) — {t['description']}")
    return "\n".join(lines)


@mcp.tool()
async def job_status(job_id: str) -> str:
    """Check status of a background job.

    Args:
        job_id: The job ID returned from a background tool execution
    """
    job = job_manager.get_job(job_id)
    if not job:
        return f"Job '{job_id}' not found."
    info = job.to_dict()
    result = json.dumps(info, indent=2)
    if job.status.value in ("completed", "failed"):
        result += f"\n\nSTDOUT:\n{job.stdout[-4000:]}"
        if job.stderr:
            result += f"\n\nSTDERR:\n{job.stderr[-2000:]}"
    return result


@mcp.tool()
async def list_jobs() -> str:
    """List all background jobs and interactive sessions."""
    jobs = job_manager.list_jobs()
    sessions = job_manager.list_sessions()
    parts = ["Background Jobs:"]
    if jobs:
        for j in jobs:
            parts.append(f"  [{j['status']}] {j['id']} — {j['tool']} → {j['target']}")
    else:
        parts.append("  (none)")
    parts.append("\nInteractive Sessions:")
    if sessions:
        for s in sessions:
            alive = "alive" if s["alive"] else "exited"
            parts.append(f"  [{alive}] {s['id']} — {s['tool']}")
    else:
        parts.append("  (none)")
    return "\n".join(parts)


@mcp.tool()
async def cancel_job(job_id: str) -> str:
    """Cancel a running background job.

    Args:
        job_id: The job ID to cancel
    """
    success = await job_manager.cancel_job(job_id)
    return f"Job '{job_id}' cancelled." if success else f"Job '{job_id}' not found or already finished."


@mcp.tool()
async def session_send(session_id: str, command: str) -> str:
    """Send a command to an interactive session (e.g., msfconsole).

    Args:
        session_id: The session ID
        command: The command to send
    """
    return await job_manager.session_send(session_id, command)


@mcp.tool()
async def session_close(session_id: str) -> str:
    """Close an interactive session.

    Args:
        session_id: The session ID to close
    """
    success = await job_manager.session_close(session_id)
    return f"Session '{session_id}' closed." if success else f"Session '{session_id}' not found."


@mcp.tool()
async def save_finding(
    title: str,
    severity: str = "info",
    finding_type: str = "information",
    target: str = "",
    url: str = "",
    parameter: str = "",
    evidence: str = "",
    description: str = "",
    cwe: str = "",
    cvss: float | None = None,
    tool: str = "manual",
) -> str:
    """Manually save a security finding.

    Args:
        title: Finding title
        severity: Severity level (critical/high/medium/low/info)
        finding_type: Type (vulnerability/misconfiguration/information/credential/service)
        target: Affected target
        url: Affected URL
        parameter: Vulnerable parameter
        evidence: Evidence/proof
        description: Detailed description
        cwe: CWE identifier
        cvss: CVSS score
        tool: Tool that found it
    """
    finding = Finding(
        title=title,
        severity=Severity(severity),
        finding_type=FindingType(finding_type),
        target=target,
        url=url,
        parameter=parameter,
        evidence=evidence,
        description=description,
        cwe=cwe,
        cvss=cvss,
        tool=tool,
    )
    finding_id = await db.save_finding(finding)
    return f"Finding saved (ID: {finding_id}): [{severity.upper()}] {title}"


@mcp.tool()
async def list_findings(
    severity: str | None = None,
    tool: str | None = None,
    target: str | None = None,
    limit: int = 50,
) -> str:
    """Query saved findings with optional filters.

    Args:
        severity: Filter by severity (critical/high/medium/low/info)
        tool: Filter by tool name
        target: Filter by target (partial match)
        limit: Max results to return
    """
    findings = await db.get_findings(severity=severity, tool=tool, target=target, limit=limit)
    if not findings:
        return "No findings found."
    lines = [f"Findings ({len(findings)}):"]
    for finding in findings:
        lines.append(
            f"  #{finding['id']} [{finding['severity'].upper()}] {finding['title']} "
            f"(target: {finding['target']}, tool: {finding['tool']})"
        )
    return "\n".join(lines)


@mcp.tool()
async def generate_report(output_format: str = "markdown") -> str:
    """Generate a report of all findings and tool runs.

    Args:
        output_format: Output format — 'markdown' or 'json'
    """
    findings = await db.get_findings(limit=500)
    tool_runs = await db.get_tool_runs(limit=200)

    if output_format == "json":
        return json.dumps({"findings": findings, "tool_runs": tool_runs}, indent=2, default=str)

    # Markdown report
    lines = ["# Arsenal Security Assessment Report\n"]
    lines.append(f"**Scope:** {', '.join(scope_guard.targets) or 'not configured'}\n")

    # Summary
    sev_counts: dict[str, int] = {}
    for finding in findings:
        sev_name = finding.get("severity", "info")
        sev_counts[sev_name] = sev_counts.get(sev_name, 0) + 1
    lines.append("## Summary")
    lines.append(f"- Total findings: {len(findings)}")
    for sev_name in ["critical", "high", "medium", "low", "info"]:
        if count := sev_counts.get(sev_name, 0):
            lines.append(f"- {sev_name.upper()}: {count}")
    lines.append(f"- Total tool runs: {len(tool_runs)}\n")

    # Findings by severity
    lines.append("## Findings\n")
    for sev in ["critical", "high", "medium", "low", "info"]:
        sev_findings = [finding for finding in findings if finding.get("severity") == sev]
        if not sev_findings:
            continue
        lines.append(f"### {sev.upper()}\n")
        for finding in sev_findings:
            lines.append(f"**{finding['title']}**")
            if finding.get("target"):
                lines.append(f"- Target: {finding['target']}")
            if finding.get("url"):
                lines.append(f"- URL: {finding['url']}")
            if finding.get("cwe"):
                lines.append(f"- CWE: {finding['cwe']}")
            if finding.get("description"):
                lines.append(f"- Description: {finding['description']}")
            if finding.get("evidence"):
                lines.append(f"- Evidence: `{finding['evidence'][:200]}`")
            lines.append("")

    # Tool run log
    lines.append("## Tool Run Log\n")
    lines.append("| Tool | Target | Exit Code | Duration |")
    lines.append("|------|--------|-----------|----------|")
    for r in tool_runs:
        dur = f"{r['duration_seconds']:.1f}s" if r.get("duration_seconds") else "N/A"
        lines.append(f"| {r['tool_name']} | {r['target']} | {r.get('exit_code', 'N/A')} | {dur} |")

    return "\n".join(lines)


# ── Recon tools ──────────────────────────────────────────────────────────────

@mcp.tool()
async def nmap_scan(
    target: str,
    ports: str = "",
    scan_type: str = "",
    scripts: str = "",
    timing: str = "",
    service_version: bool = False,
    os_detection: bool = False,
    extra_args: str = "",
    background: bool = False,
) -> str:
    """Run an nmap scan against a target.

    Args:
        target: Target IP, hostname, or CIDR range
        ports: Port specification (e.g., "80,443", "1-1000", "-")
        scan_type: Scan type flag (S=SYN, T=TCP connect, U=UDP, A=aggressive)
        scripts: NSE scripts to run (e.g., "vuln", "default,safe")
        timing: Timing template 0-5 (0=paranoid, 5=insane)
        service_version: Enable service version detection (-sV)
        os_detection: Enable OS detection (-O)
        extra_args: Additional raw nmap arguments
        background: Run in background and return job ID
    """
    result = await runner.run(
        TOOL_MAP["nmap_scan"], target, background=background,
        ports=ports, scan_type=scan_type, scripts=scripts, timing=timing,
        service_version=service_version, os_detection=os_detection, extra_args=extra_args,
    )
    return _result_to_str(result)


@mcp.tool()
async def subfinder_enum(target: str, recursive: bool = False, sources: str = "") -> str:
    """Enumerate subdomains using passive sources.

    Args:
        target: Root domain to enumerate (e.g., example.com)
        recursive: Enable recursive subdomain enumeration
        sources: Comma-separated list of sources to use
    """
    result = await runner.run(TOOL_MAP["subfinder_enum"], target, recursive=recursive, sources=sources)
    return _result_to_str(result)


@mcp.tool()
async def amass_enum(target: str, passive_only: bool = False, timeout: int = 0) -> str:
    """Run Amass subdomain enumeration.

    Args:
        target: Root domain to enumerate
        passive_only: Use only passive collection (no DNS resolution)
        timeout: Timeout in minutes (0 = no timeout)
    """
    result = await runner.run(TOOL_MAP["amass_enum"], target, passive_only=passive_only, timeout=timeout)
    return _result_to_str(result)


@mcp.tool()
async def whois_lookup(target: str) -> str:
    """Perform a WHOIS lookup on a domain or IP.

    Args:
        target: Domain or IP to look up
    """
    result = await runner.run(TOOL_MAP["whois_lookup"], target)
    return _result_to_str(result)


@mcp.tool()
async def dig_lookup(target: str, record_type: str = "", short: bool = False) -> str:
    """Perform DNS lookups using dig.

    Args:
        target: Domain to query
        record_type: DNS record type (A, AAAA, MX, NS, TXT, CNAME, SOA, ANY)
        short: Return only the answer (short mode)
    """
    result = await runner.run(TOOL_MAP["dig_lookup"], target, record_type=record_type, short=short)
    return _result_to_str(result)


@mcp.tool()
async def theharvester_scan(target: str, source: str = "all", limit: int = 0) -> str:
    """Harvest emails, subdomains, and names from public sources.

    Args:
        target: Domain to harvest
        source: Data source (all, google, bing, linkedin, etc.)
        limit: Limit number of results
    """
    result = await runner.run(TOOL_MAP["theharvester_scan"], target, source=source, limit=limit)
    return _result_to_str(result)


@mcp.tool()
async def shodan_search(query: str, subcmd: str = "search", limit: int = 10) -> str:
    """Search Shodan for hosts and services.

    Args:
        query: Shodan search query or IP for host lookup
        subcmd: Shodan subcommand (search, host, count, domain)
        limit: Maximum number of results
    """
    result = await runner.run(TOOL_MAP["shodan_search"], query, subcmd=subcmd, limit=limit)
    return _result_to_str(result)


# ── Web app tools ────────────────────────────────────────────────────────────

@mcp.tool()
async def nikto_scan(
    target: str, tuning: str = "", ssl: bool = False, background: bool = False,
) -> str:
    """Run Nikto web server scanner.

    Args:
        target: Target URL or host
        tuning: Scan tuning options
        ssl: Force SSL
        background: Run in background
    """
    result = await runner.run(TOOL_MAP["nikto_scan"], target, background=background, tuning=tuning, ssl=ssl)
    return _result_to_str(result)


@mcp.tool()
async def sqlmap_scan(
    url: str,
    parameter: str = "",
    level: int = 0,
    risk: int = 0,
    batch: bool = True,
    dbs: bool = False,
    tables: bool = False,
    database: str = "",
    extra_args: str = "",
    background: bool = False,
) -> str:
    """Run SQLMap for SQL injection testing.

    Args:
        url: Target URL with parameters (e.g., http://target.com/page?id=1)
        parameter: Specific parameter to test
        level: Test level 1-5 (default: 1)
        risk: Risk level 1-3 (default: 1)
        batch: Run in non-interactive (batch) mode
        dbs: Enumerate databases
        tables: Enumerate tables
        database: Database name for table enumeration
        extra_args: Additional sqlmap arguments
        background: Run in background
    """
    result = await runner.run(
        TOOL_MAP["sqlmap_scan"], url, background=background,
        parameter=parameter, level=level, risk=risk, batch=batch,
        dbs=dbs, tables=tables, database=database, extra_args=extra_args,
    )
    return _result_to_str(result)


@mcp.tool()
async def ffuf_fuzz(
    url: str,
    wordlist: str = "",
    extensions: str = "",
    filter_codes: str = "",
    filter_size: str = "",
    match_codes: str = "",
    threads: int = 0,
    rate: int = 0,
) -> str:
    """Run FFUF web fuzzer for directory/file discovery.

    Args:
        url: Target URL with FUZZ keyword (e.g., http://target.com/FUZZ)
        wordlist: Path to wordlist file
        extensions: File extensions to append (e.g., ".php,.html,.txt")
        filter_codes: HTTP status codes to filter out (e.g., "404,403")
        filter_size: Response sizes to filter out
        match_codes: HTTP status codes to match (e.g., "200,301")
        threads: Number of concurrent threads
        rate: Requests per second rate limit
    """
    result = await runner.run(
        TOOL_MAP["ffuf_fuzz"], url,
        wordlist=wordlist, extensions=extensions, filter_codes=filter_codes,
        filter_size=filter_size, match_codes=match_codes, threads=threads, rate=rate,
    )
    return _result_to_str(result)


@mcp.tool()
async def gobuster_dir(
    url: str,
    wordlist: str = "",
    extensions: str = "",
    status_codes: str = "",
    threads: int = 0,
    mode: str = "dir",
) -> str:
    """Run Gobuster for directory/file brute-forcing.

    Args:
        url: Target URL
        wordlist: Path to wordlist
        extensions: File extensions (e.g., "php,html,txt")
        status_codes: Positive status codes
        threads: Number of concurrent threads
        mode: Gobuster mode (dir, dns, vhost, fuzz)
    """
    result = await runner.run(
        TOOL_MAP["gobuster_dir"], url,
        wordlist=wordlist, extensions=extensions, status_codes=status_codes,
        threads=threads, mode=mode,
    )
    return _result_to_str(result)


@mcp.tool()
async def nuclei_scan(
    target: str,
    templates: str = "",
    severity: str = "",
    tags: str = "",
    new_templates: bool = False,
    rate_limit: int = 0,
    background: bool = False,
) -> str:
    """Run Nuclei vulnerability scanner.

    Args:
        target: Target URL or host
        templates: Specific template paths or directories
        severity: Filter by severity (critical,high,medium,low,info)
        tags: Filter by tags (e.g., "cve,rce")
        new_templates: Only run new/updated templates
        rate_limit: Max requests per second
        background: Run in background
    """
    result = await runner.run(
        TOOL_MAP["nuclei_scan"], target, background=background,
        templates=templates, severity=severity, tags=tags,
        new_templates=new_templates, rate_limit=rate_limit,
    )
    return _result_to_str(result)


@mcp.tool()
async def dalfox_xss(url: str, parameter: str = "", blind: str = "") -> str:
    """Run DalFox XSS scanner.

    Args:
        url: Target URL with parameters
        parameter: Specific parameter to test
        blind: Blind XSS callback URL
    """
    result = await runner.run(TOOL_MAP["dalfox_xss"], url, parameter=parameter, blind=blind)
    return _result_to_str(result)


@mcp.tool()
async def whatweb_fingerprint(target: str, aggression: int = 1) -> str:
    """Fingerprint web technologies on a target.

    Args:
        target: Target URL
        aggression: Aggression level 1-4
    """
    result = await runner.run(TOOL_MAP["whatweb_fingerprint"], target, aggression=aggression)
    return _result_to_str(result)


@mcp.tool()
async def js_analyze(target: str, max_files: int = 30, crawl_depth: int = 2) -> str:
    """Analyze JavaScript files for secrets, API keys, and hidden endpoints.

    HIGH VALUE TOOL - Finds hardcoded credentials and undocumented APIs.

    Args:
        target: Target URL to analyze (e.g., https://example.com)
        max_files: Maximum JS files to analyze (default 30)
        crawl_depth: How deep to crawl for JS files (default 2)

    Returns:
        Discovered secrets, endpoints, and sensitive data from JS files.
    """
    try:
        js_tool: JSAnalyzerTool = TOOL_MAP["js_analyzer"]  # type: ignore[assignment]
        results = await js_tool.run_analysis(target, max_files=max_files, crawl_depth=crawl_depth)

        # Format output
        lines = [
            f"JS Analysis: {target}",
            f"Files Found: {results['js_files_found']}",
            f"Files Analyzed: {results['js_files_analyzed']}",
            "",
        ]

        if results["secrets"]:
            lines.append(f"SECRETS FOUND ({len(results['secrets'])}):")
            for s in results["secrets"][:20]:
                lines.append(f"  [{s['severity'].upper()}] {s['type']}: {s['value'][:60]}...")
            lines.append("")

        if results["endpoints"]:
            lines.append(f"ENDPOINTS FOUND ({len(results['endpoints'])}):")
            # Deduplicate
            seen = set()
            for e in results["endpoints"]:
                if e['value'] not in seen:
                    seen.add(e['value'])
                    lines.append(f"  [{e['severity'].upper()}] {e['value']}")
            lines.append("")

        if results["sensitive_data"]:
            lines.append(f"SENSITIVE DATA ({len(results['sensitive_data'])}):")
            for s in results["sensitive_data"][:10]:
                lines.append(f"  [{s['severity'].upper()}] {s['type']}: {s['value'][:60]}")
            lines.append("")

        # Save findings
        for finding_data in results.get("findings", []):
            finding_data.pop("tool", None)
            finding = Finding(**finding_data, tool="js_analyzer")
            await db.save_finding(finding)

        if results["findings"]:
            lines.append(f"Saved {len(results['findings'])} findings to database.")

        return "\n".join(lines)

    except Exception as e:
        logger.exception("JS analysis failed for target: %s", target)
        return f"JS Analysis failed: {str(e)}"


# ── Exploitation tools ───────────────────────────────────────────────────────

@mcp.tool()
async def searchsploit_search(query: str, exact: bool = False, www: bool = False) -> str:
    """Search Exploit-DB for exploits matching a query.

    Args:
        query: Search query (e.g., "apache 2.4", "WordPress 5")
        exact: Use exact match
        www: Show Exploit-DB URLs instead of local paths
    """
    result = await runner.run(TOOL_MAP["searchsploit_search"], query, exact=exact, www=www)
    return _result_to_str(result)


@mcp.tool()
async def msf_search(query: str, module_type: str = "") -> str:
    """Search Metasploit modules.

    Args:
        query: Search query
        module_type: Module type filter (exploit, auxiliary, post, payload)
    """
    result = await runner.run(TOOL_MAP["msf_search"], query, module_type=module_type)
    return _result_to_str(result)


@mcp.tool()
async def msf_run(
    module_path: str,
    options: dict[str, str] | None = None,
    payload: str = "",
) -> str:
    """Run a Metasploit module (runs in background).

    Args:
        module_path: Full module path (e.g., exploit/windows/smb/ms17_010_eternalblue)
        options: Module options as key-value pairs (e.g., {"RHOSTS": "target", "RPORT": "445"})
        payload: Payload to use
    """
    result = await runner.run(
        TOOL_MAP["msf_run"], module_path,
        options=options or {}, payload=payload,
    )
    return _result_to_str(result)


@mcp.tool()
async def msfvenom_generate(
    payload: str,
    lhost: str = "",
    lport: str = "",
    output_format: str = "",
    encoder: str = "",
    iterations: int = 0,
    output: str = "",
) -> str:
    """Generate a Metasploit payload with msfvenom.

    Args:
        payload: Payload name (e.g., windows/meterpreter/reverse_tcp)
        lhost: Listener host
        lport: Listener port
        output_format: Output format (exe, elf, raw, python, etc.)
        encoder: Encoder to use
        iterations: Encoding iterations
        output: Output file path
    """
    result = await runner.run(
        TOOL_MAP["msfvenom_generate"], payload,
        lhost=lhost, lport=lport, format=output_format,
        encoder=encoder, iterations=iterations, output=output,
    )
    return _result_to_str(result)


@mcp.tool()
async def crackmapexec_scan(
    target: str,
    protocol: str = "smb",
    username: str = "",
    password: str = "",
    domain: str = "",
    shares: bool = False,
    sam: bool = False,
    module: str = "",
) -> str:
    """Run CrackMapExec against a target.

    Args:
        target: Target IP or range
        protocol: Protocol (smb, winrm, ssh, mssql, ldap)
        username: Username for authentication
        password: Password for authentication
        domain: Active Directory domain
        shares: Enumerate shares
        sam: Dump SAM hashes
        module: CrackMapExec module to run
    """
    result = await runner.run(
        TOOL_MAP["crackmapexec_scan"], target,
        protocol=protocol, username=username, password=password,
        domain=domain, shares=shares, sam=sam, module=module,
    )
    return _result_to_str(result)


# ── Password tools ───────────────────────────────────────────────────────────

@mcp.tool()
async def hydra_brute(
    target: str,
    service: str = "ssh",
    username: str = "",
    username_list: str = "",
    password: str = "",
    password_list: str = "",
    threads: int = 0,
) -> str:
    """Run Hydra online password brute-forcer.

    Args:
        target: Target host
        service: Service to attack (ssh, ftp, http-get, smb, etc.)
        username: Single username
        username_list: Path to username wordlist
        password: Single password
        password_list: Path to password wordlist
        threads: Number of parallel threads
    """
    result = await runner.run(
        TOOL_MAP["hydra_brute"], target,
        service=service, username=username, username_list=username_list,
        password=password, password_list=password_list, threads=threads,
    )
    return _result_to_str(result)


@mcp.tool()
async def john_crack(
    hash_file: str,
    wordlist: str = "",
    hash_format: str = "",
    rules: str = "",
    show: bool = False,
) -> str:
    """Run John the Ripper to crack password hashes.

    Args:
        hash_file: Path to file containing hashes
        wordlist: Path to wordlist
        hash_format: Hash format (e.g., raw-md5, sha256crypt, bcrypt)
        rules: Wordlist rules to apply
        show: Show already-cracked passwords
    """
    result = await runner.run(
        TOOL_MAP["john_crack"], hash_file,
        wordlist=wordlist, format=hash_format, rules=rules, show=show,
    )
    return _result_to_str(result)


@mcp.tool()
async def hashcat_crack(
    hash_file: str,
    hash_type: str = "",
    wordlist: str = "",
    rules: str = "",
    attack_mode: str = "0",
    show: bool = False,
) -> str:
    """Run Hashcat GPU-accelerated hash cracker.

    Args:
        hash_file: Path to file containing hashes
        hash_type: Hash type code (e.g., 0=MD5, 100=SHA1, 1000=NTLM)
        wordlist: Path to wordlist
        rules: Path to rules file
        attack_mode: Attack mode (0=straight, 1=combination, 3=brute-force)
        show: Show cracked hashes
    """
    result = await runner.run(
        TOOL_MAP["hashcat_crack"], hash_file,
        hash_type=hash_type, wordlist=wordlist, rules=rules,
        attack_mode=attack_mode, show=show,
    )
    return _result_to_str(result)


@mcp.tool()
async def medusa_brute(
    target: str,
    module: str = "ssh",
    username: str = "",
    username_list: str = "",
    password: str = "",
    password_list: str = "",
    threads: int = 0,
) -> str:
    """Run Medusa parallel network login brute-forcer.

    Args:
        target: Target host
        module: Service module (ssh, ftp, http, smb, etc.)
        username: Single username
        username_list: Path to username file
        password: Single password
        password_list: Path to password file
        threads: Number of parallel connections
    """
    result = await runner.run(
        TOOL_MAP["medusa_brute"], target,
        module=module, username=username, username_list=username_list,
        password=password, password_list=password_list, threads=threads,
    )
    return _result_to_str(result)


@mcp.tool()
async def cewl_wordlist(
    target: str,
    depth: int = 0,
    min_length: int = 0,
    with_numbers: bool = False,
    emails: bool = False,
    output: str = "",
) -> str:
    """Generate a custom wordlist from a website using CeWL.

    Args:
        target: Target URL to spider
        depth: Spider depth
        min_length: Minimum word length
        with_numbers: Include words with numbers
        emails: Also extract email addresses
        output: Output file path
    """
    result = await runner.run(
        TOOL_MAP["cewl_wordlist"], target,
        depth=depth, min_length=min_length, with_numbers=with_numbers,
        emails=emails, output=output,
    )
    return _result_to_str(result)


# ── Network tools ────────────────────────────────────────────────────────────

@mcp.tool()
async def responder_listen(
    interface: str, analyze: bool = False, wpad: bool = False,
) -> str:
    """Start Responder for LLMNR/NBT-NS poisoning (runs in background).

    Args:
        interface: Network interface (e.g., eth0)
        analyze: Analyze mode only (no poisoning)
        wpad: Enable WPAD rogue proxy
    """
    result = await runner.run(
        TOOL_MAP["responder_listen"], interface, analyze=analyze, wpad=wpad,
    )
    return _result_to_str(result)


@mcp.tool()
async def bettercap_attack(
    interface: str = "", caplet: str = "", eval_cmd: str = "",
) -> str:
    """Start Bettercap network attack framework (interactive session).

    Args:
        interface: Network interface
        caplet: Caplet file to load
        eval_cmd: Commands to evaluate on start
    """
    target = interface or "default"
    result = await runner.run(
        TOOL_MAP["bettercap_attack"], target,
        interface=interface, caplet=caplet, eval=eval_cmd,
    )
    return _result_to_str(result)


@mcp.tool()
async def arpspoof_attack(
    target: str, gateway: str = "", interface: str = "",
) -> str:
    """Start ARP spoofing attack (runs in background).

    Args:
        target: Target IP to spoof
        gateway: Gateway IP
        interface: Network interface
    """
    result = await runner.run(
        TOOL_MAP["arpspoof_attack"], target, gateway=gateway, interface=interface,
    )
    return _result_to_str(result)


# ── Wireless tools ───────────────────────────────────────────────────────────

@mcp.tool()
async def aircrack_crack(
    capture_file: str, wordlist: str = "", bssid: str = "",
) -> str:
    """Crack WiFi WEP/WPA keys from a capture file.

    Args:
        capture_file: Path to .cap capture file
        wordlist: Path to wordlist
        bssid: Target BSSID
    """
    result = await runner.run(
        TOOL_MAP["aircrack_crack"], capture_file, wordlist=wordlist, bssid=bssid,
    )
    return _result_to_str(result)


@mcp.tool()
async def wifite_attack(
    interface: str = "", bssid: str = "", wpa: bool = False, wep: bool = False,
) -> str:
    """Start Wifite automated wireless auditor (interactive session).

    Args:
        interface: Wireless interface
        bssid: Target BSSID
        wpa: Target WPA networks only
        wep: Target WEP networks only
    """
    target = bssid or interface or "auto"
    result = await runner.run(
        TOOL_MAP["wifite_attack"], target,
        interface=interface, bssid=bssid, wpa=wpa, wep=wep,
    )
    return _result_to_str(result)


# ── Post-exploitation tools ──────────────────────────────────────────────────

@mcp.tool()
async def linpeas_enum(checks: str = "", quiet: bool = False) -> str:
    """Run LinPEAS privilege escalation enumeration (runs in background).

    Args:
        checks: Specific check categories to run
        quiet: Quiet mode (less output)
    """
    result = await runner.run(
        TOOL_MAP["linpeas_enum"], "localhost", checks=checks, quiet=quiet,
    )
    return _result_to_str(result)


@mcp.tool()
async def bloodhound_collect(
    domain: str,
    username: str = "",
    password: str = "",
    collection: str = "All",
    nameserver: str = "",
) -> str:
    """Run BloodHound data collector for Active Directory.

    Args:
        domain: Target AD domain
        username: Domain username
        password: Domain password
        collection: Collection method (All, Group, LocalAdmin, Session, etc.)
        nameserver: DNS server to use
    """
    result = await runner.run(
        TOOL_MAP["bloodhound_collect"], domain,
        username=username, password=password, collection=collection, nameserver=nameserver,
    )
    return _result_to_str(result)


@mcp.tool()
async def pspy_monitor() -> str:
    """Start pspy process monitor (runs in background). Monitors for cron jobs and running processes without root."""
    result = await runner.run(TOOL_MAP["pspy_monitor"], "localhost")
    return _result_to_str(result)


# ── Generic command execution ────────────────────────────────────────────────

@mcp.tool()
async def exec_command(command: str, timeout: int = 120) -> str:
    """Execute an arbitrary shell command inside the Kali container.

    Use this for anything not covered by dedicated tools: ssh, curl, wget,
    cat, scp, python scripts, privesc, reading files on remote targets, etc.

    Scope is still enforced — configure_scope must have been called first.

    Args:
        command: The shell command to execute (e.g., "ssh user@target cat /etc/passwd")
        timeout: Max seconds to wait (default 120)
    """
    if not scope_guard.is_configured:
        return "ERROR: Scope not configured. Call configure_scope first."

    try:
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return f"Command timed out after {timeout}s: {command}"
    except Exception as e:
        logger.exception("exec_command failed for: %s", command)
        return f"Execution error: {e}"

    stdout = stdout_bytes.decode(errors="replace")
    stderr = stderr_bytes.decode(errors="replace")

    parts = [f"$ {command}", f"Exit code: {proc.returncode}"]
    if stdout.strip():
        parts.append(f"\n{stdout.strip()}")
    if stderr.strip():
        parts.append(f"\nSTDERR:\n{stderr.strip()}")

    # Log the run
    run = ToolRun(
        tool_name="exec_command",
        target="local",
        command=command,
        stdout=stdout,
        stderr=stderr,
        exit_code=proc.returncode,
    )
    await db.save_tool_run(run)

    return "\n".join(parts)


# ── Entry point ──────────────────────────────────────────────────────────────

def main() -> None:
    """Start the Arsenal MCP server."""
    logging.basicConfig(level=logging.INFO)

    # Load plugins
    loaded = load_plugins(mcp, runner, settings.resolved_plugin_dir)
    if loaded:
        logger.info("Loaded plugins: %s", ", ".join(loaded))

    mcp.run(transport=_server_args.transport)


if __name__ == "__main__":
    main()
