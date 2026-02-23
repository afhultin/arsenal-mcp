# Arsenal MCP

**Kali Linux pentesting MCP server — exposes 45+ security tools as MCP tools for AI-assisted penetration testing.**

Arsenal turns any MCP-compatible AI client (Claude Code, Claude Desktop, or custom agents) into a full-featured penetration testing platform. It wraps Kali Linux's entire offensive toolset behind a structured, scope-enforced API with automatic finding persistence and report generation.

---

## Features

- **45+ MCP tools** spanning recon, web app testing, exploitation, password cracking, network attacks, wireless, and post-exploitation
- **DENY-by-default scope enforcement** — no tool executes until targets are explicitly authorized
- **Structured output parsing** — nmap, nuclei, ffuf, and sqlmap output is parsed into structured findings
- **Background jobs & interactive sessions** — long-running scans and tools like msfconsole run asynchronously
- **Finding persistence** — all findings saved to SQLite with severity, CWE, CVSS, and evidence
- **Report generation** — export findings as Markdown or JSON
- **Plugin system** — extend with custom tools via `~/.arsenal/plugins/`
- **Autonomous agent CLI** — built-in Claude-powered agent that drives the full pentest workflow
- **Docker-ready** — ships as a Kali Linux container with all tools pre-installed

---

## Quick Start

### Option 1: Claude Code Integration (Recommended)

```bash
# Clone and install
git clone https://github.com/afhultin/arsenal-mcp.git
cd arsenal-mcp
pip install -e .

# Add to Claude Code as an MCP server
claude mcp add arsenal -- python -m arsenal
```

Then in Claude Code, just ask:
> "Scan 10.0.0.0/24 for open ports and enumerate services"

### Option 2: Docker

```bash
docker compose up -d

# Or build manually
docker build -t arsenal-mcp .
docker run --network host --cap-add NET_RAW --cap-add NET_ADMIN arsenal-mcp
```

### Option 3: Autonomous Agent

```bash
export ANTHROPIC_API_KEY=your-key-here

# Interactive mode — you approve each action
arsenal-agent --server http://localhost:8080

# Auto mode — fully autonomous pentesting
arsenal-agent --server http://localhost:8080 --auto
```

---

## Scope Enforcement

Arsenal uses a **DENY-by-default** scope model. Every tool checks scope before execution. No target is reachable until explicitly authorized.

```
configure_scope(
    targets=["10.0.0.0/24", "*.example.com", "https://app.example.com"],
    exclusions=["10.0.0.1"]
)
```

Supports IP addresses, CIDR ranges, wildcards, and URLs.

---

## Available Tools (45)

### Infrastructure (12)

| Tool | Description |
|------|-------------|
| `configure_scope` | Set authorized targets — **must call first** |
| `check_scope` | Check if a target is in scope |
| `list_tools` | List all tools and install status |
| `job_status` | Check background job status |
| `list_jobs` | List all background jobs and sessions |
| `cancel_job` | Cancel a running background job |
| `session_send` | Send command to interactive session (msfconsole, bettercap) |
| `session_close` | Close an interactive session |
| `save_finding` | Save a security finding with severity, CWE, evidence |
| `list_findings` | Query saved findings with filters |
| `generate_report` | Generate Markdown or JSON report |
| `exec_command` | Execute a shell command (generic fallback) |

### Recon (7)

| Tool | Description |
|------|-------------|
| `nmap_scan` | Port scanning, service detection, OS fingerprinting |
| `subfinder_enum` | Passive subdomain enumeration |
| `amass_enum` | Active/passive subdomain enumeration |
| `whois_lookup` | WHOIS domain/IP lookup |
| `dig_lookup` | DNS record queries |
| `theharvester_scan` | Email, subdomain, and name harvesting |
| `shodan_search` | Shodan host and service search |

### Web App (8)

| Tool | Description |
|------|-------------|
| `nikto_scan` | Web server vulnerability scanner |
| `sqlmap_scan` | SQL injection detection and exploitation |
| `ffuf_fuzz` | Web fuzzer for directory/file/parameter discovery |
| `gobuster_dir` | Directory and file brute-forcing |
| `nuclei_scan` | Template-based vulnerability scanning |
| `dalfox_xss` | XSS vulnerability scanner |
| `whatweb_fingerprint` | Web technology fingerprinting |
| `js_analyze` | JavaScript file analysis for secrets and endpoints |

### Exploitation (5)

| Tool | Description |
|------|-------------|
| `searchsploit_search` | Exploit-DB search |
| `msf_search` | Metasploit module search |
| `msf_run` | Run Metasploit module (background) |
| `msfvenom_generate` | Generate Metasploit payloads |
| `crackmapexec_scan` | Network authentication testing |

### Passwords (5)

| Tool | Description |
|------|-------------|
| `hydra_brute` | Online password brute-forcing |
| `john_crack` | John the Ripper hash cracking |
| `hashcat_crack` | GPU-accelerated hash cracking |
| `medusa_brute` | Parallel network login brute-forcing |
| `cewl_wordlist` | Website-based wordlist generation |

### Network (3)

| Tool | Description |
|------|-------------|
| `responder_listen` | LLMNR/NBT-NS/mDNS poisoning (background) |
| `bettercap_attack` | Network attack framework (interactive) |
| `arpspoof_attack` | ARP spoofing (background) |

### Wireless (2)

| Tool | Description |
|------|-------------|
| `aircrack_crack` | WiFi WEP/WPA key cracking |
| `wifite_attack` | Automated wireless auditing (interactive) |

### Post-Exploitation (3)

| Tool | Description |
|------|-------------|
| `linpeas_enum` | Linux privilege escalation enumeration (background) |
| `bloodhound_collect` | Active Directory data collection |
| `pspy_monitor` | Process monitoring without root (background) |

---

## Architecture

```
arsenal-mcp/
├── arsenal/                  # MCP server package
│   ├── server.py             # FastMCP entry — registers all 45 tools
│   ├── config/               # Pydantic settings, YAML defaults
│   ├── core/
│   │   ├── runner.py         # Subprocess execution engine
│   │   ├── scope.py          # DENY-by-default scope guard
│   │   ├── jobs.py           # Background job & session manager
│   │   └── parsers.py        # Output parser registry
│   ├── db/
│   │   ├── database.py       # aiosqlite persistence layer
│   │   └── models.py         # Finding, ToolRun, Session models
│   ├── parsers/              # Structured output parsers (nmap, nuclei, ffuf, sqlmap)
│   ├── plugins/              # Dynamic plugin loader
│   └── tools/                # Tool wrappers organized by category
│       ├── recon/            # nmap, subfinder, amass, whois, dig, theharvester, shodan
│       ├── webapp/           # nikto, sqlmap, ffuf, gobuster, nuclei, dalfox, whatweb, js_analyzer
│       ├── exploit/          # metasploit, searchsploit, crackmapexec
│       ├── passwords/        # hydra, john, hashcat, medusa, cewl
│       ├── network/          # responder, bettercap, arpspoof
│       ├── wireless/         # aircrack, wifite
│       └── post/             # linpeas, bloodhound, pspy
├── agent/                    # Autonomous agent CLI
│   ├── agent.py              # Claude API <-> MCP tool loop
│   ├── cli.py                # Rich terminal UI
│   ├── config.py             # Agent configuration
│   └── memory.py             # SQLite memory (workflows, lessons, target notes)
├── Dockerfile                # Kali Linux container with all tools
├── docker-compose.yml        # One-command deployment
└── pyproject.toml            # Package metadata
```

---

## Autonomous Agent

Arsenal includes a standalone CLI agent that connects to the MCP server and drives pentests autonomously using Claude.

```bash
# Interactive — review and approve each action
arsenal-agent --server http://localhost:8080

# Fully autonomous
arsenal-agent --server http://localhost:8080 --auto

# Custom model and turn limit
arsenal-agent --server http://localhost:8080 --model claude-sonnet-4-20250514 --max-turns 30
```

The agent features:
- **Persistent memory** — remembers workflows, lessons learned, and target notes across sessions
- **Rich terminal UI** — color-coded output with tool call visualization
- **Auto mode** — fully autonomous pentest execution following recon-to-report methodology

---

## Plugins

Extend Arsenal with custom tools. Drop `.py` files in `~/.arsenal/plugins/`:

```python
def register(mcp, runner):
    @mcp.tool()
    async def my_custom_scanner(target: str) -> str:
        """Run my custom security scanner against a target."""
        result = await runner.run(my_tool_instance, target)
        return str(result)
```

---

## Configuration

Arsenal reads configuration from `~/.arsenal/config.yaml` with environment variable overrides:

```yaml
timeout: 300
wordlist: /usr/share/wordlists/dirb/common.txt
db_path: ~/.arsenal/arsenal.db
plugin_dir: ~/.arsenal/plugins
```

---

## Requirements

- Python 3.11+
- Kali Linux tools (installed automatically in Docker, or install individually on host)
- `ANTHROPIC_API_KEY` environment variable (for the agent CLI only)

---

## License

[MIT](LICENSE)

---

> **Disclaimer:** Arsenal is designed for authorized security testing, bug bounty hunting, and educational purposes only. Always obtain proper authorization before testing any target. The scope enforcement system is a safety feature, not a substitute for legal authorization.
