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
- **Reinforcement learning** — Thompson Sampling bandit learns which tools find vulnerabilities per target type and adapts recommendations over time
- **Docker-ready** — ships as a Kali Linux container with all tools pre-installed

---

## Quick Start

> **Tip:** Arsenal works best with extended permissions so Claude can run tools without constant approval prompts. Use `claude --dangerously-skip-permissions` or configure allowlists in your Claude Code settings.

### macOS / Windows (Docker)

The security tools (nmap, sqlmap, metasploit, etc.) run inside a Kali Linux Docker container. You connect to it from your host machine.

**1. Start the server:**

```bash
git clone https://github.com/afhultin/arsenal-mcp.git
cd arsenal-mcp
docker compose up -d
```

This builds a Kali container with all 45+ tools pre-installed and starts the MCP server on port 8888.

**2. Register with Claude Code (one-time):**

```bash
claude mcp add arsenal --transport http http://localhost:8888/mcp
```

You only run this once. Claude Code remembers the server across sessions.

**3. Use it:**

Start Docker (`docker compose up -d`), then open Claude Code and ask:
> "Scan 10.0.0.0/24 for open ports and enumerate services"

The container must be running for tools to work. The `mcp add` registration is permanent — you don't need to re-add it.

**To stop the server:**

```bash
docker compose down
```

### Kali Linux (Native)

If you're already on Kali with the tools installed, you can run Arsenal directly without Docker.

```bash
git clone https://github.com/afhultin/arsenal-mcp.git
cd arsenal-mcp
pip install -e .

# Add to Claude Code (runs over stdio, no Docker needed)
claude mcp add arsenal -- python3 -m arsenal
```

### Autonomous Agent (Any Platform)

Arsenal includes a standalone agent CLI that drives pentests autonomously. Requires the MCP server to be running first (via Docker or native).

```bash
pip install -e .
export ANTHROPIC_API_KEY=your-key-here

# Interactive mode — you approve each action
arsenal-agent --server http://localhost:8888

# Auto mode — fully autonomous pentesting
arsenal-agent --server http://localhost:8888 --auto

# Custom model and turn limit
arsenal-agent --server http://localhost:8888 --model claude-sonnet-4-20250514 --max-turns 30
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

## Reinforcement Learning

The autonomous agent uses **Thompson Sampling** (multi-armed bandit) to learn which tools work best for different targets.

- **Reward tracking** — tool runs are scored based on findings: critical = 10 pts, high = 5, medium = 2, low = 0.5, info = 0.1
- **Context-aware learning** — stats tracked per (tool, target_type, task_type), so the agent learns that `nuclei_scan` works great on ecommerce sites but `js_analyze` is better for API targets
- **Exploration vs exploitation** — Beta distribution sampling ensures proven tools get prioritized while unexplored tools still get tried
- **Persistent memory** — workflows, lessons, and target notes persist in SQLite across sessions
- **Time decay** — old stats decay so the agent adapts to changing target landscapes

The agent automatically injects ranked tool recommendations into its system prompt based on bandit scores.

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
│   │   └── jobs.py           # Background job & session manager
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
│   └── memory.py             # SQLite memory + Thompson Sampling bandit
├── Dockerfile                # Kali Linux container with all tools
├── docker-compose.yml        # One-command deployment
└── pyproject.toml            # Package metadata
```

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

- **Docker** (macOS / Windows) — Docker Desktop
- **Native** (Kali Linux) — Python 3.11+ and Kali tools installed
- `ANTHROPIC_API_KEY` environment variable (for the agent CLI only)

---

## License

[MIT](LICENSE)

---

> **Disclaimer:** Arsenal is designed for authorized security testing, bug bounty hunting, and educational purposes only. Always obtain proper authorization before testing any target. The scope enforcement system is a safety feature, not a substitute for legal authorization.
