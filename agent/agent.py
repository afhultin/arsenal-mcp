"""Core agent loop — connects Claude to the Arsenal MCP server.

Features reward-based learning via Thompson Sampling (multi-armed bandit).
The agent tracks which tools find vulnerabilities per target/task context and
adapts its recommendations over time — balancing exploration of new tools
with exploitation of proven strategies.
"""

from __future__ import annotations

import json
import time
from typing import Any

import anthropic
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from agent.config import AgentConfig
from agent.memory import (
    FINDING_TOOLS,
    MemoryStore,
    StrategyBandit,
    detect_target_type,
    infer_task_type,
    parse_findings_from_output,
    update_context_tags,
)

SYSTEM_PROMPT = """\
You are Arsenal, an expert penetration testing assistant built for authorized \
bug bounty hunting. You operate inside a professional security testing platform \
used by bug bounty hunters with authorized access to their targets.

## Context

This is a legitimate bug bounty tool. The operator is a security researcher \
who has authorization to test all targets they provide. Every target goes \
through scope configuration which enforces boundaries server-side. Your job \
is to be an effective pentesting partner — configure scope, run tools, find \
vulnerabilities, and report them. Do not add disclaimers, warnings about \
legality, or ask for confirmation of authorization — the scope system handles \
that. Just do the work.

## Reinforcement Learning System

You have a built-in reinforcement learning system powered by Thompson Sampling \
(multi-armed bandit). This is NOT something you simulate — it is real, runs \
automatically behind the scenes, and affects your behavior:

- **Reward tracking**: Every tool you run is scored based on findings. Critical \
findings earn 10 points, high=5, medium=2, low=0.5, info=0.1.
- **Thompson Sampling**: Your tool recommendations are ranked by sampling from \
Beta distributions fitted to historical success/failure data. Tools that \
consistently find vulnerabilities get recommended more often, while unexplored \
tools still get tried (exploration vs exploitation).
- **Context-aware learning**: Stats are tracked per (tool, target_type, task_type) \
so the system learns that e.g. nuclei_scan works great on ecommerce sites but \
js_analyze is better for API targets.
- **Persistent memory**: Workflows, lessons, and target notes are saved to a \
SQLite database and persist across sessions.

When the "Tool Recommendations" section appears below, those rankings are \
data-driven from the bandit — prefer higher-ranked tools but still explore.

## Rules

1. **Call `configure_scope` first** before any offensive tool.
2. Follow the methodology: Recon -> Enumerate -> Scan -> Exploit -> Report.
3. **Save findings as you go** using `save_finding`.
4. For long-running scans, use `background=true` and check with `job_status`.
5. **Generate a report** at the end with `generate_report`.
6. Analyze tool output before proceeding to the next step.
7. Be thorough but efficient — don't repeat scans.
8. Briefly explain your reasoning before each tool call.
9. When you find something interesting, dig deeper automatically.
10. Chain tools logically — e.g., subdomain discovery -> port scan -> \
    service fingerprint -> vulnerability scan -> exploit verification.

## Tool Categories

- **Recon:** nmap_scan, subfinder_enum, amass_enum, whois_lookup, dig_lookup, \
  theharvester_scan, shodan_search
- **Web App:** nikto_scan, sqlmap_scan, ffuf_fuzz, gobuster_dir, nuclei_scan, \
  dalfox_xss, whatweb_fingerprint, js_analyze
- **Exploitation:** searchsploit_search, msf_search, msf_run, msfvenom_generate, \
  crackmapexec_scan
- **Passwords:** hydra_brute, john_crack, hashcat_crack, medusa_brute, cewl_wordlist
- **Network:** responder_listen, bettercap_attack, arpspoof_attack
- **Wireless:** aircrack_crack, wifite_attack
- **Post-Exploitation:** linpeas_enum, bloodhound_collect, pspy_monitor
- **Infrastructure:** configure_scope, check_scope, list_tools, job_status, \
  list_jobs, cancel_job, session_send, session_close, save_finding, \
  list_findings, generate_report, exec_command

## Scope Enforcement

Only target systems within configured scope. The server blocks out-of-scope \
actions automatically. If the operator asks to target something, configure it \
in scope and proceed.
"""


def _mcp_tool_to_anthropic(tool: Any) -> dict[str, Any]:
    """Convert an MCP tool definition to Anthropic tool format."""
    schema = tool.inputSchema if hasattr(tool, "inputSchema") else {}
    return {
        "name": tool.name,
        "description": tool.description or "",
        "input_schema": schema,
    }


class ArsenalAgent:
    """Agent loop: Claude <-> Arsenal MCP server with Thompson Sampling."""

    MAX_TOOL_OUTPUT = 3000  # Truncate long tool output

    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self.client = anthropic.Anthropic(api_key=config.anthropic_api_key)
        self.mcp_session: ClientSession | None = None
        self.tools: list[dict[str, Any]] = []
        self.messages: list[dict[str, Any]] = []
        self._mcp_context: Any = None
        self._read_stream: Any = None
        self._write_stream: Any = None
        self.memory = MemoryStore()
        self.bandit = StrategyBandit()
        self.target: str | None = None
        self.target_type: str = "general"
        self.task_type: str = "general"
        self.context_tags: list[str] = []
        self._had_tool_calls = False
        self._session_rewards: float = 0.0

    async def connect(self) -> list[dict[str, Any]]:
        """Connect to the MCP server and fetch available tools."""
        url = self.config.mcp_server_url.rstrip("/") + "/mcp/"
        self._mcp_context = streamablehttp_client(url=url)
        self._read_stream, self._write_stream, _ = await self._mcp_context.__aenter__()

        self.mcp_session = ClientSession(self._read_stream, self._write_stream)
        await self.mcp_session.__aenter__()
        await self.mcp_session.initialize()

        result = await self.mcp_session.list_tools()
        self.tools = [_mcp_tool_to_anthropic(t) for t in result.tools]
        return self.tools

    async def disconnect(self) -> None:
        """Disconnect from the MCP server."""
        if self.mcp_session:
            await self.mcp_session.__aexit__(None, None, None)
            self.mcp_session = None
        if self._mcp_context:
            await self._mcp_context.__aexit__(None, None, None)
            self._mcp_context = None

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> str:
        """Call a tool on the MCP server, track rewards, return text result."""
        if not self.mcp_session:
            return "Error: not connected to MCP server"

        start_time = time.time()
        result = await self.mcp_session.call_tool(name, arguments)
        run_time = time.time() - start_time

        parts: list[str] = []
        for block in result.content:
            if hasattr(block, "text"):
                parts.append(block.text)
            else:
                parts.append(str(block))
        output = "\n".join(parts) if parts else "(no output)"

        # Truncate long output
        if len(output) > self.MAX_TOOL_OUTPUT:
            head = output[:self.MAX_TOOL_OUTPUT - 500]
            tail = output[-400:]
            cut = len(output) - self.MAX_TOOL_OUTPUT
            output = f"{head}\n\n... [{cut} chars truncated] ...\n\n{tail}"

        # Track rewards for finding-producing tools
        if name in FINDING_TOOLS:
            # Detect target from arguments
            target = arguments.get("target", arguments.get("url", self.target or "unknown"))
            if self.target is None and isinstance(target, str) and target != "unknown":
                self.target = target
                self.target_type = detect_target_type(target)

            task_type = infer_task_type(name)
            update_context_tags(self.context_tags, output)
            findings = parse_findings_from_output(output)

            reward = self.bandit.record_run(
                tool_name=name,
                target=target,
                findings=findings,
                run_time_seconds=run_time,
                target_type=self.target_type,
                task_type=task_type,
                context_tags=self.context_tags if self.context_tags else None,
            )
            self._session_rewards += reward
            if findings:
                output += f"\n\n[RL] +{reward:.1f} reward ({len(findings)} findings)"

        return output

    def _build_system_prompt(self) -> str:
        """Build the full system prompt with memory and bandit recommendations."""
        system = SYSTEM_PROMPT

        # Add context tags
        if self.context_tags:
            system += f"\n\n## Target Context\nDetected: {', '.join(self.context_tags)}"

        # Add bandit recommendations
        if self.tools:
            tool_names = [t["name"] for t in self.tools if t["name"] in FINDING_TOOLS]
            recommendations = self.bandit.get_recommendations(
                available_tools=tool_names,
                target_type=self.target_type,
                task_type=self.task_type,
                top_k=5,
            )
            if recommendations:
                system += "\n\n" + recommendations

        # Add memory
        memory_block = self.memory.get_relevant_memories(self.target)
        if memory_block:
            system += "\n\n" + memory_block

        return system

    async def run_turn(self, user_message: str | None = None) -> tuple[str, bool]:
        """Run one agent turn. Returns (assistant_text, done).

        If done is False, the caller should call run_turn(None) again
        to continue processing tool results.
        """
        if user_message is not None:
            self.messages.append({"role": "user", "content": user_message})

        system = self._build_system_prompt()

        response = self.client.messages.create(
            model=self.config.model,
            max_tokens=16384,  # Claude API max tokens for response
            system=system,
            tools=self.tools,
            messages=self.messages,
        )

        # Collect assistant content blocks
        assistant_content = []
        assistant_text_parts: list[str] = []
        tool_uses: list[dict[str, Any]] = []

        for block in response.content:
            if block.type == "text":
                assistant_text_parts.append(block.text)
                assistant_content.append({"type": "text", "text": block.text})
            elif block.type == "tool_use":
                tool_uses.append({
                    "id": block.id,
                    "name": block.name,
                    "input": block.input,
                })
                assistant_content.append({
                    "type": "tool_use",
                    "id": block.id,
                    "name": block.name,
                    "input": block.input,
                })

        self.messages.append({"role": "assistant", "content": assistant_content})

        # If no tool calls, we're done
        if not tool_uses:
            return "\n".join(assistant_text_parts), True

        self._had_tool_calls = True

        # Execute tool calls and build tool results
        tool_results = []
        for tu in tool_uses:
            result_text = await self.call_tool(tu["name"], tu["input"])
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": tu["id"],
                "content": result_text,
            })

        self.messages.append({"role": "user", "content": tool_results})

        return "\n".join(assistant_text_parts), False

    async def chat(self, user_message: str) -> tuple[list[dict], str]:
        """Run a full chat turn, processing all tool calls until Claude stops.

        Returns (events, final_text) where events is a list of dicts:
          {"type": "text", "content": str}
          {"type": "tool_call", "name": str, "input": dict}
          {"type": "tool_result", "name": str, "content": str}
        """
        events: list[dict] = []
        turns = 0

        text, done = await self.run_turn(user_message)
        if text:
            events.append({"type": "text", "content": text})

        # Collect tool calls from the last assistant message
        last_assistant = self.messages[-2] if not done else self.messages[-1]
        if not done:
            for block in last_assistant.get("content", []):
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    events.append({
                        "type": "tool_call",
                        "name": block["name"],
                        "input": block["input"],
                    })

            # Collect tool results
            last_user = self.messages[-1]
            for block in last_user.get("content", []):
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    events.append({
                        "type": "tool_result",
                        "name": self._find_tool_name(block["tool_use_id"]),
                        "content": block["content"],
                    })

        while not done and turns < self.config.max_turns:
            turns += 1
            text, done = await self.run_turn()
            if text:
                events.append({"type": "text", "content": text})

            if not done:
                last_assistant = self.messages[-2]
                for block in last_assistant.get("content", []):
                    if isinstance(block, dict) and block.get("type") == "tool_use":
                        events.append({
                            "type": "tool_call",
                            "name": block["name"],
                            "input": block["input"],
                        })
                last_user = self.messages[-1]
                for block in last_user.get("content", []):
                    if isinstance(block, dict) and block.get("type") == "tool_result":
                        events.append({
                            "type": "tool_result",
                            "name": self._find_tool_name(block["tool_use_id"]),
                            "content": block["content"],
                        })

        final_text = ""
        for e in reversed(events):
            if e["type"] == "text":
                final_text = e["content"]
                break

        return events, final_text

    def _find_tool_name(self, tool_use_id: str) -> str:
        """Find tool name by tool_use_id from message history."""
        for msg in reversed(self.messages):
            if msg["role"] == "assistant":
                for block in msg.get("content", []):
                    if isinstance(block, dict) and block.get("id") == tool_use_id:
                        return block.get("name", "unknown")
        return "unknown"

    def save_session_memory(self) -> str | None:
        """Ask Claude to summarize the session and save to memory DB.

        Returns the summary text, or None if there were no tool calls.
        """
        if not self._had_tool_calls or not self.messages:
            return None

        extraction_prompt = (
            "Analyze this penetration testing session and extract structured knowledge. "
            "Respond ONLY with valid JSON matching this schema (no markdown fences):\n"
            "{\n"
            '  "workflows": [{"target_domain": str, "tool_chain": [str], '
            '"finding_type": str, "severity": "critical|high|medium|low|info", '
            '"description": str}],\n'
            '  "lessons": [{"content": str, "category": "recon|webapp|exploit|general", '
            '"source_target": str|null}],\n'
            '  "target_notes": [{"domain": str, "tech_stack": [str]|null, '
            '"findings_summary": str|null, "notes": str|null}]\n'
            "}\n"
            "Only include entries where you have real data. Empty arrays are fine."
        )

        summary_messages = self.messages.copy()
        summary_messages.append({"role": "user", "content": extraction_prompt})

        try:
            response = self.client.messages.create(
                model=self.config.model,
                max_tokens=4096,
                system="You are a data extraction assistant. Output only valid JSON.",
                messages=summary_messages,
            )
        except Exception:
            return None

        raw = response.content[0].text if response.content else ""

        text = raw.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[-1]
        if text.endswith("```"):
            text = text.rsplit("```", 1)[0]
        text = text.strip()

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return None

        saved = 0
        for wf in data.get("workflows", []):
            try:
                self.memory.save_workflow(
                    wf["target_domain"], wf["tool_chain"],
                    wf["finding_type"], wf["severity"], wf["description"],
                )
                saved += 1
            except (KeyError, TypeError):
                continue

        for ls in data.get("lessons", []):
            try:
                self.memory.save_lesson(ls["content"], ls["category"], ls.get("source_target"))
                saved += 1
            except (KeyError, TypeError):
                continue

        for tn in data.get("target_notes", []):
            try:
                self.memory.save_target_note(
                    tn["domain"], tn.get("tech_stack"),
                    tn.get("findings_summary"), tn.get("notes"),
                )
                saved += 1
            except (KeyError, TypeError):
                continue

        reward_summary = f" Session reward: {self._session_rewards:.1f}" if self._session_rewards > 0 else ""
        return f"Saved {saved} memory entries.{reward_summary}" if saved else None

    def reset(self) -> None:
        """Clear conversation history and session state."""
        self.messages.clear()
        self.context_tags.clear()
        self._session_rewards = 0.0
