"""Terminal interface for the Arsenal agent — rich output + interactive prompt."""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.text import Text

from agent.agent import ArsenalAgent
from agent.config import AgentConfig

console = Console()


def _print_event(event: dict) -> None:
    """Print a single agent event with rich formatting."""
    etype = event["type"]

    if etype == "text":
        console.print()
        console.print(Markdown(event["content"]))

    elif etype == "tool_call":
        name = event["name"]
        args = event.get("input", {})
        args_short = json.dumps(args, default=str)
        if len(args_short) > 200:
            args_short = args_short[:200] + "..."
        console.print(
            Panel(
                Text(f"{name}({args_short})", style="cyan"),
                title="[bold yellow]Tool Call[/bold yellow]",
                border_style="yellow",
                expand=False,
            )
        )

    elif etype == "tool_result":
        name = event.get("name", "")
        content = event.get("content", "")
        # Truncate long results for display
        display = content if len(content) <= 1500 else content[:1500] + "\n... (truncated)"
        console.print(
            Panel(
                Text(display, style="dim"),
                title=f"[bold green]Result[/bold green] — {name}",
                border_style="green",
                expand=False,
            )
        )


def _show_memories(agent: ArsenalAgent) -> None:
    """Display stored memories."""
    data = agent.memory.list_memories()

    if not any(data.values()):
        console.print("[dim]No memories stored yet.[/dim]")
        return

    if data["lessons"]:
        console.print(Panel(
            "\n".join(
                f"[{r['category']}] {r['content']}" for r in data["lessons"]
            ),
            title=f"[bold]Lessons ({len(data['lessons'])})[/bold]",
            border_style="cyan",
        ))

    if data["target_notes"]:
        lines = []
        for r in data["target_notes"]:
            tech = ""
            if r.get("tech_stack"):
                try:
                    tech = ", ".join(json.loads(r["tech_stack"]))
                except (json.JSONDecodeError, TypeError):
                    tech = str(r["tech_stack"])
            line = f"[bold]{r['domain']}[/bold]"
            if tech:
                line += f" — {tech}"
            if r.get("findings_summary"):
                line += f"\n  Findings: {r['findings_summary']}"
            if r.get("notes"):
                line += f"\n  Notes: {r['notes']}"
            line += f"\n  Last tested: {r['last_tested']}"
            lines.append(line)
        console.print(Panel(
            "\n\n".join(lines),
            title=f"[bold]Target Notes ({len(data['target_notes'])})[/bold]",
            border_style="green",
        ))

    if data["workflows"]:
        lines = []
        for r in data["workflows"]:
            try:
                chain = " → ".join(json.loads(r["tool_chain"]))
            except (json.JSONDecodeError, TypeError):
                chain = str(r["tool_chain"])
            sev = r["severity"].upper()
            lines.append(f"[{sev}] {chain} → {r['description']}")
        console.print(Panel(
            "\n".join(lines),
            title=f"[bold]Workflows ({len(data['workflows'])})[/bold]",
            border_style="yellow",
        ))


def _detect_target(agent: ArsenalAgent, text: str) -> None:
    """Try to extract a domain/target from user input as a hint for memory lookups."""
    # Match common domain patterns
    match = re.search(r'(?:https?://)?([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+)', text)
    if match:
        agent.target = match.group(1)


async def _run_interactive(config: AgentConfig) -> None:
    """Main interactive loop."""
    agent = ArsenalAgent(config)

    console.print(
        Panel(
            "[bold]Arsenal Agent[/bold]\n"
            f"Model: {config.model}\n"
            f"MCP Server: {config.mcp_server_url}\n"
            f"Max turns: {config.max_turns}",
            title="[bold red]Configuration[/bold red]",
            border_style="red",
        )
    )

    console.print("[dim]Connecting to MCP server...[/dim]")
    try:
        tools = await agent.connect()
    except Exception as e:
        console.print(f"[bold red]Failed to connect:[/bold red] {e}")
        console.print(
            "[dim]Make sure the Arsenal MCP server is running: "
            "docker compose up -d[/dim]"
        )
        return

    console.print(f"[green]Connected — {len(tools)} tools available[/green]")
    console.print(
        "[dim]Type your instructions. Commands: 'quit', 'reset', 'save', 'memory', 'forget'[/dim]\n"
    )

    try:
        while True:
            try:
                user_input = console.input("[bold blue]arsenal>[/bold blue] ").strip()
            except (EOFError, KeyboardInterrupt):
                break

            if not user_input:
                continue

            cmd = user_input.lower()

            if cmd in ("quit", "exit"):
                break

            if cmd == "reset":
                agent.reset()
                console.print("[dim]Conversation history cleared.[/dim]")
                continue

            if cmd == "save":
                console.print("[dim]Saving session memory...[/dim]")
                result = agent.save_session_memory()
                if result:
                    console.print(f"[green]{result}[/green]")
                else:
                    console.print("[dim]Nothing to save (no tool calls in this session).[/dim]")
                continue

            if cmd == "memory":
                _show_memories(agent)
                continue

            if cmd == "forget":
                agent.memory.clear()
                console.print("[yellow]All memory cleared.[/yellow]")
                continue

            # Set target hint from user input for memory lookups
            if agent.target is None:
                _detect_target(agent, user_input)

            try:
                events, _ = await agent.chat(user_input)
                for event in events:
                    _print_event(event)
            except Exception as e:
                console.print(f"[bold red]Error:[/bold red] {e}")
    finally:
        # Auto-save memory on exit
        if agent._had_tool_calls:
            console.print("[dim]Saving session memory...[/dim]")
            result = agent.save_session_memory()
            if result:
                console.print(f"[green]{result}[/green]")
        console.print("[dim]Disconnecting...[/dim]")
        await agent.disconnect()
        console.print("[dim]Goodbye.[/dim]")


async def _run_auto(config: AgentConfig, task: str) -> None:
    """Run a single autonomous task and exit."""
    agent = ArsenalAgent(config)

    # Detect target from task for memory lookup
    _detect_target(agent, task)

    console.print(f"[dim]Connecting to MCP server at {config.mcp_server_url}...[/dim]")
    try:
        tools = await agent.connect()
    except Exception as e:
        console.print(f"[bold red]Failed to connect:[/bold red] {e}")
        sys.exit(1)

    console.print(f"[green]Connected — {len(tools)} tools available[/green]")
    console.print(f"[bold]Task:[/bold] {task}\n")

    try:
        events, _ = await agent.chat(task)
        for event in events:
            _print_event(event)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
    finally:
        if agent._had_tool_calls:
            console.print("[dim]Saving session memory...[/dim]")
            result = agent.save_session_memory()
            if result:
                console.print(f"[green]{result}[/green]")
        await agent.disconnect()


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Arsenal Agent — AI-powered pentesting with Arsenal MCP"
    )
    parser.add_argument(
        "--server",
        default="http://localhost:8080",
        help="Arsenal MCP server URL (default: http://localhost:8080)",
    )
    parser.add_argument(
        "--model",
        default="claude-sonnet-4-20250514",
        help="Anthropic model to use (default: claude-sonnet-4-20250514)",
    )
    parser.add_argument(
        "--api-key",
        default="",
        help="Anthropic API key (default: ANTHROPIC_API_KEY env var)",
    )
    parser.add_argument(
        "--max-turns",
        type=int,
        default=50,
        help="Max agent turns per task (default: 50)",
    )
    parser.add_argument(
        "--auto",
        metavar="TASK",
        default="",
        help="Run a single task autonomously and exit",
    )
    args = parser.parse_args()

    config = AgentConfig(
        mcp_server_url=args.server,
        anthropic_api_key=args.api_key,
        model=args.model,
        max_turns=args.max_turns,
        auto_mode=bool(args.auto),
    )

    errors = config.validate()
    if errors:
        for e in errors:
            console.print(f"[bold red]Config error:[/bold red] {e}")
        sys.exit(1)

    if args.auto:
        asyncio.run(_run_auto(config, args.auto))
    else:
        asyncio.run(_run_interactive(config))


if __name__ == "__main__":
    main()
