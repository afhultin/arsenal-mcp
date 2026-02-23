"""Agent configuration — reads from environment and CLI args."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class AgentConfig:
    """Configuration for the Arsenal agent."""

    mcp_server_url: str = "http://localhost:8080"
    anthropic_api_key: str = ""
    model: str = "claude-sonnet-4-20250514"
    max_turns: int = 50
    auto_mode: bool = False

    def __post_init__(self) -> None:
        if not self.anthropic_api_key:
            self.anthropic_api_key = os.environ.get("ANTHROPIC_API_KEY", "")

    def validate(self) -> list[str]:
        """Return list of config errors, empty if valid."""
        errors: list[str] = []
        if not self.anthropic_api_key:
            errors.append("ANTHROPIC_API_KEY not set (env var or --api-key)")
        if not self.mcp_server_url:
            errors.append("MCP server URL not set")
        if self.max_turns <= 0:
            errors.append("max_turns must be greater than 0")
        return errors
