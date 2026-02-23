"""Pydantic models for findings, evidence, and tool results."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingType(str, Enum):
    VULNERABILITY = "vulnerability"
    MISCONFIGURATION = "misconfiguration"
    INFORMATION = "information"
    CREDENTIAL = "credential"
    SERVICE = "service"


class Finding(BaseModel):
    id: int | None = None
    session_id: int = 1
    title: str
    severity: Severity = Severity.INFO
    finding_type: FindingType = FindingType.INFORMATION
    target: str = ""
    url: str = ""
    parameter: str = ""
    evidence: str = ""
    description: str = ""
    cwe: str = ""
    cvss: float | None = None
    tool: str = ""
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ToolRun(BaseModel):
    id: int | None = None
    session_id: int = 1
    tool_name: str
    target: str
    command: str
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    duration_seconds: float | None = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ToolResult(BaseModel):
    tool: str
    target: str
    command: str
    exit_code: int | None = None
    raw_output: str = ""
    stderr: str = ""
    parsed: Any = None
    findings: list[Finding] = Field(default_factory=list)
    job_id: str | None = None
    duration_seconds: float | None = None


class Session(BaseModel):
    id: int | None = None
    name: str
    scope_targets: list[str] = Field(default_factory=list)
    scope_exclusions: list[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
