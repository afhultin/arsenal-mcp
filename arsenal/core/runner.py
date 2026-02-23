"""Subprocess execution engine — sync, background, and interactive modes."""
from __future__ import annotations

import asyncio
import shlex
import time
from typing import Any

from arsenal.config.settings import settings
from arsenal.core.jobs import JobManager, JobStatus, job_manager
from arsenal.core.scope import ScopeGuard, scope_guard
from arsenal.db import database as db
from arsenal.db.models import Finding, ToolResult, ToolRun
from arsenal.tools.base import ExecutionMode, KaliTool


class Runner:
    def __init__(
        self,
        scope: ScopeGuard | None = None,
        jobs: JobManager | None = None,
    ) -> None:
        self.scope = scope or scope_guard
        self.jobs = jobs or job_manager

    async def run(self, tool: KaliTool, target: str, background: bool = False, **kwargs: Any) -> ToolResult:
        """Execute a tool against a target with full pipeline."""
        # 1. Scope check
        allowed, reason = self.scope.validate(target)
        if not allowed:
            return ToolResult(
                tool=tool.name,
                target=target,
                command="(blocked)",
                raw_output=f"SCOPE VIOLATION: {reason}",
            )

        # 2. Build command
        cmd = tool.build_command(target, **kwargs)
        cmd_str = shlex.join(cmd)

        # 3. Execute based on mode
        if background or tool.execution_mode == ExecutionMode.BACKGROUND:
            return await self._run_background(tool, target, cmd, cmd_str)
        elif tool.execution_mode == ExecutionMode.INTERACTIVE:
            return await self._run_interactive(tool, cmd, cmd_str, target)
        else:
            return await self._run_sync(tool, target, cmd, cmd_str, **kwargs)

    async def _run_sync(
        self, tool: KaliTool, target: str, cmd: list[str], cmd_str: str, **kwargs: Any
    ) -> ToolResult:
        timeout = kwargs.get("timeout", settings.tool_defaults.timeout)
        start = time.time()

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return ToolResult(
                tool=tool.name,
                target=target,
                command=cmd_str,
                raw_output=f"Command timed out after {timeout}s",
                exit_code=-1,
            )
        except FileNotFoundError:
            return ToolResult(
                tool=tool.name,
                target=target,
                command=cmd_str,
                raw_output=f"Binary '{cmd[0]}' not found. Is {tool.binary_name} installed?",
                exit_code=-1,
            )

        duration = time.time() - start
        stdout = stdout_bytes.decode(errors="replace")
        stderr = stderr_bytes.decode(errors="replace")

        # 4. Parse
        parsed = tool.parse_output(stdout, stderr)

        # 5. Extract findings if parser returns them
        findings: list[Finding] = []
        if isinstance(parsed, dict) and "findings" in parsed:
            for f_data in parsed["findings"]:
                if isinstance(f_data, Finding):
                    findings.append(f_data)
                elif isinstance(f_data, dict):
                    # Don't override target if parser already set it
                    if "target" not in f_data:
                        f_data["target"] = target
                    findings.append(Finding(**f_data, tool=tool.name))

        # 6. Persist
        run = ToolRun(
            tool_name=tool.name,
            target=target,
            command=cmd_str,
            stdout=stdout,
            stderr=stderr,
            exit_code=proc.returncode,
            duration_seconds=duration,
        )
        await db.save_tool_run(run)

        for finding in findings:
            await db.save_finding(finding)

        return ToolResult(
            tool=tool.name,
            target=target,
            command=cmd_str,
            exit_code=proc.returncode,
            raw_output=stdout,
            stderr=stderr,
            parsed=parsed,
            findings=findings,
            duration_seconds=duration,
        )

    async def _run_background(
        self, tool: KaliTool, target: str, cmd: list[str], cmd_str: str
    ) -> ToolResult:
        job_id = self.jobs.create_job(tool.name, target, cmd_str)
        job = self.jobs.get_job(job_id)
        if job is None:
            raise RuntimeError("Failed to create background job")

        async def _bg_task() -> None:
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                job.process = proc
                stdout_bytes, stderr_bytes = await proc.communicate()
                job.stdout = stdout_bytes.decode(errors="replace")
                job.stderr = stderr_bytes.decode(errors="replace")
                job.exit_code = proc.returncode
                job.status = JobStatus.COMPLETED if proc.returncode == 0 else JobStatus.FAILED

                run = ToolRun(
                    tool_name=tool.name,
                    target=target,
                    command=cmd_str,
                    stdout=job.stdout,
                    stderr=job.stderr,
                    exit_code=proc.returncode,
                )
                await db.save_tool_run(run)
            except Exception as e:
                job.status = JobStatus.FAILED
                job.stderr = str(e)

        job.task = asyncio.create_task(_bg_task())

        return ToolResult(
            tool=tool.name,
            target=target,
            command=cmd_str,
            raw_output=f"Background job started. Job ID: {job_id}",
            job_id=job_id,
        )

    async def _run_interactive(
        self, tool: KaliTool, cmd: list[str], cmd_str: str, target: str
    ) -> ToolResult:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            return ToolResult(
                tool=tool.name,
                target=target,
                command=cmd_str,
                raw_output=f"Binary '{cmd[0]}' not found.",
                exit_code=-1,
            )

        session_id = self.jobs.register_session(tool.name, proc)
        return ToolResult(
            tool=tool.name,
            target=target,
            command=cmd_str,
            raw_output=f"Interactive session started. Session ID: {session_id}",
            job_id=session_id,
        )


runner = Runner()
