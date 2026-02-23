"""Background job tracker and interactive session manager."""
from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class JobStatus(str, Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class Job:
    id: str
    tool_name: str
    target: str
    command: str
    status: JobStatus = JobStatus.RUNNING
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    process: asyncio.subprocess.Process | None = None
    task: asyncio.Task | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tool": self.tool_name,
            "target": self.target,
            "command": self.command,
            "status": self.status.value,
            "exit_code": self.exit_code,
            "stdout_length": len(self.stdout),
            "stderr_length": len(self.stderr),
        }


@dataclass
class InteractiveSession:
    id: str
    tool_name: str
    process: asyncio.subprocess.Process
    output_buffer: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tool": self.tool_name,
            "alive": self.process.returncode is None,
            "output_buffer_length": len(self.output_buffer),
        }


class JobManager:
    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._sessions: dict[str, InteractiveSession] = {}

    def create_job(self, tool_name: str, target: str, command: str) -> str:
        job_id = uuid.uuid4().hex[:12]
        job = Job(id=job_id, tool_name=tool_name, target=target, command=command)
        self._jobs[job_id] = job
        return job_id

    def get_job(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)

    def list_jobs(self) -> list[dict[str, Any]]:
        return [j.to_dict() for j in self._jobs.values()]

    async def cancel_job(self, job_id: str) -> bool:
        job = self._jobs.get(job_id)
        if not job:
            return False
        if job.process and job.process.returncode is None:
            job.process.terminate()
            try:
                await asyncio.wait_for(job.process.wait(), timeout=5)
            except asyncio.TimeoutError:
                job.process.kill()
        if job.task and not job.task.done():
            job.task.cancel()
        job.status = JobStatus.CANCELLED
        return True

    def register_session(self, tool_name: str, process: asyncio.subprocess.Process) -> str:
        session_id = uuid.uuid4().hex[:12]
        session = InteractiveSession(id=session_id, tool_name=tool_name, process=process)
        self._sessions[session_id] = session
        return session_id

    def get_session(self, session_id: str) -> InteractiveSession | None:
        return self._sessions.get(session_id)

    async def session_send(self, session_id: str, command: str) -> str:
        session = self._sessions.get(session_id)
        if not session:
            return "Session not found."
        if session.process.returncode is not None:
            return "Session has exited."
        if not session.process.stdin:
            return "Session stdin not available."

        session.process.stdin.write((command + "\n").encode())
        await session.process.stdin.drain()

        # Read available output with a short timeout
        output = ""
        if session.process.stdout:
            try:
                data = await asyncio.wait_for(session.process.stdout.read(65536), timeout=3)
                output = data.decode(errors="replace")
                session.output_buffer += output
            except asyncio.TimeoutError:
                pass
        return output or "(no immediate output)"

    async def session_close(self, session_id: str) -> bool:
        session = self._sessions.get(session_id)
        if not session:
            return False
        if session.process.returncode is None:
            session.process.terminate()
            try:
                await asyncio.wait_for(session.process.wait(), timeout=5)
            except asyncio.TimeoutError:
                session.process.kill()
        del self._sessions[session_id]
        return True

    def list_sessions(self) -> list[dict[str, Any]]:
        return [s.to_dict() for s in self._sessions.values()]


job_manager = JobManager()
