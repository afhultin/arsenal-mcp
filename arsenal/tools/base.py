"""KaliTool abstract base class — every tool wrapper subclasses this."""
from __future__ import annotations

import shutil
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any


class ExecutionMode(str, Enum):
    SYNC = "sync"
    BACKGROUND = "background"
    INTERACTIVE = "interactive"


class KaliTool(ABC):
    """Base class for all Kali tool wrappers."""

    name: str = ""
    binary_name: str = ""
    category: str = ""
    description: str = ""
    execution_mode: ExecutionMode = ExecutionMode.SYNC

    @abstractmethod
    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        """Construct the CLI invocation as a list of args."""
        ...

    def parse_output(self, stdout: str, stderr: str) -> Any:
        """Parse raw output into structured data. Override for custom parsing."""
        return {"stdout": stdout, "stderr": stderr}

    def is_available(self) -> bool:
        """Check if the tool binary exists on the system."""
        return shutil.which(self.binary_name) is not None

    def get_info(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "binary": self.binary_name,
            "category": self.category,
            "description": self.description,
            "execution_mode": self.execution_mode.value,
            "available": self.is_available(),
        }
