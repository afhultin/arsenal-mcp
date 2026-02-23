"""Gobuster tool wrapper."""
from __future__ import annotations
from typing import Any
from arsenal.tools.base import KaliTool
from arsenal.config.settings import settings


class GobusterTool(KaliTool):
    name = "gobuster_dir"
    binary_name = "gobuster"
    category = "webapp"
    description = "Directory/file brute-forcer for web servers"

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        mode = kwargs.get("mode", "dir")
        cmd = [self.binary_name, mode, "-u", target]
        wordlist = kwargs.get("wordlist", settings.tool_defaults.default_dirlist)
        cmd.extend(["-w", wordlist])
        if extensions := kwargs.get("extensions", ""):
            cmd.extend(["-x", extensions])
        if status_codes := kwargs.get("status_codes", ""):
            cmd.extend(["-s", status_codes])
        if threads := kwargs.get("threads", ""):
            cmd.extend(["-t", str(threads)])
        cmd.append("--no-color")
        return cmd

    def parse_output(self, stdout: str, stderr: str) -> Any:
        entries = []
        for line in stdout.splitlines():
            line = line.strip()
            if line and not line.startswith("=") and not line.startswith("["):
                parts = line.split()
                if parts:
                    entries.append({"path": parts[0], "raw": line})
        return {"entries": entries, "count": len(entries)}
