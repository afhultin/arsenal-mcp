"""Medusa tool wrapper."""
from __future__ import annotations
from typing import Any
from arsenal.tools.base import KaliTool


class MedusaTool(KaliTool):
    name = "medusa_brute"
    binary_name = "medusa"
    category = "passwords"
    description = "Parallel network login brute-forcer"

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        cmd = [self.binary_name, "-h", target]
        if username := kwargs.get("username", ""):
            cmd.extend(["-u", username])
        elif username_list := kwargs.get("username_list", ""):
            cmd.extend(["-U", username_list])
        if password := kwargs.get("password", ""):
            cmd.extend(["-p", password])
        elif password_list := kwargs.get("password_list", ""):
            cmd.extend(["-P", password_list])
        module = kwargs.get("module", "ssh")
        cmd.extend(["-M", module])
        if threads := kwargs.get("threads", ""):
            cmd.extend(["-t", str(threads)])
        return cmd

    def parse_output(self, stdout: str, stderr: str) -> Any:
        creds = []
        for line in stdout.splitlines():
            if "SUCCESS" in line:
                creds.append(line.strip())
        return {"credentials": creds, "count": len(creds)}
