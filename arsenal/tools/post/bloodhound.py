"""BloodHound collector tool wrapper."""
from __future__ import annotations
from typing import Any
from arsenal.tools.base import KaliTool


class BloodhoundTool(KaliTool):
    name = "bloodhound_collect"
    binary_name = "bloodhound-python"
    category = "post"
    description = "Active Directory relationship collector for BloodHound"

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        cmd = [self.binary_name, "-d", target]
        if username := kwargs.get("username", ""):
            cmd.extend(["-u", username])
        if password := kwargs.get("password", ""):
            cmd.extend(["-p", password])
        collection = kwargs.get("collection", "All")
        cmd.extend(["-c", collection])
        if nameserver := kwargs.get("nameserver", ""):
            cmd.extend(["-ns", nameserver])
        return cmd

    def parse_output(self, stdout: str, stderr: str) -> Any:
        files = []
        for line in stdout.splitlines():
            if ".json" in line:
                files.append(line.strip())
        return {"output_files": files, "raw": stdout}
