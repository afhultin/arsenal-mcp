"""WhatWeb fingerprinting tool wrapper."""
from __future__ import annotations
from typing import Any
from arsenal.tools.base import KaliTool


class WhatWebTool(KaliTool):
    name = "whatweb_fingerprint"
    binary_name = "whatweb"
    category = "webapp"
    description = "Web technology fingerprinting — identify CMS, frameworks, servers"

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        cmd = [self.binary_name]
        aggression = kwargs.get("aggression", "1")
        cmd.extend(["-a", str(aggression)])
        if kwargs.get("verbose", False):
            cmd.append("-v")
        cmd.append(target)
        return cmd

    def parse_output(self, stdout: str, stderr: str) -> Any:
        technologies = []
        for line in stdout.splitlines():
            line = line.strip()
            if line and "[" in line:
                technologies.append(line)
        return {"technologies": technologies, "raw": stdout}
