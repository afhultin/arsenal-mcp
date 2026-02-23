"""Nmap tool wrapper."""
from __future__ import annotations
from typing import Any
from arsenal.parsers.nmap import parse_nmap
from arsenal.tools.base import KaliTool, ExecutionMode


class NmapTool(KaliTool):
    name = "nmap_scan"
    binary_name = "nmap"
    category = "recon"
    description = "Network scanner — port scanning, service detection, OS fingerprinting"
    execution_mode = ExecutionMode.SYNC

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        cmd = [self.binary_name]
        scan_type = kwargs.get("scan_type", "")
        if scan_type:
            cmd.append(f"-s{scan_type}")
        ports = kwargs.get("ports", "")
        if ports:
            cmd.extend(["-p", str(ports)])
        scripts = kwargs.get("scripts", "")
        if scripts:
            cmd.extend(["--script", scripts])
        timing = kwargs.get("timing", "")
        if timing:
            cmd.append(f"-T{timing}")
        if kwargs.get("service_version", False):
            cmd.append("-sV")
        if kwargs.get("os_detection", False):
            cmd.append("-O")
        extra = kwargs.get("extra_args", "")
        if extra:
            cmd.extend(extra.split())
        cmd.append(target)
        return cmd

    def parse_output(self, stdout: str, stderr: str) -> Any:
        return parse_nmap(stdout, stderr)
