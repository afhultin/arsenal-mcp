"""FFUF tool wrapper."""
from __future__ import annotations
from typing import Any
from arsenal.parsers.ffuf import parse_ffuf
from arsenal.tools.base import KaliTool
from arsenal.config.settings import settings


class FfufTool(KaliTool):
    name = "ffuf_fuzz"
    binary_name = "ffuf"
    category = "webapp"
    description = "Fast web fuzzer — directory/file discovery, parameter fuzzing"

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        cmd = [self.binary_name, "-u", target, "-of", "json"]
        wordlist = kwargs.get("wordlist", settings.tool_defaults.default_dirlist)
        cmd.extend(["-w", wordlist])
        if extensions := kwargs.get("extensions", ""):
            cmd.extend(["-e", extensions])
        if filter_codes := kwargs.get("filter_codes", ""):
            cmd.extend(["-fc", filter_codes])
        if filter_size := kwargs.get("filter_size", ""):
            cmd.extend(["-fs", filter_size])
        if match_codes := kwargs.get("match_codes", ""):
            cmd.extend(["-mc", match_codes])
        if threads := kwargs.get("threads", ""):
            cmd.extend(["-t", str(threads)])
        if rate := kwargs.get("rate", ""):
            cmd.extend(["-rate", str(rate)])
        return cmd

    def parse_output(self, stdout: str, stderr: str) -> Any:
        return parse_ffuf(stdout, stderr)
