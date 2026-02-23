"""Configuration management with Pydantic models and YAML loading."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class ToolDefaults(BaseModel):
    timeout: int = 300
    default_wordlist: str = "/usr/share/wordlists/rockyou.txt"
    default_dirlist: str = "/usr/share/wordlists/dirb/common.txt"
    default_seclist_dns: str = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"


class DatabaseConfig(BaseModel):
    path: str = "~/.arsenal/arsenal.db"

    @property
    def resolved_path(self) -> Path:
        return Path(self.path).expanduser()


class ArsenalSettings(BaseModel):
    tool_defaults: ToolDefaults = Field(default_factory=ToolDefaults)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    plugin_dir: str = "~/.arsenal/plugins"
    nmap_path: str = "nmap"
    session_name: str = "default"

    @property
    def resolved_plugin_dir(self) -> Path:
        return Path(self.plugin_dir).expanduser()


def load_settings() -> ArsenalSettings:
    """Load settings from defaults.yaml, user config, and env vars."""
    defaults_path = Path(__file__).parent / "defaults.yaml"
    user_path = Path("~/.arsenal/config.yaml").expanduser()

    data: dict[str, Any] = {}

    if defaults_path.exists():
        with open(defaults_path) as f:
            loaded = yaml.safe_load(f)
            if loaded:
                data.update(loaded)

    if user_path.exists():
        with open(user_path) as f:
            loaded = yaml.safe_load(f)
            if loaded:
                data.update(loaded)

    # Env overrides
    if db_path := os.environ.get("ARSENAL_DB_PATH"):
        data.setdefault("database", {})["path"] = db_path
    if plugin_dir := os.environ.get("ARSENAL_PLUGIN_DIR"):
        data["plugin_dir"] = plugin_dir
    if session := os.environ.get("ARSENAL_SESSION"):
        data["session_name"] = session

    return ArsenalSettings(**data)


settings = load_settings()
