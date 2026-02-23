"""Plugin loader — loads user plugins from ~/.arsenal/plugins/."""
from __future__ import annotations

import importlib.util
import logging
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP
    from arsenal.core.runner import Runner

logger = logging.getLogger(__name__)


def load_plugins(mcp: "FastMCP", runner: "Runner", plugin_dir: Path | None = None) -> list[str]:
    """Load all .py plugins from the plugin directory.

    Each plugin must define a `register(mcp, runner)` function.
    Returns list of loaded plugin names.
    """
    if plugin_dir is None:
        plugin_dir = Path("~/.arsenal/plugins").expanduser()

    loaded: list[str] = []

    if not plugin_dir.exists():
        return loaded

    for path in sorted(plugin_dir.glob("*.py")):
        if path.name.startswith("_"):
            continue
        try:
            spec = importlib.util.spec_from_file_location(
                f"arsenal_plugin_{path.stem}", str(path)
            )
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)  # type: ignore[union-attr]

            if hasattr(module, "register"):
                module.register(mcp, runner)
                loaded.append(path.stem)
                logger.info("Loaded plugin: %s", path.stem)
            else:
                logger.warning("Plugin %s has no register() function, skipping", path.name)
        except Exception:
            logger.exception("Failed to load plugin: %s", path.name)

    return loaded
