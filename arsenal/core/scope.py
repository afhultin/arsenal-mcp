"""Scope enforcement — DENY by default. Nothing runs until configure_scope() is called."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field


@dataclass
class ScopeGuard:
    targets: list[str] = field(default_factory=list)
    exclusions: list[str] = field(default_factory=list)
    _configured: bool = False

    @property
    def is_configured(self) -> bool:
        return self._configured

    def configure(self, targets: list[str], exclusions: list[str] | None = None) -> None:
        self.targets = [t.strip() for t in targets if t.strip()]
        self.exclusions = [e.strip() for e in (exclusions or []) if e.strip()]
        self._configured = True

    def reset(self) -> None:
        self.targets.clear()
        self.exclusions.clear()
        self._configured = False

    def validate(self, target: str) -> tuple[bool, str]:
        """Check if target is in scope. Returns (allowed, reason)."""
        if not self._configured:
            return False, "Scope not configured. Call configure_scope first."

        if not self.targets:
            return False, "No targets in scope."

        target = target.strip()

        # Check exclusions first
        for excl in self.exclusions:
            if self._matches(target, excl):
                return False, f"Target '{target}' is excluded by '{excl}'."

        # Check inclusions
        for inc in self.targets:
            if self._matches(target, inc):
                return True, "In scope."

        return False, f"Target '{target}' is not in scope."

    def _matches(self, target: str, pattern: str) -> bool:
        """Check if target matches a scope pattern (domain, wildcard, IP, CIDR)."""
        # Exact match
        if target == pattern:
            return True

        # Wildcard domain: *.example.com
        if pattern.startswith("*."):
            suffix = pattern[1:]  # .example.com
            base = pattern[2:]    # example.com
            if target == base or target.endswith(suffix):
                return True

        # CIDR range
        try:
            network = ipaddress.ip_network(pattern, strict=False)
            target_ip = self._extract_ip(target)
            if target_ip and ipaddress.ip_address(target_ip) in network:
                return True
        except ValueError:
            pass

        # IP match
        try:
            target_ip = self._extract_ip(target)
            if target_ip and target_ip == pattern:
                return True
        except ValueError:
            pass

        # Domain containment: target is subdomain of pattern
        if target.endswith("." + pattern):
            return True

        # URL matching — extract host from URL
        host = self._extract_host(target)
        if host and host != target:
            return self._matches(host, pattern)

        return False

    @staticmethod
    def _extract_ip(target: str) -> str | None:
        host = ScopeGuard._extract_host(target)
        if not host:
            return None
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            return None

    @staticmethod
    def _extract_host(target: str) -> str | None:
        """Extract hostname/IP from a target string (could be URL, host:port, etc.)."""
        # Strip protocol
        t = target
        if "://" in t:
            t = t.split("://", 1)[1]
        # Strip path
        t = t.split("/", 1)[0]
        # Strip port
        t = t.split(":", 1)[0]
        # Strip userinfo
        if "@" in t:
            t = t.split("@", 1)[1]
        return t if t else None


# Global singleton
scope_guard = ScopeGuard()
