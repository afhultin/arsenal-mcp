"""JavaScript Analyzer - Extract secrets, endpoints, and sensitive data from JS files."""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from arsenal.tools.base import KaliTool


class JSAnalyzerTool(KaliTool):
    """
    JavaScript analyzer for finding secrets and hidden endpoints.

    This is a Python-native tool (no binary) that crawls JS files
    and extracts sensitive data like API keys, hidden endpoints, etc.
    """

    name = "js_analyzer"
    binary_name = "python3"  # It's Python-based
    category = "webapp"
    description = "Extract secrets, API keys, and hidden endpoints from JavaScript files"

    # Regex patterns for secrets
    SECRET_PATTERNS = {
        "aws_access_key": (r"AKIA[0-9A-Z]{16}", "critical", "AWS Access Key ID"),
        "google_api_key": (r"AIza[0-9A-Za-z\-_]{35}", "critical", "Google API Key"),
        "github_token": (r"gh[pousr]_[A-Za-z0-9_]{36,}", "critical", "GitHub Token"),
        "slack_token": (r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*", "critical", "Slack Token"),
        "stripe_key": (r"sk_live_[0-9a-zA-Z]{24,}", "critical", "Stripe Live Secret Key"),
        "jwt_token": (r"eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*", "high", "JWT Token"),
        "bearer_token": (r"[Bb]earer\s+[A-Za-z0-9\-_\.~\+\/]+=*", "high", "Bearer Token"),
        "private_key": (r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", "critical", "Private Key"),
        "api_key_generic": (r"['\"]?(?:api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]", "high", "Generic API Key"),
        "secret_generic": (r"['\"]?(?:secret|password|passwd|pwd)['\"]?\s*[:=]\s*['\"]([^'\"]{8,})['\"]", "high", "Hardcoded Secret"),
    }

    # Endpoint patterns
    ENDPOINT_PATTERNS = {
        "api_endpoint": (r"['\"`](/api/v?\d?[a-zA-Z0-9/_\-]+)['\"`]", "medium", "API Endpoint"),
        "graphql": (r"['\"`](/graphql[a-zA-Z0-9/_\-]*)['\"`]", "high", "GraphQL Endpoint"),
        "admin_path": (r"['\"`](/(?:admin|dashboard|manage|internal|private|backend)[a-zA-Z0-9/_\-]*)['\"`]", "high", "Admin Path"),
        "debug_path": (r"['\"`](/(?:debug|test|dev|staging)[a-zA-Z0-9/_\-]*)['\"`]", "high", "Debug Path"),
        "auth_endpoint": (r"['\"`](/(?:auth|login|logout|signin|signup|oauth)[a-zA-Z0-9/_\-]*)['\"`]", "high", "Auth Endpoint"),
        "upload_endpoint": (r"['\"`](/(?:upload|file|media|attachment)[a-zA-Z0-9/_\-]*)['\"`]", "high", "Upload Endpoint"),
    }

    # Sensitive data patterns
    SENSITIVE_PATTERNS = {
        "internal_ip": (r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b", "medium", "Internal IP"),
        "s3_bucket": (r"[a-zA-Z0-9.-]+\.s3\.amazonaws\.com", "high", "S3 Bucket"),
        "database_url": (r"(?:mongodb|postgres|mysql|redis)://[^\s'\"]+", "critical", "Database URL"),
    }

    def is_available(self) -> bool:
        """Always available - it's pure Python."""
        return True

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        """Not used - we run Python directly."""
        return ["echo", "Use run_analysis() instead"]

    async def run_analysis(self, target: str, max_files: int = 30, crawl_depth: int = 2) -> dict[str, Any]:
        """Run the actual JS analysis."""
        results = {
            "target": target,
            "js_files_found": 0,
            "js_files_analyzed": 0,
            "secrets": [],
            "endpoints": [],
            "sensitive_data": [],
            "findings": [],
        }

        # Normalize URL
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        async with httpx.AsyncClient(
            timeout=30.0,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        ) as client:
            # Discover JS files
            js_urls = await self._discover_js_files(client, target, crawl_depth, max_files)
            results["js_files_found"] = len(js_urls)

            # Analyze each JS file
            for js_url in js_urls[:max_files]:
                try:
                    await self._analyze_js_file(client, js_url, results)
                    results["js_files_analyzed"] += 1
                except Exception:
                    continue

        # Build findings for database
        for secret in results["secrets"]:
            results["findings"].append({
                "title": f"Secret Found: {secret['type']}",
                "severity": secret["severity"],
                "finding_type": "credential",
                "target": target,
                "evidence": f"Found in {secret['file']}: {secret['value'][:50]}...",
            })

        for endpoint in results["endpoints"]:
            if endpoint["severity"] in ("high", "critical"):
                results["findings"].append({
                    "title": f"Hidden Endpoint: {endpoint['value']}",
                    "severity": endpoint["severity"],
                    "finding_type": "information",
                    "target": target,
                    "evidence": f"Found in JS: {endpoint['value']}",
                })

        return results

    async def _discover_js_files(self, client: httpx.AsyncClient, target: str, depth: int, max_files: int) -> list[str]:
        """Find JS files by crawling the target."""
        js_urls = set()
        visited = set()
        to_visit = [target]

        for _ in range(depth):
            next_level = []
            for url in to_visit:
                if url in visited or len(js_urls) >= max_files:
                    continue
                visited.add(url)

                try:
                    response = await client.get(url)
                    if response.status_code != 200:
                        continue

                    content = response.text

                    # Find script tags
                    for match in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', content, re.I):
                        src = match.group(1)
                        js_url = self._resolve_url(url, src)
                        if js_url and ('.js' in js_url or '.mjs' in js_url):
                            js_urls.add(js_url)

                    # Find links to crawl
                    base_domain = urlparse(target).netloc
                    for match in re.finditer(r'href=["\']([^"\']+)["\']', content):
                        link = self._resolve_url(url, match.group(1))
                        if link and base_domain in urlparse(link).netloc:
                            if not any(link.endswith(ext) for ext in ['.js', '.css', '.png', '.jpg', '.gif', '.svg']):
                                next_level.append(link)

                except Exception:
                    continue

            to_visit = next_level[:20]

        return list(js_urls)

    def _resolve_url(self, base: str, path: str) -> str | None:
        """Resolve relative URL to absolute."""
        if not path:
            return None
        if path.startswith(('http://', 'https://')):
            return path
        if path.startswith('//'):
            return 'https:' + path
        return urljoin(base, path)

    async def _analyze_js_file(self, client: httpx.AsyncClient, url: str, results: dict):
        """Analyze a single JS file for secrets and endpoints."""
        response = await client.get(url)
        if response.status_code != 200:
            return

        content = response.text
        if len(content) > 5_000_000:  # Skip huge files
            return

        # Check for secrets
        for name, (pattern, severity, description) in self.SECRET_PATTERNS.items():
            for match in re.finditer(pattern, content, re.I):
                value = match.group(0)
                if not self._is_false_positive(value):
                    results["secrets"].append({
                        "type": description,
                        "value": value,
                        "severity": severity,
                        "file": url,
                    })

        # Check for endpoints
        for name, (pattern, severity, description) in self.ENDPOINT_PATTERNS.items():
            for match in re.finditer(pattern, content):
                value = match.group(1) if match.lastindex else match.group(0)
                if len(value) > 3:
                    results["endpoints"].append({
                        "type": description,
                        "value": value,
                        "severity": severity,
                        "file": url,
                    })

        # Check for sensitive data
        for name, (pattern, severity, description) in self.SENSITIVE_PATTERNS.items():
            for match in re.finditer(pattern, content, re.I):
                results["sensitive_data"].append({
                    "type": description,
                    "value": match.group(0),
                    "severity": severity,
                    "file": url,
                })

    def _is_false_positive(self, value: str) -> bool:
        """Filter out common false positives."""
        indicators = ['example', 'sample', 'test', 'demo', 'placeholder', 'xxx', '000']
        value_lower = value.lower()
        return any(ind in value_lower for ind in indicators) or len(value) < 10

    def parse_output(self, stdout: str, stderr: str) -> Any:
        """Not used for this tool."""
        return {"raw": stdout}
