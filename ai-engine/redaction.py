r"""Enterprise PII and Secret Redaction Engine.

Provides automated redaction for alerts dispatched to external cloud LLM providers
(Azure OpenAI, Anthropic Claude, AWS Bedrock, Groq, OpenAI).

Protects sensitive enterprise telemetry by scrubbing:
- Private RFC 1918 IPv4 addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Plaintext credentials, passwords, auth tokens, bearer tokens, API keys
- Private cryptographic keys (RSA, EC, OpenSSH)
- Internal Active Directory hostnames and local network domains (*.corp, *.local, *.internal)
- Windows and Linux file system user profile paths (C:\Users\<user>, /home/<user>)
"""

from __future__ import annotations

import copy
import ipaddress
import re
from typing import Any


class Redactor:
    """Enterprise scrubbing engine for external AI telemetry."""

    # Password and credential patterns
    CREDENTIAL_PATTERNS = [
        re.compile(r"(?i)(?:password|passwd|pwd|secret)\s*[:=]\s*([^\s,;\"'|]+)"),
        re.compile(r"(?i)(?:Bearer\s+)([A-Za-z0-9_\-\.]{16,})"),
        re.compile(r"(?i)(?:api[_-]?key|access[_-]?token)\s*[:=]\s*([A-Za-z0-9_\-]{16,})"),
        re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----"),
    ]

    # Internal hostnames and domain patterns
    INTERNAL_HOST_PATTERNS = [
        re.compile(r"\b([a-zA-Z0-9_\-]+(?:\.corp|\.local|\.internal|\.lan))\b", re.IGNORECASE),
        re.compile(r"\b(?:DC0[1-9]|WINSRV-[A-Z0-9]+|DESKTOP-[A-Z0-9]+)\b", re.IGNORECASE),
    ]

    # User profile paths
    USER_PATH_PATTERNS = [
        re.compile(r"(?i)([A-Z]:\\Users\\)([a-zA-Z0-9_\-\.]+)(\\)"),
        re.compile(r"(/home/)([a-zA-Z0-9_\-\.]+)(/)"),
    ]

    # IPv4 regex matching
    IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self._ip_token_map: dict[str, str] = {}
        self._host_token_map: dict[str, str] = {}
        self._stats = {
            "ips_redacted": 0,
            "credentials_redacted": 0,
            "hosts_redacted": 0,
            "user_paths_redacted": 0,
        }

    def reset_mappings(self) -> None:
        """Reset deterministic session token mappings."""
        self._ip_token_map.clear()
        self._host_token_map.clear()

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)

    @staticmethod
    def is_private_ip(ip_str: str) -> bool:
        """Check if an IP string belongs to RFC 1918 or loopback."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private or ip.is_loopback
        except ValueError:
            return False

    def _get_ip_token(self, ip_str: str) -> str:
        if ip_str not in self._ip_token_map:
            idx = len(self._ip_token_map) + 1
            self._ip_token_map[ip_str] = f"[INTERNAL_IP_{idx}]"
        return self._ip_token_map[ip_str]

    def _get_host_token(self, host_str: str) -> str:
        lower = host_str.lower()
        if lower not in self._host_token_map:
            idx = len(self._host_token_map) + 1
            self._host_token_map[lower] = f"[INTERNAL_HOST_{idx}]"
        return self._host_token_map[lower]

    def redact_text(self, text: str) -> tuple[str, dict[str, int]]:
        """Redact sensitive patterns in raw text."""
        if not self.enabled or not text:
            return text, {"ips": 0, "credentials": 0, "hosts": 0, "paths": 0}

        counts = {"ips": 0, "credentials": 0, "hosts": 0, "paths": 0}
        out = text

        # 1. Credentials
        for pattern in self.CREDENTIAL_PATTERNS:
            matches = list(pattern.finditer(out))
            if matches:
                counts["credentials"] += len(matches)
                self._stats["credentials_redacted"] += len(matches)
                out = pattern.sub("[REDACTED_CREDENTIAL]", out)

        # 2. Private IPs
        def _replace_ip(match):
            candidate = match.group(0)
            if self.is_private_ip(candidate):
                counts["ips"] += 1
                self._stats["ips_redacted"] += 1
                return self._get_ip_token(candidate)
            return candidate

        out = self.IPV4_PATTERN.sub(_replace_ip, out)

        # 3. Internal Hostnames
        for pattern in self.INTERNAL_HOST_PATTERNS:
            def _replace_host(match):
                host = match.group(0)
                counts["hosts"] += 1
                self._stats["hosts_redacted"] += 1
                return self._get_host_token(host)
            out = pattern.sub(_replace_host, out)

        # 4. User profile paths
        for pattern in self.USER_PATH_PATTERNS:
            def _replace_path(match):
                counts["paths"] += 1
                self._stats["user_paths_redacted"] += 1
                return f"{match.group(1)}[REDACTED_USER]{match.group(3)}"
            out = pattern.sub(_replace_path, out)

        return out, counts

    def redact_alert(self, alert: dict[str, Any]) -> tuple[dict[str, Any], dict[str, int]]:
        """Return a sanitized copy of an alert payload safe for cloud LLMs."""
        if not self.enabled:
            return copy.deepcopy(alert), {"ips": 0, "credentials": 0, "hosts": 0, "paths": 0}

        sanitized = copy.deepcopy(alert)
        total_counts = {"ips": 0, "credentials": 0, "hosts": 0, "paths": 0}

        # Scrub raw_log
        if "raw_log" in sanitized and isinstance(sanitized["raw_log"], str):
            sanitized["raw_log"], c = self.redact_text(sanitized["raw_log"])
            for k in total_counts:
                total_counts[k] += c[k]

        # Scrub rule_description
        if "rule_description" in sanitized and isinstance(sanitized["rule_description"], str):
            sanitized["rule_description"], c = self.redact_text(sanitized["rule_description"])
            for k in total_counts:
                total_counts[k] += c[k]

        # Scrub source_ip
        src = sanitized.get("source_ip")
        if src and self.is_private_ip(src):
            sanitized["source_ip"] = self._get_ip_token(src)
            total_counts["ips"] += 1
            self._stats["ips_redacted"] += 1

        # Scrub dest_ip
        dst = sanitized.get("dest_ip")
        if dst and self.is_private_ip(dst):
            sanitized["dest_ip"] = self._get_ip_token(dst)
            total_counts["ips"] += 1
            self._stats["ips_redacted"] += 1

        # Scrub hostname if internal
        host = sanitized.get("hostname")
        if host:
            sanitized["hostname"], c = self.redact_text(host)
            for k in total_counts:
                total_counts[k] += c[k]

        return sanitized, total_counts
