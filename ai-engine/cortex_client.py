"""Optional Cortex observable-enrichment client.

Cortex exposes a REST API for listing enabled analyzers and running an
analyzer against an observable. The engine keeps this integration optional:
when no API key/analyzer is configured, alert processing remains deterministic
and does not fail because Cortex is unavailable.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class CortexClient:
    def __init__(
        self,
        url: str,
        api_key: str,
        analyzer_id: str,
        observable_type: str = "ip",
        tlp: int = 0,
        timeout_seconds: float = 10.0,
        enabled: bool = False,
    ):
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.analyzer_id = analyzer_id
        self.observable_type = observable_type
        self.tlp = tlp
        self.timeout_seconds = timeout_seconds
        self.enabled = enabled and bool(api_key) and bool(analyzer_id)

    async def enrich(self, alert: dict[str, Any]) -> dict[str, Any] | None:
        """Run the configured Cortex analyzer against the first alert IOC."""
        if not self.enabled:
            return None

        observable = alert.get("source_ip") or alert.get("dest_ip")
        if not observable:
            return None

        payload = {
            "data": observable,
            "dataType": self.observable_type,
            "tlp": self.tlp,
            "message": f"AI SOC Decision Engine alert {alert.get('alert_id', '')}",
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        endpoint = f"{self.url}/api/analyzer/{self.analyzer_id}/run"

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.post(endpoint, headers=headers, json=payload)
                response.raise_for_status()
                result = response.json()
            return {
                "enabled": True,
                "observable": observable,
                "observable_type": self.observable_type,
                "job": result,
            }
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning("Cortex enrichment failed for %s: %s", observable, exc)
            return {
                "enabled": True,
                "observable": observable,
                "observable_type": self.observable_type,
                "error": str(exc),
            }
