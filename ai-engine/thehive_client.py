"""
TheHive API client (TheHive 5) for automated case creation.

Fixes vs the original:
- Uses the TheHive 5 API base path /api/v1/case (the original used /api/case,
  which is the TheHive 4 path and 404s against TheHive 5).
- Idempotency: refuses to create a second case for an alert_id already sent.
- Explicit timeout + structured error logging.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

SEVERITY_MAP = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class TheHiveClient:
    def __init__(self, base_url: str, api_key: str, timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._created: set[str] = set()

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    async def create_case(self, alert: dict, triage: dict) -> Optional[dict]:
        alert_id = str(alert.get("alert_id", ""))
        if alert_id and alert_id in self._created:
            logger.info("Skipping duplicate TheHive case for alert_id=%s", alert_id)
            return None

        payload = self._build_payload(alert, triage)
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    f"{self.base_url}/api/v1/case",
                    headers=self._headers(),
                    json=payload,
                )
                resp.raise_for_status()
                case = resp.json()
        except httpx.TimeoutException as e:
            logger.error("TheHive case creation timed out for alert_id=%s: %s", alert_id, e)
            return None
        except httpx.HTTPStatusError as e:
            logger.error(
                "TheHive case creation failed for alert_id=%s: HTTP %s %s",
                alert_id,
                e.response.status_code,
                e.response.text[:200],
            )
            return None
        except httpx.TransportError as e:
            logger.error("TheHive unreachable for alert_id=%s: %s", alert_id, e)
            return None

        if alert_id:
            self._created.add(alert_id)
        logger.info("TheHive case created: %s for alert_id=%s", case.get("_id"), alert_id)
        return case

    @staticmethod
    def _build_payload(alert: dict, triage: dict) -> dict:
        severity = SEVERITY_MAP.get(str(triage.get("severity", "MEDIUM")).upper(), 2)
        techniques = triage.get("mitre_techniques") or []
        tags = [
            f"source:{alert.get('source', 'unknown')}",
            f"verdict:{triage.get('verdict')}",
        ]
        for t in techniques[:3]:
            tags.append(t.split(" - ")[0])

        description = TheHiveClient._build_description(alert, triage)
        payload = {
            "title": f"[AI-SOC] {alert.get('rule_description', 'Security Alert')}",
            "description": description,
            "severity": severity,
            "tags": tags,
            "tlp": 2,
            "status": "New",
        }

        # TheHive 5 custom fields (ordered map: name -> {order, type, value}).
        # Omitted when no custom fields are defined to avoid a 400 on a stock
        # TheHive instance that has no such fields configured.
        cf = {}
        for idx, (name, value, kind) in enumerate(
            [
                ("ai-verdict", triage.get("verdict"), "string"),
                ("ai-confidence", triage.get("confidence"), "float"),
                (
                    "mitre-tactic",
                    (triage.get("mitre_techniques") or [""])[0].split(" - ")[0],
                    "string",
                ),
                ("source-ip", alert.get("source_ip", ""), "string"),
            ]
        ):
            if value in (None, ""):
                continue
            cf[name] = {"order": idx, kind: value}
        if cf:
            payload["customFields"] = cf

        return payload

    @staticmethod
    def _build_description(alert: dict, triage: dict) -> str:
        evidence = "\n".join(f"- {e}" for e in (triage.get("evidence") or []))
        techniques = ", ".join(triage.get("mitre_techniques") or ["n/a"])
        return f"""## AI-Generated Incident Summary (advisory)

{triage.get('summary', 'No summary available.')}

---

## Rationale

{triage.get('rationale', 'No rationale.')}

---

## Alert Details

| Field | Value |
|-------|-------|
| Alert ID | `{alert.get('alert_id')}` |
| Source | {alert.get('source')} |
| Rule | {alert.get('rule_id')} — {alert.get('rule_description')} |
| Source IP | `{alert.get('source_ip', 'N/A')}` |
| Destination IP | `{alert.get('dest_ip', 'N/A')}` |
| Hostname | `{alert.get('hostname', 'N/A')}` |
| Timestamp | {alert.get('timestamp', 'N/A')} |

---

## AI Triage Output

- **Verdict**: {triage.get('verdict')} (advisory — analyst decision required)
- **Confidence**: {(float(triage.get('confidence', 0)) or 0):.0%}
- **Severity**: {triage.get('severity')}
- **MITRE Techniques**: {techniques}

---

## Evidence

{evidence or '- none recorded'}

---

## Recommended Action

{triage.get('recommended_action', 'No recommendation.')}

---

## Raw Log

```
{alert.get('raw_log', 'N/A')}
```

---
*Produced by the AI SOC Engine ({triage.get('model')}, prompt {triage.get('prompt_version')}) at {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} — advisory only.*
"""
