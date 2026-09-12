"""
LLM backends for the AI SOC Engine.

- OllamaBackend : real local model over the Ollama HTTP API (with timeouts).
- OfflineBackend : deterministic rule-engine analysis (no LLM); used as the
                   fallback and for fully-reproducible testing.
- ScriptedBackend : canned responses keyed by a trigger string (test use only).
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class BackendError(Exception):
    """Raised when a backend cannot produce a result (down / timeout / malformed)."""


class OllamaBackend:
    """Thin client for the Ollama /api/generate endpoint with explicit timeouts."""

    def __init__(
        self,
        host: str,
        model: str,
        temperature: float = 0.1,
        num_predict: int = 1024,
        timeout: float = 30.0,
    ):
        self.host = host.rstrip("/")
        self.model = model
        self.temperature = temperature
        self.num_predict = num_predict
        self.timeout = timeout

    async def generate(self, prompt: str) -> str:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": self.temperature, "num_predict": self.num_predict},
        }
        url = f"{self.host}/api/generate"
        started = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(url, json=payload)
                resp.raise_for_status()
                data = resp.json()
        except httpx.TimeoutException as e:
            raise BackendError(f"Ollama timed out after {self.timeout}s") from e
        except httpx.HTTPStatusError as e:
            raise BackendError(f"Ollama HTTP {e.response.status_code}") from e
        except (httpx.ConnectError, httpx.TransportError) as e:
            raise BackendError(f"Ollama unreachable at {self.host}") from e

        elapsed = (time.monotonic() - started) * 1000
        text = data.get("response", "")
        if not text or not text.strip():
            raise BackendError("Ollama returned an empty response")
        logger.debug("Ollama generated %d chars in %.0f ms", len(text), elapsed)
        return text


class OfflineBackend:
    """Deterministic, no-network analysis using the safety rule engine."""

    def __init__(self, safety_engine):
        self.safety = safety_engine

    async def analyze(self, alert: dict) -> dict[str, Any]:
        a = self.safety.assess(alert)
        return {
            "summary": a.summary,
            "severity": a.severity,
            "confidence": a.confidence,
            "rationale": a.rationale,
            "mitre_techniques": a.mitre_techniques,
            "recommended_action": a.recommended_action,
            "evidence": a.evidence,
            "verdict": a.verdict,
            "is_false_positive": (a.verdict == "CLOSE"),
        }


class ScriptedBackend:
    """Deterministic canned responses for tests (keyed on a marker string)."""

    def __init__(self, responses: dict[str, str]):
        self.responses = responses

    async def analyze(self, alert: dict) -> dict[str, Any]:
        raw = json.dumps(alert)
        for key, scripted in self.responses.items():
            if key in raw:
                from schemas import parse_model_json

                return parse_model_json(scripted)
        raise BackendError("no scripted response matched the alert")
