"""
Pydantic schemas for the AI SOC Engine.

The AI triage output MUST conform to a strict structure so that malformed
model responses are rejected (never silently accepted).
"""

from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
Verdict = Literal["ESCALATE", "ENRICH", "CLOSE", "PENDING_APPROVAL"]


class AlertPayload(BaseModel):
    """Normalised alert input (Wazuh/Suricata/Zeek webhook payload)."""

    alert_id: str
    source: str
    rule_id: Optional[str] = None
    rule_description: str
    severity: int = Field(ge=1, le=15, description="1-15 (Wazuh scale)")
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    hostname: Optional[str] = None
    timestamp: Optional[str] = None
    raw_log: str = ""
    misp_context: Optional[dict] = None
    cortex_context: Optional[dict] = None
    geo_info: Optional[dict] = None

    @field_validator("raw_log", "rule_description")
    @classmethod
    def _no_empty(cls, v: str) -> str:
        return v or ""

    def ioc_summary(self) -> list[str]:
        """List of the concrete indicators carried by this alert."""
        iocs = []
        if self.source_ip:
            iocs.append(f"source_ip={self.source_ip}")
        if self.dest_ip:
            iocs.append(f"dest_ip={self.dest_ip}")
        return iocs


class AIAnalysis(BaseModel):
    """The structured AI output that every analysis must produce.

    This is the canonical schema required for the pipeline:
    { summary, severity, confidence, rationale, mitre_techniques,
      recommended_action, evidence }
    """

    summary: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str
    mitre_techniques: list[str] = Field(default_factory=list)
    recommended_action: str
    evidence: list[str] = Field(default_factory=list)

    # Decision fields (used by automation; NOT part of the analyst-facing schema
    # but required for the pipeline to make a decision).
    verdict: Verdict = "ENRICH"
    is_false_positive: bool = False

    @field_validator("summary", "rationale", "recommended_action")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("field must not be empty")
        return v.strip()

    @field_validator("mitre_techniques", "evidence")
    @classmethod
    def _lists_of_str(cls, v: list) -> list:
        if not all(isinstance(x, str) for x in v):
            raise ValueError("must be a list of strings")
        return v


class TriageResult(BaseModel):
    """Full triage result returned by the engine."""

    alert_id: str
    verdict: Verdict
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str
    rationale: str
    mitre_techniques: list[str] = Field(default_factory=list)
    recommended_action: str
    evidence: list[str] = Field(default_factory=list)
    is_false_positive: bool = False
    needs_approval: bool = False
    decision_id: Optional[str] = None
    fallback_used: bool = False
    injection_detected: bool = False
    model: str = ""
    prompt_version: str = ""
    processing_time_ms: int = 0
    timestamp: str = ""


def parse_model_json(raw: str) -> dict[str, Any]:
    """Extract the first JSON object from a model response.

    Unlike the original implementation, this does NOT swallow failures: a
    response with no parseable JSON object raises ValueError so callers can
    treat it as malformed.
    """
    import json
    import re

    text = raw.strip()
    # Strip markdown code fences if the model wrapped the JSON.
    fence = re.search(r"```(?:json)?\s*(.*?)\s*```", text, re.DOTALL)
    if fence:
        text = fence.group(1).strip()
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise ValueError("no JSON object found in model output")
    try:
        parsed = json.loads(match.group())
    except json.JSONDecodeError as e:
        raise ValueError(f"model output is not valid JSON: {e}") from e
    if not isinstance(parsed, dict):
        raise ValueError("model output JSON is not an object")
    return parsed
