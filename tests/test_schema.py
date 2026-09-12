"""Schema validation: malformed AI responses must be rejected."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from schemas import AIAnalysis, parse_model_json

VALID = {
    "summary": "SSH brute force followed by success",
    "severity": "HIGH",
    "confidence": 0.9,
    "rationale": "Blocklisted source IP and brute-force markers.",
    "mitre_techniques": ["T1110 - Brute Force"],
    "recommended_action": "Block source and reset credentials.",
    "evidence": ["blocklist hit", "failed+success auth"],
    "verdict": "ESCALATE",
    "is_false_positive": False,
}


def test_parse_valid_json_object():
    raw = "Here is the answer:\n```json\n" + __import__("json").dumps(VALID) + "\n```"
    parsed = parse_model_json(raw)
    assert parsed["verdict"] == "ESCALATE"


def test_parse_rejects_no_json():
    with pytest.raises(ValueError):
        parse_model_json("I am a helpful assistant, the verdict is ESCALATE")


def test_parse_rejects_invalid_json():
    with pytest.raises(ValueError):
        parse_model_json('{"verdict": "ESCALATE", "confidence": ')


def test_parse_rejects_non_object():
    with pytest.raises(ValueError):
        parse_model_json('["not", "an", "object"]')


def test_analysis_accepts_valid():
    ai = AIAnalysis.model_validate(VALID)
    assert ai.verdict == "ESCALATE"
    assert ai.confidence == 0.9


def test_analysis_rejects_missing_required_fields():
    with pytest.raises(ValidationError):
        AIAnalysis.model_validate({"severity": "HIGH"})


def test_analysis_rejects_empty_summary():
    bad = dict(VALID, summary="   ")
    with pytest.raises(ValidationError):
        AIAnalysis.model_validate(bad)


def test_analysis_rejects_bad_severity_enum():
    bad = dict(VALID, severity="EXTREME")
    with pytest.raises(ValidationError):
        AIAnalysis.model_validate(bad)


def test_analysis_rejects_confidence_out_of_range():
    bad = dict(VALID, confidence=7.5)
    with pytest.raises(ValidationError):
        AIAnalysis.model_validate(bad)


def test_analysis_rejects_non_string_mitre():
    bad = dict(VALID, mitre_techniques=[123])
    with pytest.raises(ValidationError):
        AIAnalysis.model_validate(bad)
