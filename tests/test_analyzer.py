"""End-to-end analyzer behaviour across the required scenario matrix."""

from __future__ import annotations

import asyncio
import json

from analyzer import AlertAnalyzer
from config import Config
from scenarios import (
    AMBIGUOUS,
    FALSE_POSITIVE,
    MALFORMED_LLM_ALERT,
    MISSING_IOC,
    PROMPT_INJECTION,
    TRUE_POSITIVE,
)


def run(coro):
    return asyncio.run(coro)


def make_llm_config(mock_url=None, retries=0, approval=False):
    raw = {
        "model": {
            "backend": "ollama" if mock_url else "offline",
            "name": "llama3",
            "temperature": 0.1,
            "num_predict": 512,
        },
        "ollama": {"host": mock_url or "http://127.0.0.1:9"},
        "llm": {"timeout_seconds": 2.0, "max_retries": retries, "request_timeout_seconds": 10.0},
        "thresholds": {
            "escalate_min_confidence": 0.75,
            "close_min_confidence": 0.85,
            "missing_ioc_confidence_cap": 0.5,
        },
        "human_approval": {"enabled": approval, "verdicts": ["ESCALATE", "CLOSE"]},
        "dedupe": {"ttl_seconds": 300},
        "prompt": {"version": "v1"},
        "safety": {
            "blocklist_path": "safety/blocklist.txt",
            "allowlist_path": "safety/allowlist.txt",
        },
        "thehive": {"url": "http://127.0.0.1:9", "api_key": "", "timeout_seconds": 2.0},
        "logging": {"level": "WARNING", "decision_log": ""},
    }
    return Config(raw=raw)


def required_schema_fields(result) -> list[str]:
    """Return the required analyst-facing fields present on the result."""
    return [
        f
        for f in (
            "summary",
            "severity",
            "confidence",
            "rationale",
            "mitre_techniques",
            "recommended_action",
            "evidence",
        )
        if hasattr(result, f) and getattr(result, f) not in (None, "", [])
    ]


# --------------------------------------------------------------------------- #
# Offline backend scenarios
# --------------------------------------------------------------------------- #
def test_true_positive_escalates(offline_config):
    r = run(AlertAnalyzer(offline_config).analyze(TRUE_POSITIVE))
    assert r.verdict == "ESCALATE"
    assert r.severity in ("HIGH", "CRITICAL")
    assert r.confidence >= 0.75
    assert all(
        f in required_schema_fields(r)
        for f in (
            "summary",
            "severity",
            "confidence",
            "rationale",
            "mitre_techniques",
            "recommended_action",
            "evidence",
        )
    )


def test_false_positive_closes(offline_config):
    r = run(AlertAnalyzer(offline_config).analyze(FALSE_POSITIVE))
    assert r.verdict == "CLOSE"
    assert r.is_false_positive is True


def test_ambiguous_enriches(offline_config):
    r = run(AlertAnalyzer(offline_config).analyze(AMBIGUOUS))
    assert r.verdict == "ENRICH"


def test_missing_ioc_caps_confidence(offline_config):
    r = run(AlertAnalyzer(offline_config).analyze(MISSING_IOC))
    assert r.confidence <= 0.5
    assert r.verdict in ("ENRICH",)


def test_prompt_injection_forces_human_review(offline_config):
    r = run(AlertAnalyzer(offline_config).analyze(PROMPT_INJECTION))
    assert r.injection_detected is True
    assert r.verdict == "ENRICH"
    assert r.needs_approval is False  # approval off in this config; verdict is ENRICH anyway


def test_duplicate_event_skipped(offline_config):
    analyzer = AlertAnalyzer(offline_config)
    first = run(analyzer.analyze(TRUE_POSITIVE))
    second = run(analyzer.analyze(TRUE_POSITIVE))
    assert first.verdict == "ESCALATE"
    assert second.verdict == "ENRICH"
    assert "duplicate" in second.evidence[0]
    assert analyzer.get_stats()["duplicates"] == 1


def test_duplicate_distinct_alerts_not_skipped(offline_config):
    analyzer = AlertAnalyzer(offline_config)
    run(analyzer.analyze(TRUE_POSITIVE))
    second = run(
        analyzer.analyze(dict(TRUE_POSITIVE, alert_id="TEST-TP-001b", source_ip="203.0.113.9"))
    )
    assert "duplicate" not in second.evidence[0]


# --------------------------------------------------------------------------- #
# LLM-path scenarios (mock Ollama)
# --------------------------------------------------------------------------- #
VALID_LLM = json.dumps(
    {
        "summary": "SSH brute force followed by success from a blocklisted IP.",
        "severity": "HIGH",
        "confidence": 0.92,
        "rationale": "Blocklisted source and failed->success auth pattern.",
        "mitre_techniques": ["T1110 - Brute Force"],
        "recommended_action": "Block source and reset credentials.",
        "evidence": ["blocklist hit", "auth success"],
        "verdict": "ESCALATE",
        "is_false_positive": False,
    }
)


def test_llm_valid_response_accepted():
    from pipeline_harness import make_ollama

    ollama = make_ollama(VALID_LLM)
    cfg = make_llm_config(mock_url=ollama.url)
    r = run(AlertAnalyzer(cfg).analyze(TRUE_POSITIVE))
    ollama.stop()
    assert r.verdict == "ESCALATE"
    assert r.fallback_used is False
    assert r.prompt_version == "v1"


def test_llm_malformed_output_rejected_and_falls_back():
    from pipeline_harness import make_ollama

    ollama = make_ollama("Sure! Here is my analysis of the alert. It looks bad.")
    cfg = make_llm_config(mock_url=ollama.url)
    analyzer = AlertAnalyzer(cfg)
    r = run(analyzer.analyze(MALFORMED_LLM_ALERT))
    ollama.stop()
    assert r.fallback_used is True
    assert analyzer.get_stats()["malformed_rejected"] >= 1
    # Deterministic fallback still yields a valid structured result.
    assert r.verdict in ("ESCALATE", "ENRICH")


def test_ollama_unavailable_falls_back_gracefully():
    cfg = make_llm_config(mock_url="http://127.0.0.1:9")
    analyzer = AlertAnalyzer(cfg)
    r = run(analyzer.analyze(TRUE_POSITIVE))
    assert r.fallback_used is True
    assert r.verdict in ("ESCALATE", "ENRICH")
    assert analyzer.get_stats()["fallbacks"] >= 1


# --------------------------------------------------------------------------- #
# Confidence thresholds + human approval
# --------------------------------------------------------------------------- #
def test_low_confidence_escalate_downgraded():
    from pipeline_harness import make_ollama

    low_conf = json.dumps({**json.loads(VALID_LLM), "confidence": 0.3})
    ollama = make_ollama(low_conf)
    cfg = make_llm_config(mock_url=ollama.url)
    r = run(AlertAnalyzer(cfg).analyze(TRUE_POSITIVE))
    ollama.stop()
    assert r.verdict == "ENRICH"  # below escalate_min_confidence


def test_human_approval_holds_escalate(approval_config):
    analyzer = AlertAnalyzer(approval_config)
    r = run(analyzer.analyze(TRUE_POSITIVE))
    assert r.verdict == "ESCALATE"
    assert r.needs_approval is True
    assert r.decision_id is not None

    held = analyzer.approve(r.decision_id)
    assert held is not None
    assert held["analysis"].verdict == "ESCALATE"


def test_human_approval_reject(approval_config):
    analyzer = AlertAnalyzer(approval_config)
    r = run(analyzer.analyze(TRUE_POSITIVE))
    assert analyzer.reject(r.decision_id) is not None
    assert analyzer.approve(r.decision_id) is None  # already consumed
