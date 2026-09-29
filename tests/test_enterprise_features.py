"""Comprehensive test suite for enterprise AI SOC Decision Engine capabilities.

Covers:
1. Analyst Feedback Loop & Continuous Evaluation (Active Learning, Drift, Few-Shot)
2. Enterprise PII and Secret Redactor (RFC 1918 IPs, Passwords, Tokens, Hostnames)
3. Multi-Provider LLM Gateway (Ollama, Azure OpenAI, OpenAI, Groq, Anthropic, Bedrock)
4. Prometheus Metrics & Exposition (/metrics)
5. MITRE ATT&CK Navigator Layer Generator (/export/attack-layer & CLI)
6. Structured Outputs & Deterministic Schema Constraints
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "ai-engine"))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from analyzer import AlertAnalyzer
from app import create_app
from attack_layer import AttackLayerGenerator
from config import Config
from feedback import FeedbackStore, FeedbackSubmission
from llm_backends import (
    AnthropicBackend,
    AzureOpenAIBackend,
    GroqBackend,
    OllamaBackend,
    OpenAIBackend,
    create_llm_backend,
)
from metrics import MetricsCollector, metrics_registry
from redaction import Redactor
from schemas import AIAnalysis, parse_model_json


# -------------------------------------------------------------------------- #
# 1. Analyst Feedback Loop & Active Learning Tests
# -------------------------------------------------------------------------- #
def test_feedback_store_approval_and_rejection(tmp_path):
    db_path = tmp_path / "test_feedback.db"
    store = FeedbackStore(db_path)

    alert = {"alert_id": "ALERT-100", "rule_id": "5712", "source_ip": "185.220.101.45"}
    analysis = AIAnalysis(
        summary="SSH brute force",
        severity="CRITICAL",
        confidence=0.92,
        rationale="Known attack pattern",
        mitre_techniques=["T1110"],
        recommended_action="Block IP",
        evidence=["Multiple failed attempts"],
        verdict="ESCALATE",
    )

    # 1. Record Approval
    appr_sub = FeedbackSubmission(
        reason_code="CORRECT_TRIAGE",
        analyst_id="analyst-lead",
        notes="Confirmed brute force followed by success",
    )
    rec1 = store.record_feedback("dec-001", "APPROVE", alert, analysis, appr_sub)
    assert rec1["action"] == "APPROVE"
    assert rec1["reason_code"] == "CORRECT_TRIAGE"

    # 2. Record Rejection
    rej_sub = FeedbackSubmission(
        reason_code="FALSE_POSITIVE",
        analyst_id="analyst-tier2",
        notes="Authorized internal security audit",
        corrected_verdict="CLOSE",
        corrected_severity="LOW",
    )
    rec2 = store.record_feedback("dec-002", "REJECT", alert, analysis, rej_sub)
    assert rec2["action"] == "REJECT"
    assert rec2["reason_code"] == "FALSE_POSITIVE"

    # 3. Stats & Active Learning
    stats = store.get_stats()
    assert stats["total_feedback"] == 2
    assert stats["approvals"] == 1
    assert stats["rejections"] == 1
    assert stats["approval_rate"] == 0.5
    assert stats["false_positive_reduction_rate"] == 0.5
    assert "FALSE_POSITIVE" in stats["reasons_breakdown"]

    # 4. Few-shot retrieval
    examples = store.get_few_shot_examples(limit=5)
    assert len(examples) == 1
    assert examples[0]["decision"]["verdict"] == "ESCALATE"
    assert examples[0]["reason"] == "CORRECT_TRIAGE"

    # 5. Dataset export
    dataset = store.export_dataset()
    assert len(dataset) == 2


def test_feedback_drift_detection(tmp_path):
    db_path = tmp_path / "drift_test.db"
    store = FeedbackStore(db_path)
    alert = {"alert_id": "ALERT-D"}
    analysis = {"verdict": "ESCALATE", "severity": "HIGH", "confidence": 0.8}

    # Simulate heavy rejection drift (e.g. model misclassifying benign traffic)
    for i in range(10):
        store.record_feedback(
            f"dec-{i}",
            "REJECT",
            alert,
            analysis,
            FeedbackSubmission(reason_code="FALSE_POSITIVE"),
        )

    stats = store.get_stats()
    assert stats["drift_detected"] is True
    assert stats["recent_rejection_rate"] == 1.0


# -------------------------------------------------------------------------- #
# 2. Enterprise PII & Secret Redactor Tests
# -------------------------------------------------------------------------- #
def test_redactor_private_ip_masking():
    redactor = Redactor(enabled=True)
    # RFC 1918 IPs should be masked, external IPs preserved
    text = "Traffic from 10.0.1.55 and 192.168.1.100 to public DNS 8.8.8.8 and attacker 185.220.101.45"
    sanitized, counts = redactor.redact_text(text)

    assert "[INTERNAL_IP_1]" in sanitized
    assert "[INTERNAL_IP_2]" in sanitized
    assert "10.0.1.55" not in sanitized
    assert "192.168.1.100" not in sanitized
    assert "8.8.8.8" in sanitized
    assert "185.220.101.45" in sanitized
    assert counts["ips"] == 2


def test_redactor_credentials_and_secrets():
    redactor = Redactor(enabled=True)
    text = (
        "User login failed: password=SuperSecretPassword123! | "
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token | "
        "api_key=ak_live_998877665544332211"
    )
    sanitized, counts = redactor.redact_text(text)

    assert "[REDACTED_CREDENTIAL]" in sanitized
    assert "SuperSecretPassword123!" not in sanitized
    assert "eyJhbGciOiJIUzI1Ni" not in sanitized
    assert "ak_live_998877" not in sanitized
    assert counts["credentials"] >= 2


def test_redactor_internal_hosts_and_paths():
    redactor = Redactor(enabled=True)
    text = (
        r"Target host DC01.corp executed process C:\Users\john.doe\AppData\malware.exe "
        "and /home/security/scripts/run.sh on server.local"
    )
    sanitized, counts = redactor.redact_text(text)

    assert "DC01.corp" not in sanitized
    assert "server.local" not in sanitized
    assert "C:\\Users\\[REDACTED_USER]\\" in sanitized
    assert "/home/[REDACTED_USER]/" in sanitized


def test_redactor_full_alert():
    redactor = Redactor(enabled=True)
    alert = {
        "alert_id": "TEST-RED-001",
        "source_ip": "10.20.30.40",
        "dest_ip": "172.16.0.5",
        "hostname": "finance-srv01.corp",
        "raw_log": "sshd password=PlainTextAdminPass from 10.20.30.40",
    }
    sanitized, counts = redactor.redact_alert(alert)

    assert sanitized["source_ip"].startswith("[INTERNAL_IP_")
    assert sanitized["dest_ip"].startswith("[INTERNAL_IP_")
    assert "PlainTextAdminPass" not in sanitized["raw_log"]
    assert "finance-srv01.corp" not in sanitized["hostname"]


# -------------------------------------------------------------------------- #
# 3. Multi-Provider LLM Gateway Tests
# -------------------------------------------------------------------------- #
def test_create_llm_backend_factory():
    # 1. Ollama
    cfg_ollama = Config(raw={"model": {"backend": "ollama", "name": "llama3"}})
    b_ollama = create_llm_backend(cfg_ollama)
    assert isinstance(b_ollama, OllamaBackend)
    assert b_ollama.model == "llama3"

    # 2. Azure OpenAI
    cfg_azure = Config(
        raw={
            "model": {"backend": "azure_openai"},
            "azure_openai": {
                "endpoint": "https://test.openai.azure.com",
                "api_key": "testkey",
                "deployment": "gpt-4o",
            },
        }
    )
    b_azure = create_llm_backend(cfg_azure)
    assert isinstance(b_azure, AzureOpenAIBackend)
    assert b_azure.deployment == "gpt-4o"

    # 3. OpenAI Compatible
    cfg_openai = Config(
        raw={
            "model": {"backend": "openai", "name": "gpt-4o-mini"},
            "openai": {"api_key": "sk-test", "base_url": "https://api.openai.com/v1"},
        }
    )
    b_openai = create_llm_backend(cfg_openai)
    assert isinstance(b_openai, OpenAIBackend)

    # 4. Groq
    cfg_groq = Config(
        raw={
            "model": {"backend": "groq", "name": "llama-3.3-70b-versatile"},
            "groq": {"api_key": "gsk-test"},
        }
    )
    b_groq = create_llm_backend(cfg_groq)
    assert isinstance(b_groq, GroqBackend)

    # 5. Anthropic
    cfg_anthropic = Config(
        raw={
            "model": {"backend": "anthropic", "name": "claude-3-5-sonnet-20241022"},
            "anthropic": {"api_key": "sk-ant-test"},
        }
    )
    b_anthropic = create_llm_backend(cfg_anthropic)
    assert isinstance(b_anthropic, AnthropicBackend)

    # 6. Offline
    cfg_offline = Config(raw={"model": {"backend": "offline"}})
    b_offline = create_llm_backend(cfg_offline)
    assert b_offline is None


# -------------------------------------------------------------------------- #
# 4. Prometheus Metrics Tests
# -------------------------------------------------------------------------- #
def test_prometheus_metrics_registry():
    collector = MetricsCollector()
    collector.record_decision("ESCALATE", 0.045)
    collector.record_decision("CLOSE", 0.120)
    collector.record_injection()
    collector.record_fallback()
    collector.record_malformed()
    collector.record_duplicate()
    collector.record_tokens("ollama", "llama3", 350)
    collector.record_feedback("APPROVE", "CORRECT_TRIAGE")
    collector.record_redactions({"ips": 2, "credentials": 1})

    rendered = collector.render_prometheus_exposition()

    assert 'soc_decisions_total{verdict="ESCALATE"} 1' in rendered
    assert 'soc_decisions_total{verdict="CLOSE"} 1' in rendered
    assert "soc_triage_latency_seconds_bucket" in rendered
    assert "soc_prompt_injections_total 1" in rendered
    assert "soc_llm_fallbacks_total 1" in rendered
    assert "soc_llm_malformed_rejected_total 1" in rendered
    assert "soc_dedupe_duplicates_total 1" in rendered
    assert 'soc_llm_token_usage_total{provider="ollama",model="llama3"} 350' in rendered
    assert 'soc_feedback_total{action="APPROVE",reason_code="CORRECT_TRIAGE"} 1' in rendered
    assert 'soc_redactions_total{category="ips"} 2' in rendered


# -------------------------------------------------------------------------- #
# 5. MITRE ATT&CK Navigator Layer Generator Tests
# -------------------------------------------------------------------------- #
def test_attack_layer_generator():
    generator = AttackLayerGenerator(name="Test SOC Coverage")
    generator.record_decision(["T1110 - Brute Force"], severity="CRITICAL", verdict="ESCALATE")
    generator.record_decision(["T1046 - Port Scan"], severity="HIGH", verdict="ESCALATE")
    generator.record_decision(["T1071.004"], severity="HIGH", verdict="ESCALATE")

    layer = generator.generate_layer(min_score=0)

    assert layer["name"] == "Test SOC Coverage"
    assert layer["versions"]["navigator"] == "4.5"
    assert layer["domain"] == "enterprise-attack"

    tech_ids = [t["techniqueID"] for t in layer["techniques"]]
    assert "T1110" in tech_ids
    assert "T1046" in tech_ids
    assert "T1071.004" in tech_ids

    # Check color gradient assigned
    t1110_entry = next(t for t in layer["techniques"] if t["techniqueID"] == "T1110")
    assert t1110_entry["score"] > 50
    assert t1110_entry["color"].startswith("#")


# -------------------------------------------------------------------------- #
# 6. Structured Outputs & Schema Constraint Parsing Tests
# -------------------------------------------------------------------------- #
def test_parse_model_json_direct_fastpath():
    valid_json = (
        '{"summary": "Test alert", "severity": "HIGH", "confidence": 0.9, '
        '"rationale": "Clear evidence", "mitre_techniques": ["T1110"], '
        '"recommended_action": "Block", "evidence": ["Log match"]}'
    )
    parsed = parse_model_json(valid_json)
    assert parsed["summary"] == "Test alert"
    assert parsed["severity"] == "HIGH"


def test_parse_model_json_markdown_fenced():
    fenced_json = (
        "Here is the triage output:\n```json\n"
        '{"summary": "Fenced alert", "severity": "LOW", "confidence": 0.8, '
        '"rationale": "Benign", "mitre_techniques": [], '
        '"recommended_action": "Ignore", "evidence": []}\n```'
    )
    parsed = parse_model_json(fenced_json)
    assert parsed["summary"] == "Fenced alert"


def test_parse_model_json_invalid_raises():
    with pytest.raises(ValueError, match="no JSON object found"):
        parse_model_json("Sorry, I am an AI and cannot process this request.")


# -------------------------------------------------------------------------- #
# 7. End-to-End FastAPI Integration Tests for New Endpoints
# -------------------------------------------------------------------------- #
def test_app_enterprise_endpoints(tmp_path):
    cfg = Config(
        raw={
            "model": {"backend": "offline"},
            "human_approval": {"enabled": True, "verdicts": ["ESCALATE", "CLOSE"]},
            "feedback": {"db_path": str(tmp_path / "app_feedback.db")},
            "thehive": {"url": "http://127.0.0.1:9", "api_key": "dummy"},
        }
    )
    app = create_app(cfg)
    client = TestClient(app)

    # 1. Test /metrics
    resp_metrics = client.get("/metrics")
    assert resp_metrics.status_code == 200
    assert "text/plain" in resp_metrics.headers["content-type"]
    assert "soc_decisions_total" in resp_metrics.text

    # 2. Trigger an alert that enters approval gate
    alert_payload = {
        "alert_id": "TEST-APP-001",
        "source": "wazuh",
        "rule_id": "5712",
        "rule_description": "SSH brute force attempt",
        "severity": 12,
        "source_ip": "185.220.101.45",
        "raw_log": "sshd brute force followed by success",
    }
    resp_triage = client.post("/analyze", json=alert_payload)
    assert resp_triage.status_code == 200
    triage_data = resp_triage.json()
    assert triage_data["needs_approval"] is True
    decision_id = triage_data["decision_id"]
    assert decision_id is not None

    # 3. Test /approve with FeedbackSubmission body
    approval_body = {
        "reason_code": "CORRECT_TRIAGE",
        "analyst_id": "analyst-lead-01",
        "notes": "Verified threat intelligence and external source",
    }
    resp_appr = client.post(f"/approve/{decision_id}", json=approval_body)
    assert resp_appr.status_code == 200
    appr_data = resp_appr.json()
    assert appr_data["status"] == "approved"
    assert appr_data["feedback"]["reason_code"] == "CORRECT_TRIAGE"

    # 4. Test /feedback/stats
    resp_stats = client.get("/feedback/stats")
    assert resp_stats.status_code == 200
    fb_stats = resp_stats.json()
    assert fb_stats["total_feedback"] >= 1
    assert fb_stats["approvals"] >= 1

    # 5. Test /feedback/few-shot
    resp_few_shot = client.get("/feedback/few-shot")
    assert resp_few_shot.status_code == 200
    assert "few_shot_examples" in resp_few_shot.json()

    # 6. Test /feedback/export
    resp_export = client.get("/feedback/export")
    assert resp_export.status_code == 200
    assert len(resp_export.json()["dataset"]) >= 1

    # 7. Test /export/attack-layer
    resp_attack = client.get("/export/attack-layer")
    assert resp_attack.status_code == 200
    layer = resp_attack.json()
    assert layer["versions"]["navigator"] == "4.5"
    assert len(layer["techniques"]) > 0
