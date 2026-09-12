"""TheHive client: correct TH5 path, payload shape, idempotency, failure handling."""

from __future__ import annotations

import asyncio

from pipeline_harness import make_thehive
from thehive_client import TheHiveClient

ALERT = {
    "alert_id": "A-1",
    "source": "wazuh",
    "rule_id": "5712",
    "rule_description": "SSH brute force attack",
    "source_ip": "185.220.101.45",
    "dest_ip": "10.0.1.15",
    "hostname": "web-server-01",
    "timestamp": "2026-09-12T03:44:02Z",
    "raw_log": "Failed password ... Accepted password",
}

TRIAGE = {
    "verdict": "ESCALATE",
    "severity": "HIGH",
    "confidence": 0.9,
    "summary": "Brute force with success.",
    "rationale": "blocklist + markers",
    "mitre_techniques": ["T1110 - Brute Force"],
    "recommended_action": "Block.",
    "evidence": ["blocklist hit"],
    "model": "llama3",
    "prompt_version": "v1",
}


def run(coro):
    return asyncio.run(coro)


def test_case_posted_to_v1_path():
    hive = make_thehive()
    client = TheHiveClient(hive.url, "secret-key")
    run(client.create_case(ALERT, TRIAGE))
    req = hive.requests[0]
    hive.stop()
    assert req["path"] == "/api/v1/case"
    assert req["method"] == "POST"
    assert req["body"]["title"].startswith("[AI-SOC]")
    assert req["body"]["severity"] == 3  # HIGH -> 3
    assert "T1110" in req["body"]["tags"]


def test_custom_fields_shape():
    hive = make_thehive()
    client = TheHiveClient(hive.url, "k")
    run(client.create_case(ALERT, TRIAGE))
    cf = hive.requests[0]["body"].get("customFields", {})
    hive.stop()
    assert "ai-verdict" in cf
    assert "string" in cf["ai-verdict"] or "order" in cf["ai-verdict"]


def test_duplicate_case_suppressed():
    hive = make_thehive()
    client = TheHiveClient(hive.url, "k")
    run(client.create_case(ALERT, TRIAGE))
    run(client.create_case(ALERT, TRIAGE))
    hive.stop()
    assert len(hive.requests) == 1  # second call suppressed


def test_thehive_down_returns_none():
    hive = make_thehive(enabled=False)
    client = TheHiveClient(hive.url, "k")
    result = run(client.create_case(ALERT, TRIAGE))
    hive.stop()
    assert result is None
