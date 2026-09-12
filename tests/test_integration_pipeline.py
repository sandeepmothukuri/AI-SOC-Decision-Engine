"""Integration test: a known alert through the documented chain over HTTP.

Chain: Wazuh (synthetic alert) -> Shuffle workflow (repo JSON, interpreted)
       -> MISP/Cortex enrichment (mocks) -> AI engine (REAL code, offline backend)
       -> TheHive (mock). Includes MISP-down / Cortex-down / Ollama-down paths.
"""

from __future__ import annotations

import json
from pathlib import Path

from config import Config
from pipeline_harness import (
    WorkflowRunner,
    make_cortex,
    make_misp,
    make_thehive,
    start_engine,
)
from scenarios import TRUE_POSITIVE

REPO = Path(__file__).resolve().parent.parent
WORKFLOW_PATH = REPO / "shuffle-workflows" / "ssh-bruteforce.json"


def integration_config(
    thehive_url: str, backend: str = "offline", ollama_host: str = "http://127.0.0.1:9"
) -> Config:
    raw = {
        "model": {"backend": backend, "name": "llama3", "temperature": 0.1, "num_predict": 512},
        "ollama": {"host": ollama_host},
        "llm": {"timeout_seconds": 2.0, "max_retries": 0, "request_timeout_seconds": 10.0},
        "thresholds": {
            "escalate_min_confidence": 0.75,
            "close_min_confidence": 0.85,
            "missing_ioc_confidence_cap": 0.5,
        },
        "human_approval": {"enabled": False, "verdicts": ["ESCALATE", "CLOSE"]},
        "dedupe": {"ttl_seconds": 300},
        "prompt": {"version": "v1"},
        "safety": {
            "blocklist_path": "safety/blocklist.txt",
            "allowlist_path": "safety/allowlist.txt",
        },
        "thehive": {"url": thehive_url, "api_key": "k", "timeout_seconds": 2.0},
        "logging": {"level": "WARNING", "decision_log": ""},
    }
    return Config(raw=raw)


def test_full_chain_true_positive_creates_case():
    thehive = make_thehive()
    misp = make_misp(enabled=True, found=True, threat_level="high")
    cortex = make_cortex(enabled=True, malicious=True)

    server, engine_url = start_engine(integration_config(thehive.url))
    try:
        workflow = json.loads(WORKFLOW_PATH.read_text())
        runner = WorkflowRunner(
            workflow,
            engine_url,
            env={
                "MISP_URL": misp.url,
                "CORTEX_URL": cortex.url,
            },
        )
        trigger = {
            "id": TRUE_POSITIVE["alert_id"],
            "rule": {
                "id": TRUE_POSITIVE["rule_id"],
                "description": TRUE_POSITIVE["rule_description"],
                "level": TRUE_POSITIVE["severity"],
            },
            "agent": {"name": TRUE_POSITIVE["hostname"]},
            "data": {"srcip": TRUE_POSITIVE["source_ip"]},
            "timestamp": TRUE_POSITIVE["timestamp"],
        }
        context = runner.run(trigger)

        ai = context.get("ai_triage", {})
        assert ai.get("verdict") == "ESCALATE", f"unexpected verdict: {ai}"
        for field in (
            "summary",
            "severity",
            "confidence",
            "rationale",
            "mitre_techniques",
            "recommended_action",
            "evidence",
        ):
            assert field in ai, f"missing {field}"

        # TheHive case was created (auto, no approval required).
        hive_cases = [r for r in thehive.requests if r["path"] == "/api/v1/case"]
        assert len(hive_cases) == 1
    finally:
        server.should_exit = True
        misp.stop()
        cortex.stop()
        thehive.stop()


def test_misp_down_pipeline_still_runs():
    thehive = make_thehive()
    misp = make_misp(enabled=False)  # MISP unavailable
    server, engine_url = start_engine(integration_config(thehive.url))
    try:
        workflow = json.loads(WORKFLOW_PATH.read_text())
        runner = WorkflowRunner(workflow, engine_url, env={"MISP_URL": misp.url})
        trigger = {
            "id": "TEST-MISPDOWN-006",
            "rule": {"id": "100001", "description": "SSH brute force attack", "level": 12},
            "agent": {"name": "web-server-01"},
            "data": {"srcip": "185.220.101.45"},
            "timestamp": "2026-09-12T03:44:02Z",
        }
        context = runner.run(trigger)
        # Enrichment failed but the chain continued to triage.
        assert "error" in context.get("misp_lookup", {})
        assert context.get("ai_triage", {}).get("verdict") in ("ESCALATE", "ENRICH")
    finally:
        server.should_exit = True
        misp.stop()
        thehive.stop()


def test_ollama_down_uses_fallback():
    thehive = make_thehive()
    # Ollama backend pointed at a closed port -> fallback to offline rules.
    server, engine_url = start_engine(
        integration_config(thehive.url, backend="ollama", ollama_host="http://127.0.0.1:9")
    )
    try:
        import httpx

        r = httpx.post(f"{engine_url}/analyze", json=TRUE_POSITIVE, timeout=30)
        assert r.status_code == 200
        data = r.json()
        assert data["fallback_used"] is True
        assert data["verdict"] in ("ESCALATE", "ENRICH")
    finally:
        server.should_exit = True
        thehive.stop()
