#!/usr/bin/env python3
"""
Reproducible end-to-end smoke test for the AI-Augmented SOC Lab.

Sends a known test alert through the complete documented chain:

    Wazuh alert (synthetic) -> Shuffle workflow (repo JSON, interpreted)
      -> MISP/Cortex enrichment (mock) -> AI engine (REAL code)
      -> TheHive case creation (mock)

And a scenario matrix (true positive, false positive, ambiguous, missing IOC,
prompt injection, MISP down, Cortex down, Ollama down, malformed LLM,
duplicate event), measuring only numbers actually produced by these runs.

What is real vs mocked is stated in docs/testing.md and printed in the report.

Usage:
    python3 scripts/smoke_test.py                 # full matrix, offline backend
    python3 scripts/smoke_test.py --backend ollama --ollama-url http://localhost:11434
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai-engine"))
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(REPO / "tests"))

from config import Config  # noqa: E402
from pipeline_harness import (  # noqa: E402
    WorkflowRunner,
    make_cortex,
    make_misp,
    make_ollama,
    make_thehive,
    start_engine,
)
from scenarios import (  # noqa: E402
    AMBIGUOUS,
    FALSE_POSITIVE,
    MALFORMED_LLM_ALERT,
    MISSING_IOC,
    PROMPT_INJECTION,
    TRUE_POSITIVE,
)

WORKFLOW_PATH = REPO / "shuffle-workflows" / "ssh-bruteforce.json"

REQUIRED_FIELDS = (
    "summary",
    "severity",
    "confidence",
    "rationale",
    "mitre_techniques",
    "recommended_action",
    "evidence",
)


def build_config(
    backend: str, ollama_host: str, thehive_url: str, approval: bool = False
) -> Config:
    raw = {
        "model": {"backend": backend, "name": "llama3", "temperature": 0.1, "num_predict": 512},
        "ollama": {"host": ollama_host},
        "llm": {"timeout_seconds": 2.0, "max_retries": 1, "request_timeout_seconds": 15.0},
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
        "thehive": {"url": thehive_url, "api_key": "smoke-key", "timeout_seconds": 2.0},
        "logging": {"level": "WARNING", "decision_log": ""},
    }
    return Config(raw=raw)


def to_wazuh_trigger(alert: dict) -> dict:
    """Convert a scenario alert dict into a Wazuh webhook-style payload.

    Includes the full raw log (as `full_log`) so the chain faithfully carries
    the test alert's evidence into the AI engine via `$exec.raw`.
    """
    return {
        "id": alert["alert_id"],
        "rule": {
            "id": alert.get("rule_id", ""),
            "description": alert.get("rule_description", ""),
            "level": alert.get("severity", 5),
        },
        "agent": {"name": alert.get("hostname", "")},
        "data": {"srcip": alert.get("source_ip", ""), "dstip": alert.get("dest_ip", "")},
        "full_log": alert.get("raw_log", ""),
        "timestamp": alert.get("timestamp", ""),
    }


def run_chain(engine_url: str, alert: dict, misp, cortex, thehive) -> dict:
    workflow = json.loads(WORKFLOW_PATH.read_text())
    runner = WorkflowRunner(
        workflow,
        engine_url,
        env={
            "MISP_URL": misp.url,
            "CORTEX_URL": cortex.url,
        },
    )
    trigger = to_wazuh_trigger(alert)
    t0 = time.perf_counter()
    context = runner.run(trigger)
    total_ms = (time.perf_counter() - t0) * 1000

    ai = context.get("ai_triage", {})
    return {
        "alert_id": alert["alert_id"],
        "total_ms": round(total_ms, 1),
        "ai_triage": ai,
        "trace": runner.trace,
        "misp_step": context.get("misp_lookup", {}),
    }


def validate_response(ai: dict) -> dict:
    ok = isinstance(ai, dict)
    missing = [f for f in REQUIRED_FIELDS if f not in ai or ai.get(f) in (None, "")]
    valid = ok and not missing
    conf = ai.get("confidence")
    conf_ok = isinstance(conf, (int, float)) and 0.0 <= float(conf) <= 1.0
    return {"valid": valid and conf_ok, "missing_fields": missing, "confidence_in_range": conf_ok}


def run_variant(
    name: str,
    backend: str,
    ollama_host: str,
    scenarios: list,
    misp_enabled: bool = True,
    cortex_enabled: bool = True,
    approval: bool = False,
    duplicate: bool = False,
) -> dict:
    thehive = make_thehive()
    cortex = make_cortex(enabled=cortex_enabled)
    server, engine_url = start_engine(
        build_config(backend, ollama_host, thehive.url, approval=approval)
    )
    runs = []
    try:
        for alert in scenarios:
            # Per-scenario MISP ground truth so enrichment reflects each alert.
            misp = make_misp(
                enabled=misp_enabled,
                found=bool((alert.get("misp_context") or {}).get("found")),
                threat_level=(alert.get("misp_context") or {}).get("threat_level", ""),
            )
            r = run_chain(engine_url, alert, misp, cortex, thehive)
            r["validation"] = validate_response(r["ai_triage"])
            runs.append(r)
            misp.stop()
            if duplicate:
                # Re-send the same alert to exercise dedupe over the full chain.
                misp2 = make_misp(
                    enabled=misp_enabled,
                    found=bool((alert.get("misp_context") or {}).get("found")),
                    threat_level=(alert.get("misp_context") or {}).get("threat_level", ""),
                )
                d = run_chain(engine_url, alert, misp2, cortex, thehive)
                d["validation"] = validate_response(d["ai_triage"])
                d["alert_id"] = alert["alert_id"] + "-dup"
                d["duplicate"] = True
                runs.append(d)
                misp2.stop()
    finally:
        server.should_exit = True
        cortex.stop()

    cases = [rq for rq in thehive.requests if rq["path"] == "/api/v1/case"]
    stats = summarize_runs(runs, cases, name)
    thehive.stop()
    return stats


def summarize_runs(runs: list, cases: list, name: str) -> dict:
    lat = [r["total_ms"] for r in runs]
    ai = [r for r in runs if r.get("ai_triage") and isinstance(r["ai_triage"], dict)]
    valid = sum(1 for r in runs if r["validation"]["valid"])
    verdicts = [r["ai_triage"].get("verdict") for r in ai]
    esc = verdicts.count("ESCALATE")
    enr = verdicts.count("ENRICH")
    clo = verdicts.count("CLOSE")
    fallbacks = sum(1 for r in ai if r["ai_triage"].get("fallback_used"))
    injections = sum(1 for r in ai if r["ai_triage"].get("injection_detected"))
    needs_approval = sum(1 for r in ai if r["ai_triage"].get("needs_approval"))
    dupes = sum(1 for r in runs if r.get("duplicate"))

    decided = len(ai) - dupes
    automation_rate = round((decided - needs_approval) / decided, 3) if decided else 0.0
    auto_case_rate = round(len(cases) / decided, 3) if decided else 0.0

    return {
        "variant": name,
        "runs": len(runs),
        "response_valid": f"{valid}/{len(runs)}",
        "response_valid_rate": round(valid / len(runs), 3) if runs else 0.0,
        "verdicts": {"ESCALATE": esc, "ENRICH": enr, "CLOSE": clo},
        "fallbacks": fallbacks,
        "injections_detected": injections,
        "needs_approval": needs_approval,
        "duplicates_skipped": dupes,
        "automation_rate": automation_rate,
        "auto_case_creation_rate": auto_case_rate,
        "thehive_cases_created": len(cases),
        "latency_ms": {
            "avg": round(sum(lat) / len(lat), 1) if lat else None,
            "min": round(min(lat), 1) if lat else None,
            "max": round(max(lat), 1) if lat else None,
        },
        "runs_detail": [
            {
                "alert_id": r["alert_id"],
                "verdict": (r["ai_triage"] or {}).get("verdict"),
                "severity": (r["ai_triage"] or {}).get("severity"),
                "confidence": (r["ai_triage"] or {}).get("confidence"),
                "fallback_used": (r["ai_triage"] or {}).get("fallback_used"),
                "injection_detected": (r["ai_triage"] or {}).get("injection_detected"),
                "valid": r["validation"]["valid"],
                "total_ms": r["total_ms"],
                "misp_step": (
                    "error"
                    if "error" in r.get("misp_step", {})
                    else ("hit" if r.get("misp_step", {}).get("found") else "miss")
                ),
            }
            for r in runs
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--report-dir", default=str(REPO / "docs" / "validation-results"))
    ap.add_argument("--no-report", action="store_true", help="don't write report files")
    args = ap.parse_args()

    out_dir = Path(args.report_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "environment": {
            "note": "No Docker/GPU in the audit sandbox: upstream services (MISP, Cortex, "
            "TheHive, Ollama) are mocked; the AI engine is the real code under test.",
        },
        "variants": [],
    }

    # 1. Deterministic offline engine across the core scenario matrix.
    core = [
        ("true_positive", TRUE_POSITIVE),
        ("false_positive", FALSE_POSITIVE),
        ("ambiguous", AMBIGUOUS),
        ("missing_ioc", MISSING_IOC),
        ("prompt_injection", PROMPT_INJECTION),
    ]
    report["variants"].append(
        run_variant("offline-engine", "offline", "http://127.0.0.1:9", [a for _, a in core])
    )

    # 2. MISP unavailable (enrichment failure path).
    report["variants"].append(
        run_variant(
            "misp-down", "offline", "http://127.0.0.1:9", [TRUE_POSITIVE], misp_enabled=False
        )
    )

    # 3. Cortex unavailable (measured; Cortex is NOT wired in the repo workflow).
    report["variants"].append(
        run_variant(
            "cortex-down", "offline", "http://127.0.0.1:9", [TRUE_POSITIVE], cortex_enabled=False
        )
    )

    # 4. Ollama unavailable -> deterministic fallback.
    report["variants"].append(
        run_variant("ollama-unavailable", "ollama", "http://127.0.0.1:9", [TRUE_POSITIVE])
    )

    # 5. Ollama returns malformed output -> rejected, fallback.
    bad = make_ollama("Sure, here is my (non-JSON) analysis of this alert.")
    report["variants"].append(
        run_variant("ollama-malformed-output", "ollama", bad.url, [MALFORMED_LLM_ALERT])
    )
    bad.stop()

    # 6. Ollama returns a valid structured response -> accepted.
    good = make_ollama(
        json.dumps(
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
    )
    report["variants"].append(
        run_variant("ollama-valid-output", "ollama", good.url, [TRUE_POSITIVE])
    )
    good.stop()

    # 7. Duplicate event handling (same alert re-sent).
    report["variants"].append(
        run_variant(
            "duplicate-event", "offline", "http://127.0.0.1:9", [TRUE_POSITIVE], duplicate=True
        )
    )

    # 8. Human-approval mode (ESCALATE held for analyst).
    report["variants"].append(
        run_variant(
            "human-approval-mode", "offline", "http://127.0.0.1:9", [TRUE_POSITIVE], approval=True
        )
    )

    # Print + persist.
    print_report(report)
    if not args.no_report:
        (out_dir / f"smoke-test-{stamp}.json").write_text(json.dumps(report, indent=2) + "\n")
        (out_dir / "latest.json").write_text(json.dumps(report, indent=2) + "\n")
        (out_dir / f"smoke-test-{stamp}.md").write_text(render_markdown(report))
        print(f"\nReport written to {out_dir}")
    return 0


def print_report(report: dict) -> None:
    print("\n" + "=" * 78)
    print(" AI-SOC LAB SMOKE TEST — measured results (mocked upstreams; real engine)")
    print("=" * 78)
    for v in report["variants"]:
        lat = v["latency_ms"]
        print(f"\n[{v['variant']}]  runs={v['runs']}  valid={v['response_valid']}")
        print(
            f"   verdicts: {v['verdicts']}  fallbacks={v['fallbacks']} "
            f"injections={v['injections_detected']} needs_approval={v['needs_approval']} "
            f"dupes={v['duplicates_skipped']}"
        )
        print(
            f"   automation_rate={v['automation_rate']}  "
            f"auto_case_creation_rate={v['auto_case_creation_rate']}  "
            f"thehive_cases={v['thehive_cases_created']}"
        )
        print(f"   latency avg={lat['avg']}ms min={lat['min']}ms max={lat['max']}ms")
    print("\n" + "=" * 78)


def render_markdown(report: dict) -> str:
    lines = [
        "# AI-SOC Lab — Smoke Test Report",
        "",
        f"Generated: `{report['generated_at']}`",
        "",
        "> **Environment note:** no Docker/GPU in the audit sandbox — MISP, Cortex,",
        "> TheHive and Ollama are mocked HTTP services; the AI engine"
        "> (analyzer, safety rules, schema validation, TheHive client) is the real code.",
        "",
        "| Variant | Runs | Valid responses | Verdicts (E/N/C) | Fallbacks | Automation rate | Auto case rate | Latency avg/ min/ max (ms) |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for v in report["variants"]:
        vd = v["verdicts"]
        lat = v["latency_ms"]
        lines.append(
            f"| {v['variant']} | {v['runs']} | {v['response_valid']} "
            f"({v['response_valid_rate']:.0%}) | {vd['ESCALATE']}/{vd['ENRICH']}/{vd['CLOSE']} "
            f"| {v['fallbacks']} | {v['automation_rate']:.0%} | {v['auto_case_creation_rate']:.0%} "
            f"| {lat['avg']} / {lat['min']} / {lat['max']} |"
        )
    lines += ["", "## Per-run detail", ""]
    for v in report["variants"]:
        lines.append(f"### {v['variant']}")
        for r in v["runs_detail"]:
            lines.append(
                f"- `{r['alert_id']}` → {r['verdict']}/{r['severity']} "
                f"(conf {r['confidence']}) fallback={r['fallback_used']} "
                f"injection={r['injection_detected']} misp={r['misp_step']} {r['total_ms']}ms"
            )
        lines.append("")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    sys.exit(main())
