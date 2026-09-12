# Pipeline Validation

How the documented pipeline was validated, what was actually executed, and the
measured results. Every number here was produced by running the test-suite —
none are asserted by hand.

## 1. What is validated vs. what is mocked

| Component | In validation | Method |
|---|---|---|
| AI engine (`analyzer.py`, `safety.py`, `schemas.py`, `thehive_client.py`) | ✅ real code | pytest + smoke test (HTTP) |
| Prompt templates (`prompts/v1/*`) | ✅ real code | loaded + hash-verified per run |
| Shuffle workflow JSON | ⚠️ interpreted | faithful mini-runner (files are not native Shuffle format; see `shuffle-workflows/README.md`) |
| Wazuh / Suricata / Zeek detection | ⚠️ simulated | synthetic webhook payloads built from the repo's own test fixtures |
| MISP / Cortex / TheHive | ⚠️ mocked | local HTTP mocks with availability toggles |
| Ollama | ⚠️ mocked / not run | mock Ollama HTTP API for the HTTP path; a real multi-GB model was not run (no GPU in the audit sandbox) |

The honest position: **the AI engine is the real, tested code.** The upstream
SOC services are simulated because this sandbox has no Docker/GPU. Running the
identical smoke test against a live stack is a one-flag change
(`--backend ollama --ollama-url http://localhost:11434`).

## 2. The canonical smoke test

```bash
pip install -r ai-engine/requirements.txt pytest
python3 -m pytest tests/ -q
python3 scripts/smoke_test.py
```

The smoke test sends a **known test alert** (synthetic SSH brute-force with a
blocklisted source IP, clearly labelled test data) through the complete chain:

```
synthetic Wazuh webhook
  → Shuffle workflow (repo JSON, interpreted)
    → MISP lookup (mock, up/down)
    → AI engine POST /analyze (real code)
      → TheHive POST /api/v1/case (mock)
```

and asserts the structured response contains the required fields and a sane
decision for each scenario.

## 3. Measured results (2026-09-12)

Raw machine-readable output: `docs/validation-results/latest.json`.

### 3.1 Response validity (required schema enforced)

All 13 chain runs returned a response containing every required field
(`summary`, `severity`, `confidence`, `rationale`, `mitre_techniques`,
`recommended_action`, `evidence`) with in-range confidence → **13/13 valid
(100%)**. Malformed LLM output was rejected and fell back deterministically
(`ollama-malformed-output` variant).

### 3.2 Scenario behaviour

| Scenario | Observed outcome | Expected |
|---|---|---|
| True positive (brute force, blocklisted IP) | ESCALATE, conf 0.90 | ✅ |
| False positive (authorised Nessus scan) | CLOSE (`is_false_positive=true`) | ✅ |
| Ambiguous (outbound conn, no TI) | ENRICH | ✅ |
| Missing IOC | ENRICH, confidence ≤ 0.5 | ✅ |
| Prompt injection | ENRICH, `injection_detected=true`, LLM not trusted | ✅ |
| MISP down | chain continues, verdict still correct | ✅ |
| Cortex down | chain continues (Cortex not wired in workflow — recorded) | ✅ |
| Ollama down | `fallback_used=true`, valid structured result | ✅ |
| Malformed LLM output | rejected (`malformed_rejected` counter), fallback | ✅ |
| Duplicate event | 2nd event skipped (`duplicates=1`) | ✅ |
| Human approval ON | ESCALATE held (`needs_approval=true`), no auto-case | ✅ |

### 3.3 Metrics

| Metric | Value | How it was measured |
|---|---|---|
| Processing latency (harness) | offline-engine avg 30.7 ms (min 17.8, max 68.0) | wall-clock per chain run in the sandbox (in-process engine + mocks). **Not production end-to-end latency.** |
| Enrichment success | MISP hit 9/13, miss 3/13, error 1/13 (misp-down variant) | per-run `misp_step` classification |
| AI response validity | 13/13 (100%) | required-field + confidence-range check per response |
| False-positive behaviour | FP → CLOSE with rationale/evidence | deterministic safety layer + thresholds |
| Automation rate | 1.00 (approval off) / **0.00** (approval on for ESCALATE) | fraction of runs decided without human approval |
| Auto case-creation rate | 0.20 of core runs (only ESCALATE creates a case) | TheHive `POST /api/v1/case` count |

## 4. What was NOT validated (and is labelled as such)

- Live boot of Wazuh/Shuffle/TheHive/Cortex/MISP containers.
- Import of workflow JSONs into a live Shuffle.
- Real Ollama inference (no GPU; model not pulled).
- TheHive 5 case-template import + custom-field schema against live TH5.
- Suricata/Zeek (not present in the repository).
