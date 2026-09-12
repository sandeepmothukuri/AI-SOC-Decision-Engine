# Testing Guide

What the test-suite covers and how to run it.

## 1. Test layers

| Layer | Location | Runs against |
|---|---|---|
| Unit — schema | `tests/test_schema.py` | `schemas.py` validation (malformed rejection) |
| Unit — safety rules | `tests/test_safety.py` | `safety.py` deterministic rules |
| Unit — analyzer | `tests/test_analyzer.py` | `analyzer.py` scenarios (offline + mock Ollama) |
| Unit — TheHive client | `tests/test_thehive_client.py` | `thehive_client.py` payload/path/idempotency |
| API | `tests/test_app_api.py` | FastAPI app in-process (ASGI) |
| Integration (chain) | `tests/test_integration_pipeline.py` | Shuffle workflow → MISP/Cortex mocks → engine → TheHive mock, over HTTP |
| Smoke test | `scripts/smoke_test.py` | full scenario matrix + metrics report |

## 2. Running the tests

```bash
# 1. create a virtualenv
python3 -m venv .venv && source .venv/bin/activate

# 2. install
pip install -r ai-engine/requirements.txt pytest

# 3. unit + integration tests
python3 -m pytest tests/ -q

# 4. end-to-end smoke test (writes docs/validation-results/)
python3 scripts/smoke_test.py

# 5. against a real Ollama (swap the backend)
python3 scripts/smoke_test.py --backend ollama --ollama-url http://localhost:11434
```

## 3. Scenario matrix

| # | Scenario | Where tested | Expected |
|---|---|---|---|
| 1 | True positive | unit + chain | ESCALATE |
| 2 | False positive | unit + chain | CLOSE, `is_false_positive=true` |
| 3 | Ambiguous | unit + chain | ENRICH |
| 4 | Missing IOC | unit + chain | ENRICH, confidence ≤ 0.5 |
| 5 | Malicious prompt / injection | unit + chain | ENRICH, `injection_detected=true` |
| 6 | MISP unavailable | chain | pipeline continues |
| 7 | Cortex unavailable | chain | pipeline continues (not wired) |
| 8 | Ollama unavailable | unit + chain | `fallback_used=true` |
| 9 | Malformed LLM output | unit + chain | rejected → fallback |
| 10 | Duplicate event | unit + chain | 2nd event skipped |

## 4. Mock inventory (`scripts/pipeline_harness.py`)

- `make_misp(enabled, found, threat_level)` — MISP IOC search.
- `make_cortex(enabled, malicious)` — Cortex analyser run.
- `make_thehive(enabled)` — records `POST /api/v1/case`.
- `make_ollama(response, enabled)` — canned `/api/generate`.
- `WorkflowRunner` — interprets the repo's `shuffle-workflows/*.json`.

## 5. Interpreting the smoke-test report

`docs/validation-results/latest.json` + `.md` + `smoke-test-console.txt`:

- `response_valid` — fraction of runs whose output satisfied the required schema.
- `automation_rate` — fraction of runs decided **without** human approval.
- `auto_case_creation_rate` — fraction of runs that created a TheHive case.
- `latency_ms` — sandbox wall-clock (mocked upstreams); not production numbers.
