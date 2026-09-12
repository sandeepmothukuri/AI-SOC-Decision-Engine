# Observability

What the AI SOC Engine emits, and how to monitor it.

## 1. Decision log (structured)

Every analysis writes one JSON line (stdout, or a file via
`logging.decision_log`):

```json
{"event": "ai_decision", "alert_id": "TEST-TP-001", "verdict": "ESCALATE",
 "severity": "CRITICAL", "confidence": 0.9, "needs_approval": false,
 "fallback_used": false, "injection_detected": false, "model": "llama3",
 "prompt_version": "v1", "processing_time_ms": 12}
```

This satisfies (and strengthens) the original README claim that decisions are
logged with timestamp/confidence — the original only logged verdict/severity
and dropped confidence.

## 2. Metrics endpoint — `GET /stats`

```json
{
  "analyzed": 5, "escalated": 1, "enriched": 3, "closed": 1,
  "pending_approval": 0, "needs_approval": 1,
  "malformed_rejected": 0, "injection_detected": 1, "fallbacks": 0,
  "errors": 0, "duplicates": 1,
  "enrichment": {"misp_hits": 2, "misp_misses": 8, "cortex_runs": 0},
  "latency": {"count": 5, "avg_ms": 28.0, "p50_ms": 23, "p95_ms": 62.6, "max_ms": 62.6}
}
```

| Counter | Meaning |
|---|---|
| `malformed_rejected` | LLM responses that failed schema validation |
| `injection_detected` | alerts flagged by the injection detector |
| `fallbacks` | analyses served by the deterministic engine because the LLM failed |
| `duplicates` | events skipped inside the dedupe window |
| `needs_approval` / `pending_approval` | approval-gated decisions / currently held |
| `enrichment.misp_*` | MISP hit/miss accounting |
| `latency.p*` | per-decision latency percentiles |

## 3. Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /health` | liveness + model/backend/prompt-version/approval-mode |
| `GET /config` | resolved configuration (secrets redacted) |
| `GET /stats` | counters + latency percentiles |
| `POST /approve/{id}` / `POST /reject/{id}` | human-approval actions |
| `X-Request-Id` header | per-request correlation id |

## 4. Measuring "processing latency"

`processing_time_ms` is measured inside the engine per analysis; the smoke test
also records whole-chain wall-clock per stage. Both are exposed in the report.
Latency from the smoke test is **sandbox-internal** (in-process engine + local
mocks) — treat it as a relative measure of code-path overhead, not a
deployment SLO.

## 5. Measuring "enrichment success"

`misp_hits` / `misp_misses` are derived from the `misp_context` the workflow
passes to the engine; the smoke test additionally classifies each run's MISP
step (`hit` / `miss` / `error`). Cortex runs are counted separately and are
**zero in the repo's workflow** (Cortex is not wired).

## 6. Error logging

- LLM timeouts/unavailability → ERROR lines with attempt counts.
- Malformed model output → ERROR + `malformed_rejected` increment.
- TheHive case-creation failures → ERROR with HTTP status/body (no crash).
- Unhandled exceptions → structured 500 with `request_id`.

Suggested further work (not implemented): export `/stats` to Prometheus,
ship decision logs to OpenSearch, and alert on rising
`fallbacks`/`malformed_rejected` rates.
