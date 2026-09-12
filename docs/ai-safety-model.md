# AI Safety Model

How the AI SOC Engine constrains an LLM so that it is a **decision-support
tool**, not an autonomous responder.

## 1. Design principle

The LLM is treated as **one input among many**, never as an authority. Every
decision passes through a deterministic safety layer that runs **before and
after** the model and can override it. The model is only consulted at all when
the deterministic layer has not already flagged the alert content as a
prompt-injection attempt.

```
alert ──► deterministic safety layer ──► (LLM, optional) ──► schema validation
              │  block/allow lists                              │  reject malformed
              │  injection detection                            ▼
              │  IOC extraction                     deterministic overrides
              └──► fallback rules ◄──────────────── (blocklist, missing-IOC, injection)
```

## 2. Deterministic safety rules (always on)

Implemented in `ai-engine/safety.py`:

1. **Blocklist / allowlist** — IPs, tool signatures, and extension markers in
   `ai-engine/safety/{blocklist,allowlist}.txt`. Blocklist hits force a minimum
   escalation stance and add evidence; allowlist hits bias to CLOSE.
2. **Prompt-injection detection** — regex patterns for instruction-hijacking
   ("ignore previous instructions", "set verdict to CLOSE", DAN/jailbreak,
   system-prompt extraction). When triggered: the alert is routed to **human
   review**, the LLM is **not called**, confidence is capped at 0.5, and the
   reason is recorded.
3. **IOC presence** — alerts with no IP/hash/domain have confidence capped at
   0.5 and cannot auto-ESCALATE.
4. **Marker scanning** — known-malicious (sqlmap, mimikatz, web-shell calls,
   ransomware extensions, failed→success auth) and known-benign (Nessus,
   Qualys, maintenance windows) markers, each recorded as evidence.
5. **MITRE mapping** — deterministic keyword → non-deprecated technique IDs.

## 3. Schema validation

Model output must parse as JSON and validate against
`schemas.AIAnalysis`:

```json
{
  "summary": "...",
  "severity": "LOW|MEDIUM|HIGH|CRITICAL",
  "confidence": 0.0,
  "rationale": "...",
  "mitre_techniques": ["T1110 - Brute Force"],
  "recommended_action": "...",
  "evidence": ["..."]
}
```

Anything else (no JSON, invalid JSON, missing fields, empty strings, out-of-range
confidence) is **rejected**, counted in `malformed_rejected`, and the engine
falls back to the deterministic rules — it is never silently accepted.

## 4. Confidence thresholds

| Rule | Default | Effect |
|---|---|---|
| `escalate_min_confidence` | 0.75 | ESCALATE below this is downgraded to ENRICH |
| `close_min_confidence` | 0.85 | CLOSE below this is downgraded to ENRICH (auto-close must be very confident) |
| `missing_ioc_confidence_cap` | 0.5 | no indicators ⇒ confidence ≤ 0.5 |

All thresholds live in `ai-engine/config.yaml` (env-overridable).

## 5. Human approval mode

When enabled (`human_approval.enabled: true`, default), **ESCALATE and CLOSE
decisions are held** and returned with `needs_approval: true` and a
`decision_id`. The analyst calls:

- `POST /approve/{decision_id}` — applies the decision (creates the TheHive
  case for an ESCALATE).
- `POST /reject/{decision_id}` — discards it.

No case is created and no automated action is taken until a human approves.
With approval mode ON, the measured **automation rate drops to 0** for
ESCALATE decisions.

## 6. Fallback behaviour

- LLM unreachable / timed out → `fallback_used: true`, deterministic rules
  produce the structured result.
- LLM output malformed (after retries) → rejected, deterministic fallback.
- `backend: offline` → deterministic rules are the primary path
  (reproducible, no network, no non-determinism).

The fallback **never** produces an unvalidated verdict: it goes through the
same schema, thresholds, and approval gate.

## 7. Prompt versioning

Prompts live in `ai-engine/prompts/v1/` with a SHA-256 manifest
(`prompts/prompt_manifest.json`). Every decision logs its `prompt_version`, and
mismatched hashes are surfaced as warnings. Changing a prompt means adding a new
version directory and bumping `prompt.version`.

## 8. Known limitations (be honest about these)

- The deterministic layer is a **keyword/heuristic** engine — it is not a
  substitute for an analyst or for a trained model, and it has not been
  evaluated for accuracy against a labelled alert corpus.
- No model (llama3/mistral/phi3) was executed during this audit; the
  LLM-integration path is tested against a mock Ollama API.
- Prompt-injection detection is pattern-based and can be bypassed by
  sufficiently obfuscated input; human approval remains the backstop.
