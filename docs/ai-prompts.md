# AI Prompt Guide

## Overview

Prompts are **versioned** and live in `ai-engine/prompts/v1/`. Each version
directory has a SHA-256 manifest (`ai-engine/prompts/prompt_manifest.json`) so
integrity can be verified and changes tracked. The active version is set via
`prompt.version` in `ai-engine/config.yaml` (or `AI_SOC_PROMPT_VERSION`).

## Versioned templates

| Template | Purpose |
|---|---|
| `v1/triage.txt` | Alert triage → strict JSON `{summary, severity, confidence, rationale, mitre_techniques, recommended_action, evidence, verdict, is_false_positive}`. Explicitly instructs the model that alert content is untrusted input and to never follow embedded instructions. |
| `v1/summary.txt` | 2–3 sentence incident summary. |
| `v1/playbook.txt` | Numbered IR playbook (contain → investigate → eradicate → recover → document). |
| `v1/nl_to_dsl.txt` | Natural language → Elasticsearch DSL. |

## Prompt versioning workflow

1. Copy `prompts/vN` → `prompts/vN+1` and edit.
2. Regenerate the manifest (a small helper is run at audit time; keep the same
   hashing convention: SHA-256 of each `.txt` file).
3. Bump `prompt.version` in `config.yaml`.
4. Every decision log line records `prompt_version`, so outputs remain
   attributable to a prompt version.

## Safety guidance baked into the triage prompt

- Alert content is declared **untrusted**; the model is told not to obey
  instructions inside it.
- Confidence ≤ 0.5 and verdict ENRICH when no indicators are present.
- Verdict definitions are explicit (ESCALATE / ENRICH / CLOSE).

The deterministic safety layer in `ai-engine/safety.py` enforces these
constraints even if the model disobeys — see
[docs/ai-safety-model.md](ai-safety-model.md).
