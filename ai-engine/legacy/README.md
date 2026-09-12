# Legacy (pre-audit) AI engine sources

These are the original files as found at audit time (2026-09-12), preserved for
provenance and diffing. The hardened replacements live in `ai-engine/` root.

| Original | Notes |
|---|---|
| `app.py` | FastAPI server; no timeouts/fallback/approval; logs verdict but not confidence |
| `analyzer.py` | LangChain+Ollama; no schema enforcement, silent fallback on malformed JSON, deprecated MITRE IDs |
| `thehive_client.py` | Posts to `/api/case` (TheHive 4 path; TH5 uses `/api/v1/case`) |
