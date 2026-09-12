# Screenshots

## Real, project-generated assets

| File | Origin |
|---|---|
| `ai-engine-triage-output.png` | Rendered from the **actual** `POST /analyze` JSON response captured during the smoke test (source: `../validation-results/example-triage-response.json`). |
| `smoke-test-output.png` | Rendered from the **actual** console output of `scripts/smoke_test.py` (source: `../validation-results/smoke-test-console.txt`). |

These two are regenerated from real captured output, not hand-drawn or
fabricated; the underlying raw files live in `../validation-results/`.

## Vendor / example originals (archived, NOT project screenshots)

`vendor-originals/` holds the 10 images that previously illustrated the README.
OCR + metadata forensics showed none of them depicts this project's deployment
(see `../audit-report.md` §4):

- `wazuh-*.png` — generic Wazuh module overview pages.
- `thehive-*.png` — TheHive/Cortex **documentation** screenshots.
- `shuffle-workflow.png` — Shuffle "[EMAIL] Phishing email handler" example
  (unrelated to this repo's workflows).
- `misp-dashboard.png` / `misp-trendings.png` — MISP demo data; the trendings
  view is dated **2017**.
- `ollama-openwebui.png` — Open WebUI with `gpt-4.1-nano` (a cloud model),
  contradicting the "local LLaMA 3" caption it used to carry.

They are kept for provenance only and are **not** referenced from the README.
