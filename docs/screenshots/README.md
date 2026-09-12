# Screenshots

## Real, project-generated assets

| File | Origin |
|---|---|
| `ai-engine-triage-output.png` | Rendered from the **actual** `POST /analyze` JSON response captured during the smoke test (source: `../validation-results/example-triage-response.json`). |
| `smoke-test-output.png` | Rendered from the **actual** console output of `scripts/smoke_test.py` (source: `../validation-results/smoke-test-console.txt`). |

These two are regenerated from real captured output, not hand-drawn or fabricated; the underlying raw files live in `../validation-results/`.

## Vendor / example originals (archived, NOT project screenshots)

`vendor-originals/` holds the 10 archived vendor/example images that previously illustrated the README. OCR + metadata forensics showed none of them depicts this project's deployment (see `../audit-report.md` §4).

- `wazuh-*.png` — generic Wazuh module overview pages.
- `thehive-*.png` — TheHive/Cortex **documentation** screenshots.
- `shuffle-workflow.png` — Shuffle example workflow unrelated to this repo's workflows.
- `misp-dashboard.png` / `misp-trendings.png` — MISP demo data; the trendings view is dated **2017**.
- `ollama-openwebui.png` — Open WebUI with `gpt-4.1-nano`, so it is not evidence of a local LLaMA 3 runtime.

### Vendor reference gallery

The images are now displayed with descriptions in [`vendor-originals/README.md`](vendor-originals/README.md). This keeps the folder visually useful while preserving a strict distinction between **vendor UI references** and **project-generated runtime evidence**.

They are intentionally not presented as live project evidence.