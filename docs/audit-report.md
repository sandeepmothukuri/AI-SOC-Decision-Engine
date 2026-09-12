# AI-Augmented SOC Lab — File-by-File Audit

**Audit date:** 2026-09-12
**Audit scope:** full repository (`main` @ `af9ef4d`)
**Method:** static review of every file, OCR + metadata forensics on all 10
screenshots, cross-checks against vendor documentation (TheHive 5 API, Wazuh
ruleset syntax, Shuffle workflow format), and execution of a reproducible
end-to-end smoke test against the real AI-engine code.

> **Environment constraint.** This audit ran in a sandbox with **no Docker and
> no GPU**. Wazuh, Suricata, Zeek, Shuffle, TheHive, Cortex, MISP and a real
> Ollama model were **not booted**. Wherever the pipeline was exercised, the AI
> engine is the **real code under test** while upstream services are mocked
> HTTP services (see [docs/testing.md](testing.md)). Everything that could not
> be verified live is marked **UNVERIFIED** — not "passing".

---

## 1. Repository state

| Fact | Value |
|---|---|
| Commits on `main` | 1 (squashed) — `af9ef4d "Update README.md"`, 2026-09-12, Sandeep Mothukuri |
| Tests directory | absent (pre-audit) |
| CI | lint only (flake8/black/JSON/XML/YAML syntax) — no tests, no pipeline validation |
| Vendor/generic screenshots | 10 (see §4) |

---

## 2. File-by-file findings

### `docker/`

| File | Verdict | Notes |
|---|---|---|
| `docker-compose.wazuh.yml` | ⚠️ Simplified / UNVERIFIED | Single-node Wazuh 4.7.3 (manager/indexer/dashboard). No Suricata, no Zeek (see §3.1). Indexer bootstrap (certificates/passwords) and Filebeat wiring are implicit; not verified bootable. Mounts `../wazuh-config/custom-rules.xml` → `local_rules.xml`. |
| `docker-compose.thehive.yml` | ⚠️ UNVERIFIED | TheHive 5.2 + Cassandra + ES 7.17 + Cortex 3.1.7. Cortex has **no Elasticsearch/`application.conf` configuration** supplied — Cortex 3.x cannot store jobs as configured here. Mounted `case-templates.json` shape unverified against the TH5 CaseTemplate schema. |
| `docker-compose.shuffle.yml` | ⚠️ UNVERIFIED | Official Shuffle images + `gcloud` datastore emulator. Bootable in principle; **but the workflows in `shuffle-workflows/` are not importable** (§3.3). |
| `docker-compose.misp.yml` | ⚠️ UNVERIFIED | `ghcr.io/misp/misp-docker/misp-core:latest` returned HTTP 401 to unauthenticated registry probes — existence could not be confirmed; the upstream misp-docker project is normally built locally, not pulled from a prebuilt image. |
| `docker-compose.ollama.yml` | ✅ OK (structure) | Ollama + AI engine build context. `THEHIVE_API_KEY` is a placeholder. |

Default credentials are hard-coded in all compose files (documented in
`deploy.sh` and `SECURITY.md`); they **must** be changed before any real
deployment.

### `ai-engine/` (original, pre-audit — preserved in `ai-engine/legacy/`)

| File | Findings |
|---|---|
| `app.py` | No LLM timeout, no fallback, no approval, no structured decision log. Logs verdict/severity/ms but **not confidence** (README claims "every AI decision is logged with confidence"). Auto-creates TheHive cases for ESCALATE/ENRICH with no analyst gate. |
| `analyzer.py` | ① Output schema ≠ required schema. ② Malformed LLM JSON is **silently accepted** (fallback `{"verdict":"ENRICH","confidence":0.5}`). ③ No dedupe. ④ Deprecated MITRE ID T1068 in the keyword map. ⑤ `langchain` chain with no `asyncio` timeout. |
| `thehive_client.py` | Posts to **`/api/case`** — the TheHive **4** path. TheHive 5 (deployed image `strangebee/thehive:5.2`) serves the API under **`/api/v1`**, so `POST /api/case` returns 404 against the deployed stack. |
| `requirements.txt` | Pinned, valid. |
| `Dockerfile` | Valid. |
| `prompts/*.txt` | No versioning; triage prompt requests a different JSON shape than the engine validates. |

### `shuffle-workflows/`

| File | Findings |
|---|---|
| `ssh-bruteforce.json`, `malware-detection.json` | **Not valid Shuffle workflow JSON** — hand-written `{triggers:[{type:WEBHOOK}], actions:[{app,action,requires}]}` shape, not Shuffle's native schema (`app_name`, `app_version`, `position`, `parameters`, `branches`…). The inline Python uses a **top-level `return`**, which is not executable. "Import into Shuffle" (README step 5) cannot work as written. Also: the AI-engine call originally did **not** forward `rule_id`/`dest_ip` (caused dedupe-key collisions — fixed). |

### `wazuh-config/custom-rules.xml`

| Finding | Evidence |
|---|---|
| **`<occurrence>` is not a Wazuh rule option** | The [Wazuh ruleset syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html) documents **`<frequency>`** (54 mentions); `occurrence` appears **0 times**. Rules 100001/100004/100006 use `<occurrence>` and will not fire as intended. |
| `<time>22:00 - 06:00</time>` format | Wazuh documents `time` as `hh:mm-hh:mm` (also `hh-hh`), not `HH:MM - HH:MM` with spaces; an overnight range is not shown as supported. Rule 100005 is doubtful. |
| `<same_field>file.path</same_field>` | `same_field` exists (since 3.9) but must be paired with `frequency`/`timeframe` and a matched child rule; rule 100006 uses it with `<occurrence>` (invalid, above). |
| MITRE IDs | T1068 is **deprecated** in ATT&CK; T1041 fine. |

XML is well-formed, but several rules are semantically invalid for Wazuh 4.7.

### `thehive-config/case-templates.json`

Valid JSON. TheHive 5 CaseTemplate schema requires `displayName`, task `order`,
and page structure; the file supplies `name/titlePrefix/tasks[{title,
description, group}]`, which is closer to TheHive 4. **UNVERIFIED** against a
live TheHive 5 (import step in the setup guide is unlikely to succeed as-is).

### `scripts/`

| File | Findings (pre-audit) |
|---|---|
| `deploy.sh` | Used `docker-compose` (v1) only — breaks on Docker Compose v2-only installs. Fixed. |
| `test-pipeline.sh` | `check_http` accepted any 200/302 as pass regardless of expected code (e.g. Wazuh API expecting 401). Fixed. Only did reachability + a grep on `send-test-alert.py` output. |
| `setup-ollama.sh` | Valid. |
| `send-test-alert.py` | Printed old field names (`severity_normalized`, `mitre_tactic`, `response_recommendation`) that the engine no longer returns. Rewritten for the hardened schema. |

### `docs/`

| File | Findings |
|---|---|
| `setup-guide.md` | TheHive login `admin@thehive.local`/`secret` unverified against TH5; "import case templates" endpoint `/api/case/template` is the **TheHive 4** path. |
| `ai-prompts.md` | Describes the old unversioned prompts. |
| `mitre-mapping.md` | Lists T1068 (deprecated) and detection sources (Suricata, Zeek) that are **not deployed** in this repo. |
| `screenshots/` (10 PNGs) | See §4. |

### `.github/workflows/`

- `ci.yml` — real, runs flake8/black + JSON/XML/YAML syntax checks. No tests.
- `stargazer-tracker.yml` — auto-opens an issue for each new star; `STARGAZERS.md` is **not present** in the repo.

### Other

| File | Notes |
|---|---|
| `SECURITY.md` | References "`.env` files" that do not exist in the repo; defaults are in compose files. |
| `pyproject.toml` | black/flake8 config only — no test runner config. |
| `.gitignore`, `.gitattributes` | Fine. |

---

## 3. Documented pipeline vs. reality

README/architecture claim:

```
Wazuh/Suricata/Zeek → alert → Shuffle → enrichment (MISP/Cortex)
  → local Ollama → structured triage → TheHive → analyst decision/response
```

| # | Claimed stage | Reality (audited) | Status |
|---|---|---|---|
| 1 | Wazuh, Suricata, Zeek as sources | Wazuh compose exists. **No Suricata or Zeek service/config anywhere** — only a `decoded_as zeek` rule and synthetic test fixtures. | ❌ Suricata/Zeek not deployed |
| 2 | alert → Shuffle | Shuffle compose exists; **workflow JSONs are not importable** (wrong format, non-executable inline Python). | ⚠️ Not functional as written |
| 3 | MISP enrichment | Only a workflow step (`search_ioc`); the AI engine never calls MISP. OK as a design, but the workflow itself is not importable. | ⚠️ Design-only |
| 4 | Cortex enrichment | **No Cortex step in either workflow; no Cortex call in the engine.** Cortex only appears in compose + screenshots. | ❌ Not wired |
| 5 | local Ollama | Real in principle (langchain → Ollama HTTP). No timeout/fallback pre-audit. A real model was **not run in this audit** (no GPU/Docker). | ⚠️ Code path only |
| 6 | structured triage | Yes, but schema ≠ required schema, and malformed output was silently accepted. | ❌ pre-audit / ✅ hardened |
| 7 | TheHive case creation | `POST /api/case` = TheHive 4 path; **404s against the deployed TheHive 5.2** (which uses `/api/v1/case`). | ❌ Broken pre-audit / ✅ fixed |
| 8 | analyst decision/response | Case created with status `New`; no approval gate; malware workflow's "isolate host" PUT targets a Wazuh API without auth bootstrap. | ⚠️ Aspirational |

**Conclusion:** as of the audit, the repo's own code could not deliver the
documented end-to-end pipeline: the TheHive hop would 404, the Shuffle
workflows would not import, Suricata/Zeek/Cortex are absent, and the AI output
schema did not match the stated structure. The pipeline is now implemented and
tested in the hardened engine (see §5 and [validation.md](validation.md)).

---

## 4. Screenshot verification (OCR + metadata)

Every README screenshot was inspected with tesseract OCR and PNG
chunk/EXIF analysis. **None of the 10 images evidences this project's pipeline.**

| File | What it actually shows (OCR evidence) | Classification |
|---|---|---|
| `wazuh-dashboard.png` | Wazuh 4.x "Security Operations" module cards (IT Hygiene, GDPR, NIST 800-53, PCI DSS, HIPAA, TSC). No project data. | Vendor/generic UI |
| `wazuh-endpoint-security.png` | Wazuh "Endpoint Security" module cards (Config Assessment, Malware Detection, FIM). | Vendor/generic UI |
| `wazuh-threat-intel.png` | Wazuh "Threat Intelligence" module cards (Threat Hunting, Vuln Detection, MITRE). | Vendor/generic UI |
| `thehive-alert-management.png` | TheHive docs "email-intake" alerts — 509 alerts, `<VI1P189MB…>` mail IDs, "malspam". Not Wazuh/Suricata alerts. | Vendor docs image |
| `thehive-case-management.png` | Crop of TheHive case tabs (Tasks/Observables/TTPs/…). All three TheHive PNGs share identical 1456×1088 palette encoding → batch docs images. | Vendor docs image |
| `thehive-cortex-response.png` | Cortex **analyzer catalog** (DShield, GoogleDNS_resolve, MISP_2_1, Maltiverse…) — not an alert response. | Vendor docs image |
| `shuffle-workflow.png` | Shuffle **"[EMAIL] Phishing email handler"** example (Gmail, VirusTotal, OWA, ServiceNow, RTIR, PassiveTotal). **Not this project's workflows.** | Unrelated example |
| `misp-dashboard.png` | MISP dashboard w/ mimikatz hashes "checked via VT" (classic MISP demo data), `gnome-screenshot` EXIF. | MISP demo, not this instance |
| `misp-trendings.png` | MISP "trendings" UI dated **11/14/2017** (`localhost:8001/trendings`). Stale 2017 image; not the deployed `misp-core:latest`. | Stale/foreign |
| `ollama-openwebui.png` | Open WebUI with **`gpt-4.1-nano`** selected and personal chats ("Roman Concrete Durability", "Finance", "Study"). **Contradicts the caption** "local LLaMA 3 / Mistral — no data leaves your network". | Misleading/generic |

**Action taken:** these images were moved to
`docs/screenshots/vendor-originals/` and the README now shows only assets that
are real outputs of this project (architecture diagram + captured test output),
clearly labelled.

---

## 5. Measured results (smoke test, 2026-09-12)

Reproducible via `python3 scripts/smoke_test.py`. Raw results:
`docs/validation-results/latest.json` (+ timestamped copies). These numbers are
**generated by the tests**, not asserted.

| Variant | Runs | Valid responses | Verdicts (E/N/C) | Fallbacks | Inj. detected | Automation rate | Auto-case rate | Latency avg/min/max |
|---|---|---|---|---|---|---|---|---|
| offline-engine | 5 | 5/5 | 1/3/1 | 0 | 1 | 1.00 | 0.20 | 30.7 / 17.8 / 68.0 ms |
| misp-down | 1 | 1/1 | 1/0/0 | 0 | 0 | 1.00 | 1.00 | 36.3 ms |
| cortex-down | 1 | 1/1 | 1/0/0 | 0 | 0 | 1.00 | 1.00 | 34.2 ms |
| ollama-unavailable | 1 | 1/1 | 1/0/0 | 1 | 0 | 1.00 | 1.00 | 55.3 ms |
| ollama-malformed-output | 1 | 1/1 | 1/0/0 | 1 | 0 | 1.00 | 1.00 | 47.1 ms |
| ollama-valid-output | 1 | 1/1 | 1/0/0 | 0 | 0 | 1.00 | 1.00 | 40.4 ms |
| duplicate-event | 2 | 2/2 | 1/1/0 | 0 | 0 | 1.00 | 1.00 | 29.5 ms |
| human-approval-mode | 1 | 1/1 | 1/0/0 | 0 | 0 | **0.00** | 0.00 | 17.6 ms |

Scenario outcomes (offline-engine): true positive → ESCALATE; false positive →
CLOSE; ambiguous → ENRICH; missing IOC → ENRICH (confidence ≤ 0.5); prompt
injection → ENRICH with `injection_detected=true`.

> Latency figures are **harness-internal** (in-process engine + mocked
> upstreams on one host). They are not production end-to-end latency and are
> not presented as such.

---

## 6. Hardening applied (this audit)

- Structured AI output enforced: `{summary, severity, confidence, rationale,
  mitre_techniques, recommended_action, evidence}`; **malformed responses are
  rejected**, not silently accepted.
- Prompt versioning + SHA-256 manifest (`prompts/v1/`, `prompt_manifest.json`).
- Model configuration (`config.yaml` + env overrides + `.env.example`).
- Per-call LLM timeout + retries + **deterministic fallback**.
- Confidence thresholds (escalate ≥ 0.75, auto-close ≥ 0.85, missing-IOC cap 0.5).
- Human-approval mode (`/approve`, `/reject`) gating ESCALATE/CLOSE.
- Deterministic safety layer: block/allow lists, injection detection, IOC
  extraction, non-deprecated MITRE mapping.
- Duplicate-event dedupe (engine + TheHive client).
- TheHive client fixed to `/api/v1/case` (TH5) with typed custom fields.
- Structured JSONL decision logging + `/stats` metrics (latency p50/p95,
  enrichment hit/miss, malformed/injection/fallback counters).
- Workflow JSONs: `rule_id`/`dest_ip` now forwarded (fixes dedupe-key
  collisions); severity field names aligned to the new schema.
- Wazuh custom rules: `<occurrence>` → `<frequency>`; `<time>` normalised.
- Scripts fixed (`deploy.sh` v2 compose, `test-pipeline.sh` logic,
  `send-test-alert.py` schema).
- Original sources preserved in `ai-engine/legacy/` for provenance.

---

## 7. What could NOT be verified here

- Booting Wazuh / Shuffle / TheHive / Cortex / MISP (no Docker in sandbox).
- Importing the workflow JSONs into a live Shuffle (no Shuffle; files remain
  in the repo's simplified format, documented as illustrative).
- Running a real Ollama model (no GPU; multi-GB models not feasible).
- TheHive 5 case-template import and custom-field schema against a live TH5.
- Suricata/Zeek integration (not present in the repo at all).

These are marked **UNVERIFIED** in the README's capability matrix.
