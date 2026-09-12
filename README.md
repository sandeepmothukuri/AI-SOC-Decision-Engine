# 🧠 AI-Augmented SOC Lab

An open-source Security Operations Center (SOC) lab with a **local AI
decision-support layer** for alert triage. Built for learning, research, and
blue-team skill development.

> **Status (audited 2026-09-12).** The AI engine is real, hardened, and tested
> (42 unit/integration tests + a reproducible end-to-end smoke test). The
> surrounding SOC services (Wazuh, Shuffle, MISP, TheHive, Cortex, Ollama) are
> provided as Docker Compose files but were **not booted during the audit** and
> are labelled accordingly. See [docs/audit-report.md](docs/audit-report.md) and
> [docs/validation.md](docs/validation.md) for exactly what was and wasn't
> verified.

---

## ⚠️ What this project is (and is not)

- **It is** an *augmentation / decision-support* tool: the AI proposes a
  structured triage (summary, severity, confidence, rationale, MITRE mapping,
  recommended action, evidence) and an analyst decides.
- **It is not** a replacement for L1 analysts. No evaluation against a labelled
  alert corpus has been performed here, so no stronger claim is made. Human
  approval gates ESCALATE/CLOSE decisions by default.

---

## 📐 Architecture (as implemented)

![Pipeline architecture](docs/diagrams/architecture.svg)

```
Wazuh (compose ✓)
        ↓  (Suricata / Zeek — NOT in this repo)
Shuffle workflow (reference JSON — not native-importable, see below)
        ↓
Enrichment: MISP (workflow step ✓) · Cortex (NOT wired)
        ↓
AI SOC Engine (real code, tested)
   deterministic safety → optional Ollama LLM → schema validation
   → thresholds → fallback → human-approval gate
        ↓
TheHive 5 — POST /api/v1/case
        ↓
Analyst decision / approve / reject
```

---

## 🛠️ Stack

| Component | Role | In this repo |
|-----------|------|--------------|
| **Wazuh** | SIEM + EDR + log aggregation | ✅ compose file |
| **Suricata** | Network IDS/IPS | ❌ not deployed (no service/config) |
| **Zeek** | Network traffic analysis | ❌ not deployed (no service/config) |
| **TheHive** | Case management | ✅ compose file |
| **Cortex** | Alert enrichment / analysers | ⚠️ compose only — not wired into the pipeline |
| **Shuffle** | SOAR / workflow automation | ⚠️ compose + reference workflow JSON |
| **MISP** | Threat intelligence platform | ✅ compose + workflow step |
| **Ollama** | Local LLM inference | ✅ compose; model not run in audit |
| **AI SOC Engine** | Triage decision-support | ✅ real code, tested |

---

## ✅ Actual tested functionality vs. 🧪 optional vs. 🔮 future

### ✅ Actual (implemented and tested)

- Structured AI output with **strict schema validation** —
  `{summary, severity, confidence, rationale, mitre_techniques,
  recommended_action, evidence}`; malformed responses are **rejected**.
- Deterministic safety layer: block/allow lists, **prompt-injection
  detection**, IOC extraction, non-deprecated MITRE mapping.
- **Prompt versioning** (SHA-256 manifest), **model configuration**
  (`config.yaml` + env), **timeouts + retries**, **deterministic fallback**
  when the LLM is down or malformed.
- **Confidence thresholds** (escalate ≥ 0.75, auto-close ≥ 0.85, missing-IOC
  cap 0.5).
- **Human-approval mode** — ESCALATE/CLOSE are held for `/approve` or
  `/reject`; no automated action without approval.
- **Duplicate-event** deduplication.
- TheHive 5 case creation via `/api/v1/case`.
- Structured decision logging + `/stats` metrics (latency, enrichment
  hit/miss, malformed/injection/fallback counters).
- End-to-end smoke test + 42-test suite (see [docs/validation.md](docs/validation.md)).

### 🧪 Optional integrations (configs exist, not verified in the audit)

- Full Docker deployment of Wazuh / TheHive / Cortex / Shuffle / MISP /
  Ollama (`docker/`). **Not booted in the audit sandbox (no Docker/GPU).**
- Running the engine against a real Ollama model
  (`--backend ollama --ollama-url http://localhost:11434`).

### 🔮 Future improvements (explicitly NOT implemented)

- Live Suricata & Zeek ingestion (not present in the repo).
- Wiring Cortex analysers into the Shuffle workflow.
- Shuffle-native workflow exports (current JSON files are reference specs).
- Accuracy evaluation against a labelled alert corpus.
- Prometheus export of `/stats`; OpenSearch shipping of decision logs.
- TheHive 5 case-template import verification.

---

## 📸 Real project output

| | |
|---|---|
| ![AI triage output](docs/screenshots/ai-engine-triage-output.png) | Rendered from a **real** `POST /analyze` response captured during the smoke test (raw: `docs/validation-results/example-triage-response.json`). |
| ![Smoke test](docs/screenshots/smoke-test-output.png) | Rendered from the **real** console output of `scripts/smoke_test.py` (raw: `docs/validation-results/smoke-test-console.txt`). |

The vendor/example images that previously illustrated this README (and did not
show this project's deployment) are archived in
`docs/screenshots/vendor-originals/` — see
[docs/audit-report.md §4](docs/audit-report.md).

---

## 🚀 Quick start

### A. Run the AI engine standalone (tested path)

```bash
cd ai-engine
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# deterministic offline backend (no GPU/model needed)
AI_SOC_BACKEND=offline python app.py
# ...or with a local Ollama model
AI_SOC_BACKEND=ollama OLLAMA_HOST=http://localhost:11434 python app.py
```

Then:

```bash
curl -s http://localhost:8888/health
python3 ../scripts/send-test-alert.py ssh-bruteforce
```

### B. Run the validation suite (what the audit ran)

```bash
python3 -m pytest tests/ -q
python3 scripts/smoke_test.py
```

### C. Deploy the full stack (not verified in the audit)

```bash
chmod +x scripts/*.sh
./scripts/deploy.sh            # requires Docker + Docker Compose v2, 16+ GB RAM
./scripts/setup-ollama.sh      # pulls a model into Ollama
```

> The Shuffle workflow JSON files are **reference specifications** and are not
> importable into Shuffle as-is — see
> [shuffle-workflows/README.md](shuffle-workflows/README.md).

---

## 📁 Project structure

```text
├── docker/                  # Docker Compose per service (UNVERIFIED boot)
├── ai-engine/               # FastAPI triage engine (real code, tested)
│   ├── app.py               #   API: /analyze /approve /reject /stats ...
│   ├── analyzer.py          #   analysis pipeline (schema, thresholds, fallback)
│   ├── safety.py            #   deterministic safety rules
│   ├── llm_backends.py      #   Ollama / offline / scripted backends
│   ├── schemas.py           #   strict Pydantic schemas
│   ├── thehive_client.py    #   TheHive 5 client (/api/v1/case)
│   ├── config.py + config.yaml  # model config, thresholds, approval
│   ├── prompts/v1/          #   versioned prompts + SHA-256 manifest
│   ├── safety/              #   blocklist / allowlist
│   └── legacy/              #   original pre-audit sources (provenance)
├── shuffle-workflows/       # reference workflow JSONs (+ README on format)
├── wazuh-config/            # custom rules (frequency/time fixed)
├── thehive-config/          # case templates (TH5 schema UNVERIFIED)
├── scripts/                 # deploy, smoke_test, send-test-alert, harness
├── tests/                   # 42 unit/integration tests
└── docs/                    # audit, validation, safety model, testing, observability
```

---

## 📚 Documentation

| Doc | Contents |
|---|---|
| [docs/audit-report.md](docs/audit-report.md) | File-by-file audit, pipeline vs. reality, screenshot verification |
| [docs/validation.md](docs/validation.md) | What was validated, measured results (real numbers) |
| [docs/ai-safety-model.md](docs/ai-safety-model.md) | Safety rules, thresholds, approval, fallback, limitations |
| [docs/testing.md](docs/testing.md) | How to run tests; scenario matrix |
| [docs/observability.md](docs/observability.md) | Logging, metrics, latency/enrichment/validity measurement |
| [docs/setup-guide.md](docs/setup-guide.md) | Full-stack deployment guide (see audit for caveats) |
| [docs/mitre-mapping.md](docs/mitre-mapping.md) | MITRE coverage reference |

---

## 🔐 Security

- All LLM inference is designed to run locally (Ollama); the engine defaults to
  deterministic rules when no model is available.
- AI output is **advisory** — analysts retain final decision authority
  (enforced via the human-approval gate).
- Default credentials in the Compose files **must** be changed before any real
  deployment (see [SECURITY.md](SECURITY.md)).

---

## 📜 License

MIT — free to use, modify, and share.

---

## 👤 Author

**Sandeep Mothukuri** — [@sandeepmothukuri](https://github.com/sandeepmothukuri)
· [cybertechnology.in](https://cybertechnology.in)
