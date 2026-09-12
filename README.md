# 🧠 AI SOC Decision Engine

An open-source Security Operations Center (SOC) decision-support engine with a **local AI analysis layer** for alert triage. Built for blue-team engineering, AI-assisted SOC research, detection workflows, and reproducible security validation.

> **Status (audited 2026-09-12).** The AI engine is real, hardened, and tested (42 unit/integration tests + a reproducible end-to-end smoke test). The surrounding SOC services (Wazuh, Shuffle, MISP, TheHive, Cortex, Ollama) are provided as Docker Compose files but were **not booted during the audit** and are labelled accordingly. See [docs/audit-report.md](docs/audit-report.md) and [docs/validation.md](docs/validation.md) for exactly what was and wasn't verified.

---

## ⚠️ What this project is (and is not)

- **It is** an *augmentation / decision-support* tool: the AI proposes a structured triage containing summary, severity, confidence, rationale, MITRE mapping, recommended action, and evidence; an analyst remains accountable for the final decision.
- **It is not** a replacement for L1 analysts. No evaluation against a labelled alert corpus has been performed here, so no stronger accuracy claim is made. Human approval gates ESCALATE/CLOSE decisions by default.

---

## 📐 Architecture

The following diagram shows the implemented decision flow and its integration boundaries.

![AI SOC Decision Engine architecture](docs/diagrams/architecture.svg)

### Decision flow

```text
Wazuh / SOC Alert
        ↓
Shuffle workflow
        ↓
MISP enrichment
        ↓
AI SOC Decision Engine
  ├─ deterministic safety
  ├─ optional Ollama LLM
  ├─ strict schema validation
  ├─ confidence thresholds
  ├─ fallback handling
  └─ human-approval gate
        ↓
TheHive 5 case
        ↓
Analyst approve / reject
```

> **Integration boundary:** Suricata and Zeek are not deployed in this repository; Cortex is not yet wired into the active workflow; Shuffle JSON files are reference specifications rather than native-importable workflow exports.

---

## 🛠️ Stack

| Component | Role | Repository status |
|-----------|------|-------------------|
| **Wazuh** | SIEM / EDR / log aggregation | ✅ Compose configuration |
| **Suricata** | Network IDS/IPS | ❌ Not deployed |
| **Zeek** | Network traffic analysis | ❌ Not deployed |
| **Shuffle** | SOAR / workflow automation | ⚠️ Reference workflow configuration |
| **MISP** | Threat intelligence enrichment | ✅ Workflow step defined |
| **Cortex** | Analyzer / enrichment layer | ⚠️ Compose only; not wired |
| **Ollama** | Local LLM inference | ✅ Integration code + Compose |
| **TheHive 5** | Case management | ✅ API client implemented |
| **AI SOC Decision Engine** | AI-assisted triage and decision support | ✅ Implemented + tested |

---

## 🔎 Visual Walkthrough

### 1. End-to-end architecture

The architecture diagram is the primary visual reference for understanding how alerts move through enrichment, AI analysis, safety controls, and analyst approval.

![End-to-end AI SOC architecture](docs/diagrams/architecture.svg)

### 2. AI triage result

This screenshot is generated from a **real `POST /analyze` response** captured during the smoke test. It demonstrates the structured decision returned by the engine.

![Real AI triage output](docs/screenshots/ai-engine-triage-output.png)

### 3. Validation and smoke-test evidence

This screenshot is the captured console output from the repository's reproducible smoke-test harness.

![Smoke test output](docs/screenshots/smoke-test-output.png)

### Visual evidence policy

Only project-generated evidence is shown in this README. Historical vendor/example screenshots are retained separately under `docs/screenshots/vendor-originals/` for provenance and are intentionally not presented as evidence of this project's deployment. See [docs/screenshots/README.md](docs/screenshots/README.md).

---

## ✅ Actual tested functionality

- Strict structured AI output with schema validation.
- Deterministic safety controls, including prompt-injection detection and IOC handling.
- Prompt versioning with SHA-256 manifest verification.
- Ollama integration with timeout/retry handling.
- Deterministic fallback when the LLM is unavailable or returns malformed output.
- Confidence-threshold enforcement.
- Human-approval workflow for high-impact decisions.
- Duplicate-event deduplication.
- TheHive 5 case creation through `/api/v1/case`.
- Structured decision logging and `/stats` metrics.
- Reproducible end-to-end smoke testing plus a 42-test suite.

---

## 🧪 Integration status

| Capability | Status | Evidence |
|---|---|---|
| AI decision engine | ✅ Implemented | Unit/integration tests + smoke test |
| Local LLM path | ✅ Implemented | Ollama backend code |
| Offline deterministic path | ✅ Implemented | Validation harness |
| TheHive 5 integration | ✅ Implemented | `/api/v1/case` client |
| Wazuh deployment | ⚠️ Configuration present | Docker Compose |
| MISP workflow enrichment | ⚠️ Configuration present | Shuffle reference workflow |
| Cortex enrichment | ❌ Not wired | Future integration |
| Suricata ingestion | ❌ Not present | Future integration |
| Zeek ingestion | ❌ Not present | Future integration |
| Native Shuffle export | ❌ Not present | Reference JSON only |

---

## 🚀 Quick Start

### A. Run the tested AI engine path

```bash
cd ai-engine
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# deterministic offline backend
AI_SOC_BACKEND=offline python app.py

# or local Ollama backend
AI_SOC_BACKEND=ollama OLLAMA_HOST=http://localhost:11434 python app.py
```

Then:

```bash
curl -s http://localhost:8888/health
python3 ../scripts/send-test-alert.py ssh-bruteforce
```

### B. Run validation

```bash
python3 -m pytest tests/ -q
python3 scripts/smoke_test.py
```

### C. Deploy the optional SOC stack

```bash
chmod +x scripts/*.sh
./scripts/deploy.sh
./scripts/setup-ollama.sh
```

> The full Docker stack was not booted during the audit environment, so deployment components remain explicitly marked as unverified until exercised in a live environment.

---

## 📁 Project Structure

```text
├── docker/                  # SOC service Compose files
├── ai-engine/               # FastAPI AI decision engine
│   ├── app.py               # API endpoints
│   ├── analyzer.py          # analysis pipeline
│   ├── safety.py            # deterministic safety controls
│   ├── llm_backends.py      # Ollama / offline / scripted backends
│   ├── schemas.py           # strict Pydantic schemas
│   ├── thehive_client.py    # TheHive 5 API client
│   ├── config.py            # resolved configuration
│   ├── prompts/v1/          # versioned prompts
│   ├── safety/              # allow/block lists
│   └── legacy/              # pre-audit implementation preserved for provenance
├── shuffle-workflows/       # reference workflow specifications
├── wazuh-config/            # Wazuh custom rules
├── thehive-config/          # TheHive configuration/templates
├── scripts/                 # deployment and validation utilities
├── tests/                   # unit/integration tests
└── docs/                    # architecture, validation, safety, testing and evidence
```

---

## 📚 Documentation

| Document | Purpose |
|---|---|
| [docs/audit-report.md](docs/audit-report.md) | File-by-file audit and implementation reality |
| [docs/validation.md](docs/validation.md) | Reproducible validation results |
| [docs/ai-safety-model.md](docs/ai-safety-model.md) | Safety controls, thresholds and approval model |
| [docs/testing.md](docs/testing.md) | Test strategy and scenario matrix |
| [docs/observability.md](docs/observability.md) | Metrics, logging and operational visibility |
| [docs/setup-guide.md](docs/setup-guide.md) | Deployment and setup guidance |
| [docs/mitre-mapping.md](docs/mitre-mapping.md) | MITRE ATT&CK mapping |
| [docs/screenshots/README.md](docs/screenshots/README.md) | Screenshot provenance and evidence policy |

---

## 🔐 Security Model

- Local Ollama inference is supported to keep alert data on controlled infrastructure.
- AI output is advisory; analyst approval remains the control point for high-impact decisions.
- Structured validation rejects malformed model output.
- Deterministic fallback prevents dependence on LLM availability.
- Default credentials in Compose files **must** be replaced before any real deployment.

---

## 📊 Validation Highlights

The current validation harness measures decision outcomes, fallback behaviour, prompt-injection handling, duplicate-event handling, and human-approval behaviour. The documented results are generated from the test harness rather than asserted manually.

See [docs/validation.md](docs/validation.md) for the recorded scenario-level results and methodology.

---

## 📜 License

MIT — free to use, modify, and share.

---

## 👤 Author

**Sandeep Mothukuri** — [@sandeepmothukuri](https://github.com/sandeepmothukuri)
 · [cybertechnology.in](https://cybertechnology.in)
