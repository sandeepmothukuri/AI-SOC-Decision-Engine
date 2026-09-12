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

<p align="center">
  <img src="docs/diagrams/architecture.svg" alt="AI SOC Decision Engine architecture" width="100%">
</p>

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

## 🖼️ Visual Evidence

This section provides a complete visual walkthrough of the repository's available architecture, implementation evidence, validation output, and retained vendor-reference screenshots.

### 1. End-to-end architecture

The primary architecture diagram shows how a SOC alert moves through enrichment, deterministic safety controls, local AI analysis, validation, and human approval.

<p align="center">
  <img src="docs/diagrams/architecture.svg" alt="End-to-end AI SOC Decision Engine architecture" width="100%">
</p>

---

### 2. Real project evidence — AI triage

Captured from a real `POST /analyze` response produced by the repository's AI engine.

<p align="center">
  <img src="docs/screenshots/ai-engine-triage-output.png" alt="AI SOC Decision Engine triage output" width="90%">
</p>

---

### 3. Real project evidence — smoke test

Captured console output from the reproducible end-to-end smoke-test harness.

<p align="center">
  <img src="docs/screenshots/smoke-test-output.png" alt="AI SOC Decision Engine smoke test output" width="90%">
</p>

---

## 🧩 SOC Platform Reference Screenshots

The following screenshots are retained under `docs/screenshots/vendor-originals/` as **vendor/reference visuals** for the technologies represented in the architecture. They are intentionally separated from project-generated evidence and must not be interpreted as proof that those vendor services were live during the audit.

### Wazuh

<p align="center">
  <img src="docs/screenshots/vendor-originals/wazuh-dashboard.png" alt="Wazuh dashboard reference" width="90%">
</p>

<p align="center">
  <img src="docs/screenshots/vendor-originals/wazuh-endpoint-security.png" alt="Wazuh endpoint security reference" width="90%">
</p>

<p align="center">
  <img src="docs/screenshots/vendor-originals/wazuh-threat-intel.png" alt="Wazuh threat intelligence reference" width="90%">
</p>

### TheHive + Cortex

<p align="center">
  <img src="docs/screenshots/vendor-originals/thehive-alert-management.png" alt="TheHive alert management reference" width="90%">
</p>

<p align="center">
  <img src="docs/screenshots/vendor-originals/thehive-case-management.png" alt="TheHive case management reference" width="90%">
</p>

<p align="center">
  <img src="docs/screenshots/vendor-originals/thehive-cortex-response.png" alt="TheHive and Cortex response reference" width="90%">
</p>

### Shuffle SOAR

<p align="center">
  <img src="docs/screenshots/vendor-originals/shuffle-workflow.png" alt="Shuffle SOAR workflow reference" width="90%">
</p>

### MISP Threat Intelligence

<p align="center">
  <img src="docs/screenshots/vendor-originals/misp-dashboard.png" alt="MISP dashboard reference" width="90%">
</p>

<p align="center">
  <img src="docs/screenshots/vendor-originals/misp-trendings.png" alt="MISP trending threat intelligence reference" width="90%">
</p>

### Ollama / Open WebUI

<p align="center">
  <img src="docs/screenshots/vendor-originals/ollama-openwebui.png" alt="Ollama Open WebUI reference" width="90%">
</p>

> **Reference-image policy:** these vendor-original screenshots are preserved for documentation and provenance only. Project-generated evidence is presented separately above.

See [docs/screenshots/README.md](docs/screenshots/README.md) for screenshot provenance.

---

## 🧪 Validation Evidence

Validation artifacts are stored in [`docs/validation-results/`](docs/validation-results/), including the latest JSON results, timestamped smoke-test results, Markdown reporting, and captured console output.

| Artifact | Purpose |
|---|---|
| [latest.json](docs/validation-results/latest.json) | Latest machine-readable validation results |
| [example-triage-response.json](docs/validation-results/example-triage-response.json) | Example structured triage response |
| [smoke-test-20260912T174744Z.md](docs/validation-results/smoke-test-20260912T174744Z.md) | Timestamped smoke-test report |
| [smoke-test-console.txt](docs/validation-results/smoke-test-console.txt) | Captured smoke-test console output |

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
