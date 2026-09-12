# 🧠 AI SOC Decision Engine

An open-source SOC decision-support engine for **AI-assisted alert triage, enrichment, safety controls, human approval and incident escalation**. The repository is designed as the decision/control-plane layer of a practical blue-team stack.

> **Engineering principle:** AI augments analyst judgement; it does not replace analyst accountability.

## Architecture

<p align="center">
  <img src="docs/diagrams/architecture.svg" alt="AI SOC Decision Engine architecture" width="100%">
</p>

## Component matrix

| Component | Role | Repository status |
|---|---|---|
| **Wazuh** | SIEM / EDR / log aggregation | ✅ Compose deployment |
| **Suricata** | Network IDS/IPS | ✅ Container deployment + EVE JSON logging |
| **Zeek** | Network traffic analysis | ✅ Container deployment + JSON network logs |
| **Shuffle** | SOAR / workflow automation | ✅ Compose deployment + workflow definitions |
| **MISP** | Threat intelligence enrichment | ✅ Compose deployment + enrichment workflow |
| **Cortex** | Observable analysis / enrichment | ✅ Compose deployment + REST enrichment client |
| **Ollama** | Local LLM inference | ✅ Integration code + Compose |
| **TheHive 5** | Case management | ✅ API client implemented |
| **AI SOC Decision Engine** | AI-assisted triage and decision support | ✅ Implemented + tested |

### Deployment truth

The repository contains executable deployment definitions for the complete SOC stack. **Green status means the capability is implemented in the repository and has a deployment path; it does not claim that the services are currently running on the maintainer's host.** Live runtime evidence is recorded separately when a lab execution is performed.

## Decision pipeline

1. Receive a normalized alert from Wazuh, Suricata, Zeek or an automation layer.
2. Optionally enrich the alert IOC with Cortex.
3. Apply deterministic safety checks and prompt-injection controls.
4. Run the local Ollama backend or the deterministic offline backend.
5. Validate the model response against strict Pydantic schemas.
6. Apply confidence thresholds and deterministic overrides.
7. Hold high-impact decisions for analyst approval when configured.
8. Create a TheHive 5 case for approved/high-confidence escalation.
9. Record structured decision and enrichment metrics.

## Operational diagrams

### Alert lifecycle

<p align="center">
  <img src="docs/diagrams/alert-lifecycle.svg" alt="Alert lifecycle from telemetry ingestion through enrichment, AI analysis, decision and case recording." width="100%">
</p>

### AI decision safety gates

<p align="center">
  <img src="docs/diagrams/ai-decision-gates.svg" alt="AI decision safety gates for input validation, model validation, policy checks and controlled action." width="100%">
</p>

### IOC enrichment flow

<p align="center">
  <img src="docs/diagrams/enrichment-flow.svg" alt="IOC enrichment flow using Cortex and MISP before AI decisioning." width="100%">
</p>

### Human approval and escalation

<p align="center">
  <img src="docs/diagrams/human-approval-gate.svg" alt="Human approval and controlled escalation workflow for high-impact SOC decisions." width="100%">
</p>

### Decision observability

<p align="center">
  <img src="docs/diagrams/observability-metrics.svg" alt="Decision observability metrics covering telemetry, AI processing, decision quality and audit evidence." width="100%">
</p>

### ATT&amp;CK-aligned detection layer

<p align="center">
  <img src="docs/diagrams/mitre-detection-layer.svg" alt="ATT&CK-aligned detection engineering layer connecting telemetry, detection, evidence mapping and response." width="100%">
</p>

## Network sensors

<p align="center">
  <img src="docs/diagrams/network-sensor-deployment.svg" alt="Diagram showing Suricata and Zeek network sensor deployment and log flow." width="95%">
</p>

### Suricata

`docker/docker-compose.network-sensors.yml` runs Suricata against the host interface selected by `SOC_SENSOR_INTERFACE`. The container uses `NET_ADMIN`, `NET_RAW` and `SYS_NICE`, writes EVE JSON to `network-sensors/suricata/logs/`, and retains the Suricata rule/runtime volume.

### Zeek

Zeek runs on the same selected host interface and writes JSON-formatted `conn.log`, `dns.log`, `http.log`, `ssl.log`, `files.log` and `weird.log` under `network-sensors/zeek/logs/`.

Set the interface before deployment:

```bash
export SOC_SENSOR_INTERFACE=eth0
./scripts/deploy.sh
```

Use the actual interface carrying the traffic you are authorized to monitor. Passive IDS/NSM monitoring is the default; this repository does not claim inline blocking simply because Suricata is present.

## Cortex enrichment

<p align="center">
  <img src="docs/diagrams/cortex-enrichment.svg" alt="Diagram showing optional Cortex observable enrichment before AI triage and TheHive case escalation." width="95%">
</p>

Cortex is deployed with TheHive and can be enabled for observable enrichment:

```bash
export CORTEX_ENABLED=true
export CORTEX_API_KEY='<cortex-api-key>'
export CORTEX_ANALYZER_ID='<enabled-ip-analyzer-id>'
```

The engine sends the first available `source_ip`/`dest_ip` as an `ip` observable to `/api/analyzer/{ANALYZER_ID}/run`. The Cortex analyzer must already be enabled and permitted for the configured organization.

## Full deployment topology

<p align="center">
  <img src="docs/diagrams/full-stack-deployment.svg" alt="Diagram showing the complete SOC deployment topology from telemetry through AI decision support to case management." width="100%">
</p>

### End-to-end SOC workflow visualization

<p align="center">
  <img src="docs/diagrams/end-to-end-soc-workflow.png" alt="Illustrative end-to-end SOC workflow visualization showing Wazuh, Suricata, Zeek, Cortex, MISP, Shuffle, AI SOC Decision Engine, TheHive and Docker." width="100%">
</p>

> **Illustrative visualization — not live runtime evidence.** This image communicates the intended end-to-end SOC architecture. Project-generated runtime evidence is documented separately.

## Shuffle and MISP

The repository contains the SOAR deployment and versioned workflow definitions under `shuffle-workflows/`. The workflows describe the alert → enrichment → AI decision → case-management path without pretending that a Git-tracked JSON file is proof of a live Shuffle instance.

MISP is deployed through `docker/docker-compose.misp.yml`; its enrichment contract is represented in the workflow layer and can be supplied to the AI engine as `misp_context`.

## Actual tested functionality

- Strict structured AI output validation.
- Deterministic safety controls and prompt-injection detection.
- Prompt versioning with SHA-256 manifest verification.
- Ollama integration with timeout/retry handling.
- Deterministic offline fallback.
- Confidence-threshold enforcement.
- Human-approval gating.
- Duplicate-event deduplication.
- TheHive 5 case creation.
- Structured decision metrics.
- Reproducible smoke test and automated test suite.
- Suricata and Zeek container deployment definitions.
- Cortex REST enrichment integration with fail-soft behaviour.

## Visual evidence

### AI triage output

<p align="center">
  <img src="docs/screenshots/ai-engine-triage-output.png" alt="AI SOC Decision Engine triage output" width="90%">
</p>

### Smoke test

<p align="center">
  <img src="docs/screenshots/smoke-test-output.png" alt="AI SOC Decision Engine smoke test output" width="90%">
</p>

These two images are project-generated evidence backed by captured validation artifacts. They are distinct from the vendor reference screenshots below.

## Vendor UI reference gallery

The following screenshots are archived **vendor/example references** for the technologies represented in the stack. They are included for visual context only and are **not presented as proof of live deployment or project-generated runtime output**.

<details>
<summary>Wazuh — dashboard, endpoint security and threat intelligence</summary>

### Wazuh dashboard

![Screenshot of a Wazuh dashboard interface used as a vendor UI reference.](docs/screenshots/vendor-originals/wazuh-dashboard.png)

### Wazuh endpoint security

![Screenshot of Wazuh endpoint security views used as a vendor UI reference.](docs/screenshots/vendor-originals/wazuh-endpoint-security.png)

### Wazuh threat intelligence

![Screenshot of a Wazuh threat intelligence view used as a vendor UI reference.](docs/screenshots/vendor-originals/wazuh-threat-intel.png)

</details>

<details>
<summary>TheHive / Cortex — alert, case and analyzer response views</summary>

### TheHive alert management

![Screenshot of TheHive alert management used as a vendor UI reference.](docs/screenshots/vendor-originals/thehive-alert-management.png)

### TheHive case management

![Screenshot of TheHive case management used as a vendor UI reference.](docs/screenshots/vendor-originals/thehive-case-management.png)

### TheHive Cortex response

![Screenshot of a TheHive/Cortex response view used as a vendor UI reference.](docs/screenshots/vendor-originals/thehive-cortex-response.png)

</details>

<details>
<summary>Shuffle — workflow automation interface</summary>

![Screenshot of a Shuffle workflow interface used as a vendor/example reference.](docs/screenshots/vendor-originals/shuffle-workflow.png)

</details>

<details>
<summary>MISP — dashboard and threat-intelligence trend views</summary>

### MISP dashboard

![Screenshot of the MISP dashboard used as a vendor UI reference.](docs/screenshots/vendor-originals/misp-dashboard.png)

### MISP trendings

![Screenshot of MISP trendings used as an archived vendor/example reference.](docs/screenshots/vendor-originals/misp-trendings.png)

</details>

<details>
<summary>Ollama / Open WebUI — AI interface reference</summary>

![Screenshot of an Open WebUI interface used as a vendor/example reference for the AI layer.](docs/screenshots/vendor-originals/ollama-openwebui.png)

</details>

For provenance and the full folder-level gallery, see [`docs/screenshots/vendor-originals/README.md`](docs/screenshots/vendor-originals/README.md).

## Quick start

### AI engine only

```bash
cd ai-engine
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
AI_SOC_BACKEND=offline python app.py
```

Then:

```bash
curl -s http://localhost:8888/health
python3 ../scripts/send-test-alert.py ssh-bruteforce
```

### Full lab deployment

```bash
chmod +x scripts/*.sh
export SOC_SENSOR_INTERFACE=eth0
./scripts/deploy.sh
./scripts/setup-ollama.sh
```

The deployment script starts Wazuh, Suricata, Zeek, TheHive, Cortex, Shuffle, MISP, Ollama and the AI engine. Replace all default credentials and configure API keys before exposing any service outside an isolated lab.

## Validation

```bash
python3 -m pytest tests/ -q
python3 scripts/smoke_test.py
```

CI validates Python quality, Docker Compose syntax, configuration files, the test suite and the smoke-test path.

## Documentation

| Document | Purpose |
|---|---|
| [docs/audit-report.md](docs/audit-report.md) | File-by-file implementation audit |
| [docs/validation.md](docs/validation.md) | Validation methodology and results |
| [docs/ai-safety-model.md](docs/ai-safety-model.md) | Safety controls and approval model |
| [docs/testing.md](docs/testing.md) | Test strategy and scenario matrix |
| [docs/observability.md](docs/observability.md) | Metrics and operational visibility |
| [docs/setup-guide.md](docs/setup-guide.md) | Deployment and setup guidance |
| [docs/mitre-mapping.md](docs/mitre-mapping.md) | MITRE ATT&CK mapping |
| [docs/screenshots/README.md](docs/screenshots/README.md) | Screenshot provenance |

## Security model

- Local Ollama inference keeps alert content on controlled infrastructure.
- AI output remains advisory.
- High-impact decisions can require explicit analyst approval.
- Malformed model output is rejected rather than trusted.
- Deterministic fallback prevents total dependence on LLM availability.
- Cortex is optional and fail-soft; unavailable enrichment does not stop alert triage.
- Network sensors are passive by default.
- Default credentials and API keys must never be used outside an isolated lab.

## License

MIT — see [LICENSE](LICENSE).

## 👤 Author

## Sandeep Mothukuri

**Senior SOC Analyst (L3) · Detection Engineering · Threat Hunting · Incident Response · Security Engineering**

Focus areas:

- Security Operations
- Detection Engineering
- Threat Hunting
- Incident Response
- SIEM / XDR
- SOAR
- DFIR
- MITRE ATT&CK
- Security Automation
- AI-Augmented SOC Operations

This repository is maintained as a practical security engineering environment for designing, testing and validating modern SOC capabilities.

- GitHub: [@sandeepmothukuri](https://github.com/sandeepmothukuri)
- Website: [cybertechnology.in](https://cybertechnology.in)
- LinkedIn: [linkedin.com/in/sandeepmothukuri](https://www.linkedin.com/in/sandeepmothukuri)
- Email: [sandeep.mothukuris@gmail.com](mailto:sandeep.mothukuris@gmail.com)

---

# 🗂️ All Repositories

| Repository Description | |
| --- | --- |
| [AI-SOC-Decision-Engine](https://github.com/sandeepmothukuri/AI-SOC-Decision-Engine) | AI-assisted SOC decision/control plane for triage, enrichment, safety controls and analyst approval |
| [AI-Augmented-SOC-Lab](https://github.com/sandeepmothukuri/AI-Augmented-SOC-Lab) | AI-augmented SOC with Wazuh + TheHive + Ollama (LLaMA3) for analyst-assisted triage |
| [Enterprise-Detection-Engineering-SOC-Lab](https://github.com/sandeepmothukuri/Enterprise-Detection-Engineering-SOC-Lab) | 12-tool SOC lab with OpenSearch, Suricata, Zeek, MISP, Caldera, Velociraptor |
| [Autonomous-SOC-Lab](https://github.com/sandeepmothukuri/Autonomous-SOC-Lab) | Autonomous SOC with AI-driven detection and self-healing playbooks |
| [soc-threat-hunting-lab](https://github.com/sandeepmothukuri/soc-threat-hunting-lab) | Threat detection lab — Zeek, RITA, Arkime, Velociraptor, OSQuery, MISP |
| [soc-lab-free](https://github.com/sandeepmothukuri/soc-lab-free) | Free SOC lab — OpenVAS, Wazuh, pfSense, Proxmox Mail, Lynis |
| [SOC-Detection-and-Threat-Hunting-Lab](https://github.com/sandeepmothukuri/SOC-Detection-and-Threat-Hunting-Lab) | SOC analyst home lab — Wazuh, Sysmon, MITRE ATT&CK mapping and incident response |
| [PromptSentinel](https://github.com/sandeepmothukuri/PromptSentinel) | Enterprise-grade prompt injection detection and AI firewall for LLM applications |
| [PromptShield](https://github.com/sandeepmothukuri/PromptShield) | AI Security + SOC Detection Engineering Lab with prompt-security telemetry, detections and response |
| [sentinel-detection-engine](https://github.com/sandeepmothukuri/sentinel-detection-engine) | Detection-as-code for Microsoft Sentinel and Defender XDR with KQL, SOAR and ATT&CK coverage |

---

**Author portfolio:** [github.com/sandeepmothukuri](https://github.com/sandeepmothukuri)
