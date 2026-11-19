# OpenKai — Enterprise AI-Powered Threat Intelligence & SOC Investigation Platform

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.14-blue)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com/)
[![Tests](https://img.shields.io/badge/Tests-Passing-brightgreen.svg)]()

**OpenKai** is an enterprise-grade, self-hosted, AI-powered Threat Intelligence and SOC Investigation Platform. It correlates multi-source external threat intelligence against an organization's actual internal attack surface, endpoint telemetry (**CrowdStrike Falcon**), historical SIEM events (**Elasticsearch / Elastic SIEM**), and central enterprise asset inventory.

Whenever a new threat, IOC, CVE, malicious IP, domain, file hash, or security advisory is identified, OpenKai automatically evaluates:
> **"DOES THIS THREAT AFFECT OUR ENTERPRISE ENVIRONMENT?"**

The system delivers deterministic, evidence-backed verdicts rather than speculative AI assumptions.

---

## 🌟 Core Architecture & Capabilities

```
┌────────────────────────────────────────────────────────────────────────┐
│                        OpenKai SOC Web Dashboard                       │
│  Executive KPI · Threat Feeds · Investigation Console · Asset Inventory│
└────────────────────────────────────┬───────────────────────────────────┘
                                     │ REST API
┌────────────────────────────────────▼───────────────────────────────────┐
│                 OpenKai Core Python Platform Engine                    │
│                                                                        │
│  ┌──────────────────────┐  ┌──────────────────┐  ┌──────────────────┐ │
│  │ AI Multi-Agent Layer │  │  Cross-Platform  │  │ Automated Alert  │ │
│  │                      │  │Correlation Engine│  │ & Notification   │ │
│  │ · TI Analyst         │  │                  │  │                  │ │
│  │ · Asset Impact Agent │  │ Deterministic    │  │ · Slack Webhook  │ │
│  │ · MITRE ATT&CK Agent │  │ Evidence Match   │  │ · MS Teams Card  │ │
│  │ · Reporting Agent    │  │ Risk Score 0-100 │  │ · Discord Embed  │ │
│  └──────────────────────┘  └──────────────────┘  └──────────────────┘ │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                Multi-Source Ingestion & EDR/SIEM                 │  │
│  │                                                                  │  │
│  │ 14 Threat Feeds        CrowdStrike Falcon       Elastic SIEM     │  │
│  │ CISA KEV · NVD · OTX   Hosts · Detections       ECS Search       │  │
│  │ AbuseIPDB · VT · ATT&CK Telemetry · Hashes      Alerts · Network │  │
│  │ CERT-In · ENISA · NCSC Token Auth & Rate-Limit  Query DSL Guard  │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │ Async SQLAlchemy
┌────────────────────────────────────▼───────────────────────────────────┐
│                Persistent Enterprise Database Storage                  │
│  Threat Indicators · CVEs · Devices · Software Inventory · Evidence    │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Key Modules & Highlights

### 1. 14 Threat Intelligence Connectors
- **CISA Known Exploited Vulnerabilities (KEV)**: Automated catalog sync & active exploitation flags.
- **NIST National Vulnerability Database (NVD)**: 2.0 API ingestion with CVSS v3.1/v3.0 metrics and CWE IDs.
- **MITRE ATT&CK Enterprise Matrix**: STIX 2.1 techniques, tactics, mitigations, and data sources.
- **AlienVault OTX**: Subscribed pulse ingestion, malicious indicator normalization.
- **AbuseIPDB**: High-confidence IP blacklist ingestion and reputation verification.
- **VirusTotal v3**: File hash (SHA256, MD5), IP, and domain reputation analysis.
- **abuse.ch ThreatFox**: Live community IOC feeds with confidence levels and malware tags.
- **abuse.ch URLhaus**: Malicious payload download URL feed.
- **abuse.ch MalwareBazaar**: Malware sample hashes and signature mapping.
- **CERT-In Advisories**: High-priority advisories from India's Computer Emergency Response Team.
- **ENISA Publications**: European Union Cybersecurity agency bulletins and threat landscapes.
- **UK NCSC Alerts**: UK National Cyber Security Centre alerts.
- **JPCERT/CC Advisories**: Japan CERT vulnerability and threat advisories.
- **CISA Security Advisories**: US CISA cybersecurity alerts and threat actor profiles.

### 2. CrowdStrike Falcon Integration
- Official OAuth2 client authentication with automatic token caching and expiration renewal.
- Endpoint device inventory retrieval with OS, sensor version, IP address, and health.
- Detection retrieval and behavioral summary inspection.
- Real-time IOC hunting across file hashes (SHA256, MD5), process command lines, and network destinations.

### 3. Elastic SIEM Integration
- Elastic Common Schema (ECS) multi-field query generator for IPs, domains, processes, and hashes.
- Resource-bounded, time-bounded query safety preventing query injection and memory over-consumption.
- Historical log correlation across authentication, network connections, and security alerts.

### 4. Cross-Platform Correlation Engine
Deterministically correlates external indicators with enterprise telemetry:
- **`confirmed_match`**: Malicious indicator active in CrowdStrike detections or SIEM network/process telemetry on internal assets.
- **`potential_match`**: Vulnerable software installed on enterprise endpoints or matching advisory context.
- **`no_match_found`**: Indicator evaluated across EDR, SIEM, and Assets with zero hits.
- **`unable_to_verify`**: Integrations unconfigured or unreachable.
- Calculates an objective Risk Score (0-100) factoring CVSS, KEV, EDR detections, asset criticality, and internet exposure.

### 5. Multi-Agent AI Orchestrator
- **Local Ollama Priority**: Zero-cost, 100% private inference with models like `llama3:8b`.
- **Cloud Fallbacks**: Configurable support for OpenAI and Anthropic.
- **Specialized Roles**: Threat Intelligence Analyst, Asset Impact Agent, MITRE ATT&CK Specialist, and SOC Incident Commander.
- **Prompt Injection Defense**: Sanitizes external untrusted data before prompt construction.
- **Deterministic Code Guard**: Code computes IOC matches and risk scores; LLM provides interpretation and technical synthesis without hallucinating evidence.

### 6. SOC Investigation Dashboard & Reporting
- Dark-mode, high-density SOC web interface available at `http://localhost:8000`.
- Real-time metric cards queried directly from database records.
- Instant threat investigation console for IP, domain, hash, or CVE queries.
- Multi-format report export: **PDF**, **Excel (XLSX)**, **CSV**, and **JSON**.

---

## 📦 Quick Start & Setup

### Prerequisites
- Python 3.10+ (or Docker Compose)
- Git

### Local Development Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/openafw/openkai.git
   cd openkai
   ```

2. **Create Python virtual environment**:
   ```bash
   python -m venv .venv
   # Windows:
   .venv\Scripts\activate
   # Linux/macOS:
   source .venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment**:
   ```bash
   cp .env.example .env
   # Edit .env with your CrowdStrike, Elastic, or Webhook credentials
   ```

5. **Start the platform engine**:
   ```bash
   uvicorn openkai_engine.main:app --host 0.0.0.0 --port 8000 --reload
   ```

6. **Access the SOC Dashboard**:
   Open [http://localhost:8000](http://localhost:8000) in your browser.
   API Documentation is available at [http://localhost:8000/docs](http://localhost:8000/docs).

---

## 🐳 Docker Deployment

Run the complete platform with a single command:

```bash
docker-compose up -d
```

Services started:
- `openkai-engine`: FastAPI backend + SOC web UI on port `8000`
- `ollama`: Local AI model server on port `11434`

---

## 🧪 Automated Testing

Run the full pytest test suite:

```bash
pytest tests/ -v
```

Automated tests validate:
- Ingestion and normalization of CISA KEV, ThreatFox, and MalwareBazaar feeds.
- PBKDF2 password hashing and JWT token verification.
- CrowdStrike Falcon and Elastic SIEM connector error and telemetry handling.
- End-to-end investigation scenario with multi-agent analysis and report exports.

---

## 📄 License

OpenKai is open-source software licensed under the [Apache License 2.0](LICENSE).
