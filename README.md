# 🛡️ Secure SMTP

**Passive Cryptographic Posture Intelligence & Explainable AI Risk Attribution for Enterprise Mail Infrastructure**

---

## 📌 What is Secure SMTP?

**Secure SMTP** is an enterprise-grade cybersecurity forensic and cryptographic posture intelligence platform purpose-built for critical mail transport protocols (**SMTP, IMAP, and POP3**). 

Operating entirely **out-of-band and passively**, Secure SMTP ingests raw network packet captures (PCAP) or live mirror streams to evaluate the security health of mail infrastructure. It reconstructs bi-directional TCP sessions, extracts granular cryptographic negotiations (TLS versions, cipher suites, elliptic curves, extensions, and X.509 certificate chains), and computes client/server fingerprints (**JA3/JA3S** and **JA4/JA4S**)—**all without ever decrypting message payloads or violating privacy regulations.**

By coupling an AST-safe declarative compliance engine with **Explainable AI (SHAP feature attribution)** and **unsupervised anomaly detection (Isolation Forests)**, Secure SMTP bridges the gap between raw network telemetry and actionable, boardroom-ready security risk attribution.

---

## 🚨 The Problem: The Hidden Crisis in Email Cryptography

Email infrastructure remains the single largest attack surface for enterprise communications, yet it suffers from pervasive, silent cryptographic degradation:

### 1. The Fallacy of Opportunistic Encryption & STARTTLS Stripping
Unlike HTTPS (which defaults to strict encryption), SMTP was engineered to default to unencrypted transmission, upgrading to TLS only if advertised via the `STARTTLS` keyword in `EHLO` responses. On-path adversaries or compromised intermediate hops can effortlessly perform **STARTTLS Stripping downgrade attacks**, erasing the capability from the advertisement. Mail servers silently fall back to cleartext, exposing sensitive credentials and confidential business communication to passive wiretapping without triggering any user-facing error.

### 2. Cryptographic Drift & Legacy Cipher Inertia
Decades of backward-compatibility requirements leave corporate mail transfer agents (MTAs) accepting deprecated protocols and vulnerable ciphers:
- Outlawed protocols still active in production (**TLS 1.0 / 1.1**).
- Legacy ciphers vulnerable to cryptographic breaks (**RC4, 3DES, CBC-mode ciphers susceptible to Lucky13/POODLE**).
- Static RSA key exchanges lacking **Forward Secrecy (FS)**, allowing adversaries to record traffic today and decrypt it in the future if private keys are compromised.

### 3. Certificate Hygiene & PKI Blind Spots
Expired certificates, weak signature algorithms (e.g., **SHA-1 / MD5**), insufficient RSA key lengths (<2048-bit), and self-signed certificates routinely go unnoticed on internal relays and secondary MX servers until an audit failure or active breach occurs.

### 4. The "Black Box" Compliance & Scoring Dilemma
Traditional security scanners produce arbitrary risk numbers with zero contextual explanation. Security operations teams and compliance auditors cannot see *why* an endpoint was assigned a particular severity score, making root-cause remediation slow and difficult.

---

## 💡 Why Secure SMTP is Critical

Secure SMTP directly eliminates these blind spots:

- **Zero-Knowledge & Absolute Privacy Preservation**: Evaluates cryptographic integrity solely from handshake metadata and protocol commands. The actual email subject, headers, and body remain completely untouched and unread.
- **Continuous Compliance Posture Auditing**: Instantly maps every observed session against rigorous federal and industry cryptographic standards (**NIST SP 800-52r2, PCI-DSS v4.0, RFC 8996, RFC 8314**).
- **Explainable AI (XAI)**: Eliminates black-box ambiguity by calculating exact mathematical percentage attributions for every risk finding using **SHAP (SHapley Additive exPlanations)**.
- **Unsupervised Anomaly Hunting**: Identifies novel, zero-day cryptographic drift and abnormal client/server pairings with **Isolation Forests**, catching misconfigurations that static rules miss.
- **Automated Incident Remediation**: Features an integrated Generative AI Security Copilot that ingests forensic findings and synthesizes production-hardened configuration files for Postfix, Exim, Sendmail, Dovecot, and Nginx.

---

## 🔬 Architectural Pipeline & How It Works

Secure SMTP operates a multi-stage forensic analysis pipeline that transforms raw network packets into prioritized intelligence:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        1. PASSIVE REASSEMBLY                           │
│   PCAP Ingestion ──> Bi-directional TCP Stream Tracking & Reassembly  │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   2. PROTOCOL & STARTTLS AUDITING                      │
│   EHLO/HELO Command Extraction ──> STARTTLS Stripping Detection        │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                 3. CRYPTOGRAPHIC & CERTIFICATE FORENSICS               │
│   TLS Record Dissection (v1.0-1.3) ──> Full X.509 Cert Chain Analysis  │
│   JA3 / JA3S & JA4 / JA4S Client/Server Cryptographic Fingerprinting   │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                    4. DECLARATIVE COMPLIANCE ENGINE                    │
│   AST-Safe Rule Evaluations: NIST SP 800-52r2 | PCI-DSS v4.0 | RFC 8996│
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│               5. DUAL-LAYER EXPLAINABLE AI & ANOMALY ML                │
│   • Calibrated Base Risk (0–100)                                       │
│   • SHAP Mathematical Feature Attribution Vectors                      │
│   • Unsupervised Isolation Forest Anomaly Detection                    │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                  6. SOC COMMAND CENTER & DOSSIER EXPORT                │
│   • Real-Time Interactive SOC Console (Fleet Overview & Session Deep)  │
│   • Multi-Format Boardroom Dossiers (PDF, HTML, JSON)                  │
│   • AI Remediation Synthesizer (Hardened MTA Configs)                  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🛡️ Core Capabilities

### 1. Passive Stream Reconstruction & Protocol ID
- Reassembles fragmented TCP flows across standard email ports (`25`, `465`, `587`, `110`, `995`, `143`, `993`).
- Detects plaintext commands (`EHLO`, `HELO`, `STARTTLS`, `AUTH`, `QUIT`) prior to encryption initiation.
- Immediately flags downgrade attacks where `STARTTLS` was stripped from the server's response.

### 2. Deep TLS Handshake & Certificate Dissection
- Extracts TLS version, cipher suite, key exchange mechanism, elliptic curve parameters, and TLS extensions.
- Validates the complete X.509 certificate chain: expiration dates, validity windows, self-signed origins, SHA-1/MD5 hashing, and weak RSA/ECC keys.
- Operates specialized heuristics for TLS 1.3 to inspect encrypted handshakes accurately via ClientHello/ServerHello negotiations.

### 3. Cryptographic Fingerprinting (JA3/JA3S & JA4/JA4S)
- Calculates standard **JA3 / JA3S** MD5 fingerprints for rapid threat intelligence feeds.
- Computes modern **JA4 / JA4S** alphanumeric fingerprints for precise client application and server daemon identification.

### 4. Declarative Compliance Rulebook
- Evaluates traffic against a modular YAML security rulebook.
- Cross-references violations directly against:
  - **NIST SP 800-52r2**: Guidelines for the Selection, Configuration, and Use of Transport Layer Security (TLS) Implementations.
  - **PCI-DSS v4.0 Requirements 4.1 & 4.2**: Safeguarding cardholder data in transit.
  - **RFC 8996**: Deprecation of TLS 1.0 and TLS 1.1.
  - **RFC 8314**: Cleartext Considered Obsolete: Use of TLS for Email Submission and Access.

### 5. Explainable AI (XAI) & Anomaly Attribution
- **Scored Risk (0–100)**: Normalizes findings into clear severity bands (Critical, High, Medium, Low, Secure).
- **SHAP (SHapley Additive exPlanations)**: Calculates game-theoretic feature contributions for every session, demonstrating the exact percentage impact of each finding on the total risk score.
- **Isolation Forest**: Spots anomalous cryptographic signatures, rare cipher suite combinations, and atypical handshake sizes without requiring labeled training datasets.

### 6. AI Security Copilot & Remediation Synthesizer
- Built-in contextual security assistant that translates complex cryptographic telemetry into plain-English root causes.
- Generates hardened, copy-pasteable configuration scripts for popular MTAs (**Postfix `main.cf`, Exim, Sendmail, Dovecot, and Nginx SSL termination**).

### 7. Fleet-Wide Host Cartography & Threat Rollup
- Aggregates session telemetry by IP and Fully Qualified Domain Name (FQDN).
- Employs **Worst-Session Weighting** to ensure that critical vulnerabilities on high-value mail servers are never hidden or diluted by massive volumes of low-risk background traffic.

### 8. Multi-Format Executive Audit Dossiers
- Exports detailed audit reports for C-suite executives, external auditors, and SOC engineers.
- Available on-demand in **PDF** (multi-page, print-ready), **HTML** (interactive standalone report), and **JSON** (machine-readable SIEM ingestion).

---

## 📁 Repository Organization & Architecture

```
Secure SMTP/
├── src/
│   ├── secure_smtp/               # Primary Python backend package
│   │   ├── config.py              # Centralized Pydantic settings & env loader
│   │   ├── ai/                    # ML risk scoring, Isolation Forest & AI Copilot
│   │   ├── alerts/                # Webhook & Slack notification routing
│   │   ├── api/                   # FastAPI application & modular routers
│   │   │   ├── main.py            # Clean application entrypoint & middleware
│   │   │   ├── broker.py          # WebSocket real-time event broker
│   │   │   ├── pipeline.py        # Asynchronous PCAP analysis pipeline
│   │   │   └── routers/           # Domain-specific route controllers
│   │   │       ├── system.py      # Health checks & client downloads
│   │   │       ├── analysis.py    # PCAP upload & job status
│   │   │       ├── hosts.py       # Host fleet inventory & drill-downs
│   │   │       ├── sessions.py    # Session forensics & SHAP explanations
│   │   │       ├── reports.py     # JSON, HTML, PDF report downloads
│   │   │       ├── compliance.py  # NIST, PCI-DSS, HIPAA compliance checks
│   │   │       ├── copilot.py     # AI remediation synthesizer & Q&A
│   │   │       └── live.py        # Multi-port live mail lab & WebSocket stream
│   │   ├── compliance/            # Regulatory frameworks & compliance mapping
│   │   ├── db/                    # MongoDB session managers & Pydantic models
│   │   ├── ingest/                # PCAP reader, TCP reassembly & protocol ID
│   │   ├── live/                  # Live mail server, certs & client dispatcher
│   │   ├── reporting/             # ReportLab PDF, Jinja2 HTML & JSON exporters
│   │   ├── rules/                 # Declarative YAML rule engine
│   │   └── tls/                   # TLS handshake parsing, certs & fingerprints
│   └── securemailscope/           # Backward-compatibility bridge
├── frontend/                      # React 19 + Vite SOC Web Console
│   ├── src/
│   │   ├── components/            # Reusable UI widgets & barrel export
│   │   ├── pages/                 # Full-page views (Fleet, Sessions, Live, AI)
│   │   ├── context/               # Authentication & session state context
│   │   ├── api/                   # Typed API client wrapper
│   │   ├── utils/                 # Visual formatting & color utilities
│   │   ├── config/                # Clerk theme configuration
│   │   ├── App.jsx                # Application routing tree
│   │   └── main.jsx               # React DOM entrypoint
│   ├── package.json               # Frontend dependencies & scripts
│   └── vite.config.js             # Vite configuration & dev proxy
├── scripts/                       # Maintenance, provisioning & seeding scripts
│   ├── seed_demo_data.py          # Ingests fixture PCAPs into MongoDB
│   ├── setup_mongo_auth.py        # Configures SCRAM-SHA-256 DB security
│   ├── generate_test_pcaps.py     # Scapy synthetic PCAP generator
│   └── README.md                  # Script documentation & usage guide
├── tests/                         # Unit & integration test suite
│   ├── fixtures/pcaps/            # Cryptographic test PCAP vectors
│   └── unit/                      # 168 comprehensive unit tests
├── docker/                        # Deployment configurations & Nginx proxy
├── attacker_proxy.py              # Zero-dependency MITM/downgrade proxy
├── demo_client.py                 # Zero-dependency interactive SMTP client
├── start_demo.sh                  # One-command full-stack presentation launcher
└── pyproject.toml                 # Backend dependencies & pytest config
```

---

## 🚀 Quick Start Guide

### Prerequisites
- **Python 3.10+** (with virtual environment)
- **Node.js 18+** & npm
- **MongoDB** running locally or in Docker

### 1. Launch the Full Stack (Single Command)
```bash
./start_demo.sh
```
This automatically:
1. Activates the Python virtual environment.
2. Seeds MongoDB with realistic demo traffic.
3. Starts the FastAPI backend on `http://localhost:8000`.
4. Starts the Live Mail Lab on ports `2525`, `2526`, `2527`, `2528`.
5. Starts the React Web Console on `http://localhost:5173`.

### 2. Run Test Suite
```bash
# Python backend tests (176 unit tests covering security hardening, AI, and forensics)
pytest

# Frontend linter (oxlint: 0 warnings, 0 errors)
npm run lint --prefix frontend

# Frontend production bundle compilation
npm run build --prefix frontend
```

### 3. Production Deployment with Docker
Launch the containerized production stack (MongoDB 7.0, Redis 7, FastAPI backend, Nginx frontend reverse proxy):
```bash
# Configure production secrets
cp .env.example .env
# Edit .env with your production SECURE_SMTP_API_KEY and Mongo credentials

# Build and start services in detached mode
docker compose up -d --build

# View operational logs
docker compose logs -f
```

---

## 🛡️ Security Hardening & Testing Verification

Secure SMTP includes multi-layered enterprise defense mechanisms ready for penetration testing and red-team audits:

| Security Control | Implementation Mechanism | Red-Team Testing Command |
|---|---|---|
| **In-Memory Rate Limiting** | Sliding-window quota (15/min uploads, 5/min database resets, 30/min Copilot) with automatic HTTP 429 & `Retry-After` headers. | Rapidly send 6 requests: `for i in {1..6}; do curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:8000/api/live/clear-history -H "X-API-Key: securesmtp_live_secret_key"; done` (Yields `429 Too Many Requests`). |
| **PCAP Upload Safety** | Pre-flight magic byte inspection (`0xa1b2c3d4`, `0x0a0d0d0a`) and 64KB chunked streaming with 100MB quota. | `curl -X POST http://localhost:8000/api/analyze -H "X-API-Key: securesmtp_live_secret_key" -F "file=@README.md;filename=fake.pcap"` (Yields `400 Bad Request: Invalid capture format`). |
| **WebSocket Authentication** | Constant-time token verification (`secrets.compare_digest`) on `/ws/live?token=...` with WS close code 1008. | Connect with an invalid token: `wscat -c "ws://localhost:8000/ws/live?token=invalid"` (Connection drops immediately with code 1008). |
| **Security Headers & Tracing** | Automatic injection of `X-Request-ID`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection`, and `Permissions-Policy`. | `curl -i http://localhost:8000/api/health` and inspect defensive response headers. |
| **Production Fail-Fast Secret Check** | Application refuses to boot in `SECURE_SMTP_ENV=production` if default development secret is retained. | `SECURE_SMTP_ENV=production uvicorn secure_smtp.api.main:app` (Raises `RuntimeError: Refusing to start in production mode...`). |

---

## 🎯 Target Audience & Operational Context

Secure SMTP is engineered for:

- **Security Operations Center (SOC) Teams**: Real-time triage of mail-related alerts, credential exposure warnings, and anomalous network activity.
- **Cryptographic & Compliance Auditors**: Automated generation of evidence for PCI-DSS, NIST, and ISO 27001 email transport assessments.
- **Incident Response (IR) Investigators**: Rapid post-incident PCAP forensics to verify whether eavesdropping or STARTTLS stripping occurred during a breach window.
- **Network & Infrastructure Engineers**: Pre-deployment validation and continuous monitoring of enterprise MTA configurations to prevent cryptographic regression.

---

## 👤 Author & Ownership

**Secure SMTP** is designed and maintained by **Harshit Sharma** ([@sharmaharshit1661-web](https://github.com/sharmaharshit1661-web)).

---

## 📄 License

This project is licensed under the **MIT License**.
