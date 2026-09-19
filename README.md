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
