# Implementation Decisions — Secure SMTP

Key architecture and implementation decisions made for the Secure SMTP platform:

| # | Decision | Rationale |
|---|---|---|
| 1 | **React 19 + Vite SOC Web Console** | High-performance, zero-latency reactive dashboard with real-time WebSocket packet streaming, interactive attack simulation terminals, and Recharts visualization. |
| 2 | **Modular FastAPI Router Architecture** | Decomposed API endpoints into clean domain routers (`system`, `analysis`, `hosts`, `sessions`, `reports`, `compliance`, `copilot`, `live`) with dedicated pipeline and broker abstractions for maximum maintainability. |
| 3 | **MongoDB Document Model** (PyMongo) | Direct alignment with architecture diagram; allows natural document hierarchy for sessions with embedded TLS handshakes, certificate chains, rule findings, and SHAP vectors. |
| 4 | **Deterministic Synthetic PCAPs** | Scapy-generated PCAPs ensure 100% reproducible cryptographic test vectors covering STARTTLS stripping, weak ciphers, and expired certs. |
| 5 | **Native JA3 / JA3S & JA4 / JA4S Fingerprinting** | Computes MD5 and SHA-256 client/server cryptographic hashes directly from raw handshake records. |
| 6 | **Safe Condition DSL** for Rule Engine | Safe AST evaluation against declarative YAML rulebook without raw `eval()` vulnerabilities. |
| 7 | **Explainable AI (SHAP + Isolation Forest)** | Transparent percentage attributions for every risk score (0–100) and statistical anomaly detection against baseline fleet behaviors. |
| 8 | **Comprehensive Compliance Mapping** | Mapped rulebook to NIST SP 800-52r2, PCI-DSS v4.0, and RFC 8996 standards. |
| 9 | **Worst-Session Weighting for Host Rollup** | Surfaces genuine high-risk infrastructure threats without being diluted by high volumes of benign sessions. |
| 10 | **Multi-Engine PDF Generation (ReportLab First)** | Fast, pure-Python PDF synthesis avoiding native C-library dlopen crashes on macOS while delivering boardroom-ready audit dossiers. |
| 11 | **Sliding-Window In-Memory Rate Limiting** | Thread-safe, memory-bounded sliding window rate limiter enforcing per-route and per-client quotas with standard 429 Retry-After headers without external Redis dependency. |
| 12 | **PCAP Streaming & Magic Byte Pre-Flight Validation** | Streams uploads to disk in 64KB chunks up to a configurable ceiling (100MB) while verifying PCAP/PCAPNG magic signature bytes before job submission. |
| 13 | **Defensive Security Headers & End-to-End Tracing** | Automatically injects `X-Request-ID` tracing alongside `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection`, and `Permissions-Policy`. |
| 14 | **Production Fail-Fast Secret Enforcement** | Fast startup verification refusing to boot in production (`SECURE_SMTP_ENV=production`) if default development secrets are detected. |
