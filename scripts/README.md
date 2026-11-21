# Secure SMTP — Utility & Automation Scripts

This directory houses maintenance, provisioning, test fixture generation, and demonstration seeding scripts.

---

## Script Inventory

| Script | Type | Description |
|---|---|---|
| [`seed_demo_data.py`](file:///Users/harshit/Desktop/Secure%20SMTP/scripts/seed_demo_data.py) | Python | Ingests all fixture PCAPs and seeds MongoDB with realistic mail sessions, handshakes, certificates, rule violations, and AI risk scores. |
| [`setup_mongo_auth.py`](file:///Users/harshit/Desktop/Secure%20SMTP/scripts/setup_mongo_auth.py) | Python | Configures SCRAM-SHA-256 administrative and service user credentials in MongoDB. |
| [`generate_test_pcaps.py`](file:///Users/harshit/Desktop/Secure%20SMTP/scripts/generate_test_pcaps.py) | Python (Scapy) | Generates synthetic yet cryptographically valid PCAPs simulating STARTTLS stripping, expired certs, weak ciphers, and clean sessions. |
| [`generate_test_pcaps.sh`](file:///Users/harshit/Desktop/Secure%20SMTP/scripts/generate_test_pcaps.sh) | Shell | Wrapper script to invoke `generate_test_pcaps.py` within the activated virtual environment. |

---

## Common Usage

### 1. Reseed MongoDB Demo Data
```bash
# Verify existing database
PYTHONPATH=src python3 scripts/seed_demo_data.py

# Force wipe and re-ingest all fixture PCAPs
PYTHONPATH=src python3 scripts/seed_demo_data.py --force
```

### 2. Configure MongoDB Authentication
```bash
python3 scripts/setup_mongo_auth.py
```

### 3. Regenerate Synthetic Test PCAPs
```bash
./scripts/generate_test_pcaps.sh
```
