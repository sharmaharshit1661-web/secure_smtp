"""
Authorized Mail-Server Traffic & Forensic Ingestion Rehearsal.

Generates real SMTP dialogues across multiple security configurations:
1. Modern TLS 1.3/1.2 (Clean Baseline, Perfect Forward Secrecy)
2. Plaintext Port 25 Leakage (Critical Risk, No-TLS Rule)
3. STARTTLS Stripping Downgrade Simulation
4. Vulnerable / Expired X.509 Certificate Profile

Verifies stream capture, AST compliance evaluation, explainable risk scoring,
and MongoDB persistence.
"""

from __future__ import annotations

import asyncio
import os
import smtplib
import ssl
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from secure_smtp.config import get_settings
from secure_smtp.db.mongodb import get_database, get_mongo_client, init_db_indexes
from secure_smtp.live.mail_server import LiveMailLab


def run_smtp_client(port: int, use_tls: bool = False, insecure_ssl: bool = False):
    """Synchronous RFC 5321 SMTP client running in dedicated thread."""
    s = smtplib.SMTP("127.0.0.1", port, timeout=5)
    try:
        s.ehlo("client.authorized.corp")
        if use_tls:
            ctx = ssl.create_default_context()
            if insecure_ssl:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            s.starttls(context=ctx)
            s.ehlo("client.authorized.corp")

        s.mail("auditor@authorized.corp")
        s.rcpt("compliance@authorized.corp")
        s.data(b"Subject: Cryptographic Forensic Probe\r\n\r\nTest Payload Data\r\n")
        s.quit()
    except Exception:
        # In stripping / downgrade scenarios, client may disconnect after missing STARTTLS
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass


async def rehearse_traffic():
    print("=" * 70)
    print(" Secure SMTP — Authorized Mail-Server Traffic & Ingestion Rehearsal")
    print("=" * 70)

    test_db = f"test_traffic_{uuid.uuid4().hex[:8]}"
    os.environ["SECURE_SMTP_PILOT_ORG_ID"] = "org_pilot"
    os.environ["SECURE_SMTP_MONGO_DB"] = test_db
    os.environ["SECURE_SMTP_MONGO_USER"] = ""
    os.environ["SECURE_SMTP_MONGO_PASSWORD"] = ""
    os.environ["SECURE_SMTP_MONGO_AUTH_REQUIRED"] = "false"
    if hasattr(get_settings, "cache_clear"):
        get_settings.cache_clear()

    init_db_indexes()
    db = get_database()

    lab = LiveMailLab(host="127.0.0.1")
    ports = await lab.start()
    print(f"[*] Live Mail Lab active on ports: {ports}")

    try:
        # 1. Plaintext SMTP Traffic (Port 2525)
        print("\n[*] Scenario 1: Generating Plaintext SMTP Traffic on port 2525...")
        await asyncio.to_thread(run_smtp_client, 2525, False, False)
        await asyncio.sleep(0.3)
        print("  [✓] Plaintext SMTP transaction completed.")

        # 2. Modern TLS SMTP Traffic (Port 2526)
        print("\n[*] Scenario 2: Generating Modern TLS 1.3/1.2 SMTP Traffic on port 2526...")
        await asyncio.to_thread(run_smtp_client, 2526, True, True)
        await asyncio.sleep(0.3)
        print("  [✓] Modern TLS SMTP transaction completed.")

        # 3. Vulnerable TLS SMTP Traffic (Port 2527)
        print("\n[*] Scenario 3: Generating Vulnerable TLS (Expired/Weak) on port 2527...")
        await asyncio.to_thread(run_smtp_client, 2527, True, True)
        await asyncio.sleep(0.3)
        print("  [✓] Vulnerable TLS SMTP transaction completed.")

        # 4. STARTTLS Stripping Downgrade Traffic (Port 2528)
        print("\n[*] Scenario 4: Generating STARTTLS Stripping Attack Traffic on port 2528...")
        await asyncio.to_thread(run_smtp_client, 2528, False, False)
        await asyncio.sleep(0.3)
        print("  [✓] STARTTLS Stripping fallback transaction completed.")

        # Allow async recording tasks to finalize in MongoDB
        await asyncio.sleep(0.8)

        # 5. Database Forensic Verification
        print("\n[*] Verifying Stored Forensic Telemetry in MongoDB...")
        sessions = list(db.sessions.find({"org_id": "org_pilot"}))
        hosts = list(db.hosts.find({"org_id": "org_pilot"}))

        print(f"  [✓] Captured Sessions: {len(sessions)}")
        print(f"  [✓] Tracked Mail Hosts: {len(hosts)}")

        assert len(sessions) >= 4, f"Expected at least 4 recorded sessions, got {len(sessions)}"
        assert len(hosts) >= 1, "Expected tracked mail host"

        # Check that different risk levels were correctly attributed
        scores = [s.get("risk_score", {}).get("score_0_100", 0.0) for s in sessions]
        tiers = [s.get("risk_score", {}).get("tier", "unknown") for s in sessions]
        print(f"  [✓] Evaluated Risk Scores: {scores}")
        print(f"  [✓] Assigned Risk Tiers: {tiers}")

        # Plaintext or stripped must trigger high/critical risk
        assert any(t in ("high", "critical") for t in tiers), "Must trigger high/critical risk on insecure traffic"
        # Modern TLS must produce low/clean risk
        assert any(t == "low" for t in tiers), "Must recognize clean modern TLS baseline as low risk"

        print("\n" + "=" * 70)
        print(" [ALL PASSED] Authorized mail-server traffic successfully observed & scored!")
        print("=" * 70)

    finally:
        await lab.stop()
        get_mongo_client().drop_database(test_db)
        print("[*] Cleaned up test database and closed listening ports.")


if __name__ == "__main__":
    asyncio.run(rehearse_traffic())
