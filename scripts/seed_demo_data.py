#!/usr/bin/env python3
"""
Seed demo data for Secure SMTP (MongoDB).

Analyzes the real fixture PCAPs and seeds the MongoDB database with
realistic email traffic sessions, TLS handshakes, certificates, rule findings,
and AI risk scores for immediate presentation.
"""

import sys
from pathlib import Path

# Add src to pythonpath
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from secure_smtp.api.main import _run_analysis
from secure_smtp.db.models import AnalysisJob
from secure_smtp.db.mongodb import (
    drop_database,
    get_hosts_col,
    get_jobs_col,
    get_next_sequence,
    get_sessions_col,
    init_db_indexes,
)


def seed():
    print("=" * 60)
    print("🛡️ Secure SMTP — Seeding MongoDB Demo Data")
    print("=" * 60)

    hosts_col = get_hosts_col()
    sessions_col = get_sessions_col()
    h_count = hosts_col.count_documents({})
    s_count = sessions_col.count_documents({})

    force = "--force" in sys.argv
    if not force and h_count > 0 and s_count > 0:
        print(f"ℹ️ MongoDB already populated with {h_count} hosts and {s_count} sessions.")
        print("   Skipping re-analysis. Run 'python scripts/seed_demo_data.py --force' to reseed.")
        print("=" * 60)
        return

    # 1. Clean wipe MongoDB
    drop_database()
    init_db_indexes()
    print("✅ MongoDB database wiped clean & indexes initialized.")

    pcaps_dir = PROJECT_ROOT / "tests" / "fixtures" / "pcaps"
    if not pcaps_dir.exists():
        print(f"Error: PCAP directory not found at {pcaps_dir}")
        return

    # Ingest all available fixture PCAPs
    pcap_files = sorted([f for f in pcaps_dir.glob("*.pcap") if f.name != "demo_composite.pcap"])
    composite_pcap = pcaps_dir / "demo_composite.pcap"
    if composite_pcap.exists():
        pcap_files.append(composite_pcap)

    jobs_col = get_jobs_col()

    for pcap_path in pcap_files:
        job_id = f"demo-{pcap_path.stem}"
        job = AnalysisJob(
            id=get_next_sequence("job_id"),
            job_id=job_id,
            pcap_filename=pcap_path.name,
            status="queued",
        )
        jobs_col.insert_one(job.model_dump())

        print(f"Analyzing {pcap_path.name} (Job: {job_id})...")
        _run_analysis(job_id, str(pcap_path))

    hosts_col = get_hosts_col()
    sessions_col = get_sessions_col()

    h_count = hosts_col.count_documents({})
    s_count = sessions_col.count_documents({})

    print("=" * 60)
    print(f"✅ Seeding Complete! MongoDB populated with {h_count} hosts and {s_count} sessions.")
    print("=" * 60)


if __name__ == "__main__":
    seed()
