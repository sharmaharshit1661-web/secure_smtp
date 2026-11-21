"""
Database Models & MongoDB Persistence Package.

Provides Pydantic data models and MongoDB collection managers for mail hosts,
sessions, handshakes, findings, risk scores, and asynchronous analysis jobs.
"""

from __future__ import annotations

from secure_smtp.db.models import (
    AnalysisJob,
    AnomalyScore,
    Certificate,
    Finding,
    Host,
    RiskScore,
    Session,
    TLSHandshake,
)
from secure_smtp.db.mongodb import (
    drop_database,
    get_database,
    get_hosts_col,
    get_jobs_col,
    get_next_sequence,
    get_sessions_col,
    init_db_indexes,
    serialize_doc,
)

__all__ = [
    "Session",
    "Host",
    "Finding",
    "RiskScore",
    "TLSHandshake",
    "Certificate",
    "AnomalyScore",
    "AnalysisJob",
    "get_database",
    "get_hosts_col",
    "get_sessions_col",
    "get_jobs_col",
    "get_next_sequence",
    "init_db_indexes",
    "serialize_doc",
    "drop_database",
]
