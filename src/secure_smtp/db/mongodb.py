"""
MongoDB connection and collection management for Secure SMTP.

Provides connection pooling, collection accessors, sequence generators for integer IDs,
indexing, and document serialization helpers.
"""

from __future__ import annotations

import logging
import re
import urllib.parse
from datetime import datetime
from typing import Any

from pymongo import ASCENDING, DESCENDING, MongoClient, ReturnDocument
from pymongo.database import Database
from pymongo.errors import ConnectionFailure, OperationFailure, ServerSelectionTimeoutError

from secure_smtp.config import get_settings

logger = logging.getLogger(__name__)

# Configurable MongoDB Settings from centralized Settings
settings = get_settings()
MONGO_HOST = settings.mongo_host
MONGO_PORT = settings.mongo_port
DATABASE_NAME = settings.mongo_db
MONGO_USER = settings.mongo_user
MONGO_PASSWORD = settings.mongo_password
MONGO_AUTH_DB = settings.mongo_auth_db
MONGO_AUTH_MECHANISM = settings.mongo_auth_mechanism
MONGO_AUTH_REQUIRED = settings.mongo_auth_required
EXPLICIT_MONGO_URI = settings.mongo_uri or ""


def build_mongo_uri(
    user: str = "",
    password: str = "",
    host: str = "",
    port: int = 0,
    db_name: str = "",
    auth_db: str = "",
    auth_mechanism: str = "",
) -> str:
    """
    Build a well-formed MongoDB connection URI, safely percent-encoding
    usernames and passwords that contain special characters.
    """
    curr = get_settings()
    u = user if user is not None and user != "" else ""
    p = password if password is not None and password != "" else ""
    h = host or curr.mongo_host
    pt = port or curr.mongo_port
    db = db_name or curr.mongo_db
    adb = auth_db if auth_db != "" else curr.mongo_auth_db
    amech = auth_mechanism if auth_mechanism != "" else curr.mongo_auth_mechanism

    if u and p:
        encoded_user = urllib.parse.quote_plus(u)
        encoded_pwd = urllib.parse.quote_plus(p)
        query_params = []
        if adb:
            query_params.append(f"authSource={urllib.parse.quote_plus(adb)}")
        if amech:
            query_params.append(f"authMechanism={urllib.parse.quote_plus(amech)}")
        query_str = f"?{'&'.join(query_params)}" if query_params else ""
        return f"mongodb://{encoded_user}:{encoded_pwd}@{h}:{pt}/{db}{query_str}"
    elif u:
        encoded_user = urllib.parse.quote_plus(u)
        query_params = []
        if adb:
            query_params.append(f"authSource={urllib.parse.quote_plus(adb)}")
        query_str = f"?{'&'.join(query_params)}" if query_params else ""
        return f"mongodb://{encoded_user}@{h}:{pt}/{db}{query_str}"
    else:
        return f"mongodb://{h}:{pt}/{db}"


def get_active_mongo_uri() -> str:
    """Return the active MongoDB connection URI from Settings."""
    return get_settings().get_mongo_connection_uri()


# Default MONGO_URI for backwards compatibility
MONGO_URI = get_active_mongo_uri()


def get_masked_mongo_uri(uri: str | None = None) -> str:
    """
    Return a redacted version of the MongoDB URI for safe logging and status reporting.
    Replaces the password component with '******' to prevent secret leakage.
    """
    if uri:
        return re.sub(r":([^/@]+)@", r":******@", uri)
    return get_settings().get_masked_mongo_uri()


def get_mongo_auth_status() -> dict[str, Any]:
    """
    Check MongoDB connectivity and authentication posture.
    Returns connection status, latency, authentication status, and redacted URI.
    """
    curr = get_settings()
    active_uri = curr.get_mongo_connection_uri()
    is_authenticated = bool(curr.mongo_user and curr.mongo_password) or (
        ":" in active_uri.split("@")[0] if "@" in active_uri else False
    )

    username = curr.mongo_user
    if not username and "@" in active_uri:
        try:
            user_part = active_uri.split("://")[1].split("@")[0]
            username = urllib.parse.unquote_plus(user_part.split(":")[0])
        except Exception:
            username = None

    try:
        client = get_mongo_client()
        ping_res = client.admin.command("ping")
        return {
            "status": "connected",
            "ping": ping_res.get("ok") == 1.0,
            "auth_enabled": is_authenticated,
            "auth_required": curr.mongo_auth_required,
            "authenticated_user": username if is_authenticated else None,
            "auth_source": curr.mongo_auth_db if is_authenticated else None,
            "database": curr.mongo_db,
            "uri_masked": get_masked_mongo_uri(active_uri),
        }
    except OperationFailure as e:
        logger.error("MongoDB authentication failure: %s", e)
        return {
            "status": "auth_failure",
            "error": str(e),
            "auth_enabled": is_authenticated,
            "auth_required": curr.mongo_auth_required,
            "authenticated_user": username,
            "database": curr.mongo_db,
            "uri_masked": get_masked_mongo_uri(active_uri),
        }
    except (ConnectionFailure, ServerSelectionTimeoutError) as e:
        logger.error("MongoDB connection failure: %s", e)
        return {
            "status": "disconnected",
            "error": str(e),
            "auth_enabled": is_authenticated,
            "auth_required": curr.mongo_auth_required,
            "authenticated_user": username,
            "database": curr.mongo_db,
            "uri_masked": get_masked_mongo_uri(active_uri),
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "auth_enabled": is_authenticated,
            "auth_required": curr.mongo_auth_required,
            "authenticated_user": username,
            "database": curr.mongo_db,
            "uri_masked": get_masked_mongo_uri(active_uri),
        }


_client: MongoClient | None = None


def get_mongo_client(uri: str | None = None) -> MongoClient:
    """Get or initialize singleton PyMongo MongoClient with authentication support."""
    global _client
    if _client is None or uri is not None:
        target_uri = uri or get_active_mongo_uri()
        _client = MongoClient(
            target_uri,
            serverSelectionTimeoutMS=5000,
            connectTimeoutMS=5000,
            tz_aware=True,
        )
    return _client


def get_database(db_name: str | None = None) -> Database:
    """Get the active MongoDB database instance."""
    client = get_mongo_client()
    return client[db_name or getattr(get_settings(), "mongo_db", DATABASE_NAME)]


# ── Collection Accessors ──


def get_hosts_col():
    """Access the `hosts` collection."""
    return get_database()["hosts"]


def get_sessions_col():
    """Access the `sessions` collection."""
    return get_database()["sessions"]


def get_jobs_col():
    """Access the `analysis_jobs` collection."""
    return get_database()["analysis_jobs"]


def get_counters_col():
    """Access the `counters` collection for integer ID generation."""
    return get_database()["counters"]


# ── Sequence Helper for Integer IDs ──


def get_next_sequence(name: str) -> int:
    """
    Generate an atomic auto-incrementing integer ID for entities (host_id, session_id).
    Ensures seamless compatibility with numerical IDs used in APIs and dashboards.
    """
    col = get_counters_col()
    result = col.find_one_and_update(
        {"_id": name},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=ReturnDocument.AFTER,
    )
    return result["seq"]


# ── Database Lifecycle Helpers ──


def init_db_indexes() -> None:
    """Initialize performance and uniqueness indexes on collections."""
    try:
        hosts = get_hosts_col()
        try:
            hosts.drop_index("ip_or_hostname_1")
        except Exception:
            pass
        hosts.create_index([("org_id", ASCENDING), ("ip_or_hostname", ASCENDING)], unique=True)
        hosts.create_index([("id", ASCENDING)], unique=True)
        hosts.create_index([("aggregate_risk_score", DESCENDING)])

        sessions = get_sessions_col()
        sessions.create_index([("id", ASCENDING)], unique=True)
        sessions.create_index([("host_id", ASCENDING)])
        sessions.create_index([("pcap_source", ASCENDING)])
        sessions.create_index([("org_id", ASCENDING), ("job_id", ASCENDING)])

        jobs = get_jobs_col()
        jobs.create_index([("job_id", ASCENDING)], unique=True)
        db = get_database()
        db.users.create_index("email", unique=True)
        db.agents.create_index("agent_id", unique=True)
        db.sessions.create_index(
            [("agent_id", ASCENDING), ("event_id", ASCENDING)],
            unique=True,
            partialFilterExpression={"event_id": {"$type": "string"}},
        )
        db.event_tombstones.create_index(
            [("agent_id", ASCENDING), ("event_id", ASCENDING)], unique=True
        )
        db.event_tombstones.create_index("expires_at", expireAfterSeconds=0)
        db.audit.create_index([("org_id", ASCENDING), ("created_at", DESCENDING)])
        db.alert_deliveries.create_index("dedupe_key", unique=True)
        db.remediations.create_index(
            [("org_id", ASCENDING), ("session_id", ASCENDING), ("rule_id", ASCENDING)], unique=True
        )
        logger.info("MongoDB indexes successfully created on database: %s", DATABASE_NAME)
    except Exception:
        logger.error("Failed to initialize MongoDB indexes")
        raise


def drop_database() -> None:
    """Drop the database — use for testing / clean wipe."""
    client = get_mongo_client()
    client.drop_database(DATABASE_NAME)
    logger.info("MongoDB database '%s' dropped.", DATABASE_NAME)


def serialize_doc(doc: dict[str, Any] | None) -> dict[str, Any] | None:
    """
    Recursively serialize MongoDB document for JSON / API responses.
    Converts ObjectId to string, ISO-formats datetimes, and ensures clean dict keys.
    """
    if doc is None:
        return None
    res = {}
    for k, v in doc.items():
        if k == "_id":
            res["mongo_id"] = str(v)
        elif isinstance(v, datetime):
            res[k] = v.isoformat()
        elif isinstance(v, dict):
            res[k] = serialize_doc(v)
        elif isinstance(v, list):
            res[k] = [serialize_doc(item) if isinstance(item, dict) else item for item in v]
        else:
            res[k] = v
    return res
