"""
Database management bridge for Secure SMTP.

Provides compatibility functions for MongoDB initialization and collection resets.
"""

from __future__ import annotations

from secure_smtp.db.mongodb import (
    drop_database,
    init_db_indexes,
)


def create_db_and_tables(db_url: str | None = None) -> None:
    """Initialize MongoDB database and collection indexes."""
    init_db_indexes()


def drop_all_tables(db_url: str | None = None) -> None:
    """Drop MongoDB database — use for testing / clean wipe."""
    drop_database()
