"""Bounded SQLite outbox. Payloads survive crashes; only acknowledged batches are removed."""

import json
import os
import sqlite3
import threading
from uuid import uuid4

from secure_smtp.monitoring.schema import ObservationBatch


class Outbox:
    def __init__(self, path, max_bytes=50 * 1024 * 1024, max_batches=2000):
        os.makedirs(os.path.dirname(os.path.abspath(path)), mode=0o700, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        os.chmod(path, 0o600)
        self.lock = threading.Lock()
        self.max_bytes, self.max_batches = max_bytes, max_batches
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA wal_autocheckpoint=64")
        self.db.execute("PRAGMA journal_size_limit=262144")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS batches (id TEXT PRIMARY KEY, payload TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP)"
        )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL)"
        )
        self.db.commit()

    def increment(self, name, amount=1):
        with self.lock, self.db:
            self.db.execute(
                "INSERT INTO counters VALUES (?,?) ON CONFLICT(name) DO UPDATE SET value=value+excluded.value",
                (name, amount),
            )

    def enqueue(self, observations):
        payload = ObservationBatch(batch_id=uuid4(), observations=observations)
        encoded = payload.model_dump_json()
        with self.lock, self.db:
            count, size = self.db.execute(
                "SELECT COUNT(*), COALESCE(SUM(length(CAST(payload AS BLOB))),0) FROM batches"
            ).fetchone()
            if count >= self.max_batches or size + len(encoded.encode()) > self.max_bytes:
                self.db.execute(
                    "INSERT INTO counters VALUES ('dropped_events',?) ON CONFLICT(name) DO UPDATE SET value=value+excluded.value",
                    (len(observations),),
                )
                return False
            self.db.execute(
                "INSERT INTO batches(id,payload) VALUES (?,?)", (str(payload.batch_id), encoded)
            )
        return True

    def oldest(self):
        with self.lock:
            row = self.db.execute(
                "SELECT id,payload FROM batches ORDER BY rowid LIMIT 1"
            ).fetchone()
            return row

    def acknowledge(self, batch_id):
        with self.lock, self.db:
            self.db.execute("DELETE FROM batches WHERE id=?", (batch_id,))

    def health(self):
        with self.lock:
            counters = dict(self.db.execute("SELECT name,value FROM counters"))
            counters["queued_events"] = sum(
                len(json.loads(row[0])["observations"])
                for row in self.db.execute("SELECT payload FROM batches")
            )
            return counters

    def close(self):
        with self.lock:
            self.db.close()
