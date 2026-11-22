"""Run from the project root. Requires mongod, mongodump, mongorestore and dev dependencies."""

import hashlib
import hmac
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]


@contextmanager
def disposable_mongo(root, *, authenticated=False):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    dbpath = root / "mongo"
    dbpath.mkdir()
    process = subprocess.Popen(
        [
            "mongod",
            "--bind_ip",
            "127.0.0.1",
            "--port",
            str(port),
            "--dbpath",
            str(dbpath),
            "--logpath",
            str(root / "mongo.log"),
            *(["--auth"] if authenticated else []),
        ],
        stdout=subprocess.DEVNULL,
    )
    from pymongo import MongoClient

    uri = f"mongodb://127.0.0.1:{port}"
    try:
        with MongoClient(uri, serverSelectionTimeoutMS=500) as mongo:
            for _ in range(30):
                if process.poll() is not None:
                    raise RuntimeError("Disposable MongoDB failed to start")
                try:
                    mongo.admin.command("ping")
                    break
                except Exception:
                    time.sleep(0.25)
            else:
                raise RuntimeError("Disposable MongoDB did not become healthy")
            yield uri, mongo
    finally:
        process.terminate()
        process.wait(timeout=30)


def rehearse(root, uri, mongo, webhook):
    # The analysis child inherits these isolated settings. Never read a deployment .env.
    os.chdir(root)
    sys.path.insert(0, str(ROOT / "src"))
    os.environ.update(
        PYTHONPATH=str(ROOT / "src"),
        SECURE_SMTP_MONGO_URI=uri,
        SECURE_SMTP_MONGO_USER="",
        SECURE_SMTP_MONGO_PASSWORD="",
        SECURE_SMTP_MONGO_DB="rehearsal",
        SECURE_SMTP_REPORTS_DIR=str(root / "reports"),
        SECURE_SMTP_UPLOAD_DIR=str(root / "uploads"),
        SECURE_SMTP_ENABLE_LIVE_LAB="false",
        SECURE_SMTP_PILOT_ORG_ID="org_rehearsal",
        SECURE_SMTP_CLERK_ISSUER="https://identity.invalid",
        SECURE_SMTP_CLERK_AUTHORIZED_PARTIES='["https://pilot.invalid"]',
        SECURE_SMTP_NEO4J_URI="",
        SECURE_SMTP_ALERTS_ENABLED="true",
        SECURE_SMTP_ALERT_WEBHOOK_URL=webhook,
        SECURE_SMTP_ALERT_WEBHOOK_SECRET="fixture",
        SECURE_SMTP_ALERT_MIN_SEVERITY="HIGH",
    )
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    from fastapi.testclient import TestClient

    from secure_smtp.api.main import app

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwks = SimpleNamespace(
        get_signing_key_from_jwt=lambda token: SimpleNamespace(key=key.public_key())
    )

    def headers(role):
        now = int(time.time())
        token = jwt.encode(
            dict(
                iss="https://identity.invalid",
                sub="operator",
                sid="test",
                azp="https://pilot.invalid",
                iat=now,
                nbf=now,
                exp=now + 300,
                org_id="org_rehearsal",
                org_role=role,
            ),
            key,
            algorithm="RS256",
        )
        return {"Authorization": "Bearer " + token}

    with patch("secure_smtp.api.auth.jwks_client", return_value=jwks):
        with TestClient(app, base_url="https://pilot.invalid") as client:
            assert client.get("/api/identity").status_code == 401
            admin, analyst = headers("org:admin"), headers("org:member")
            assert client.get("/api/identity", headers=admin).json()["role"] == "admin"
            assert (
                client.post("/api/agents", headers=analyst, json={"name": "sensor"}).status_code
                == 403
            )
            provision = client.post("/api/agents", headers=admin, json={"name": "sensor"})
            provision.raise_for_status()
            agent = {"Authorization": "Bearer " + provision.json()["credential"]}
            client.post(
                "/api/agents/heartbeat", headers=agent, json={"capture_active": True}
            ).raise_for_status()
            batch = {
                "batch_id": str(uuid4()),
                "observations": [
                    dict(
                        event_id=str(uuid4()),
                        observed_at=datetime.now(UTC).isoformat(),
                        src_ip="192.0.2.2",
                        dst_ip="192.0.2.1",
                        src_port=44000,
                        dst_port=25,
                        protocol="smtp",
                        tls_mode="none",
                        capture_complete=True,
                    )
                ],
            }
            result = client.post("/api/agents/ingest", headers=agent, json=batch)
            result.raise_for_status()
            agent_job = result.json()["job_id"]
            assert client.post("/api/agents/ingest", headers=agent, json=batch).json()["duplicate"]
            assert len(client.get("/api/sessions", headers=analyst).json()) == 1
            capture = ROOT / "tests/fixtures/pcaps/smtp_plaintext.pcap"
            with capture.open("rb") as stream:
                upload = client.post(
                    "/api/analyze", headers=analyst, files={"file": (capture.name, stream)}
                )
            upload.raise_for_status()
            job = upload.json()["job_id"]
            assert (
                client.get(f"/api/analyze/{job}/status", headers=analyst).json()["status"] == "done"
            )
            pdf = client.get(f"/api/reports/{job}.pdf", headers=analyst)
            pdf.raise_for_status()
            assert pdf.content.startswith(b"%PDF")
            assert (
                client.get(f"/api/reports/{agent_job}.json", headers=analyst).json()["summary"][
                    "total_sessions"
                ]
                == 1
            )
            assert client.get("/api/operations", headers=admin).json()["alerts"]
        archive = root / "backup.archive"
        subprocess.run(
            [
                "mongodump",
                "--quiet",
                "--uri",
                uri,
                "--db",
                "rehearsal",
                "--archive=" + str(archive),
            ],
            check=True,
        )
        shutil.copytree(root / "reports", root / "backup_reports")
        subprocess.run(
            [
                "mongorestore",
                "--quiet",
                "--uri",
                uri,
                "--archive=" + str(archive),
                "--nsFrom=rehearsal.*",
                "--nsTo=recovered.*",
            ],
            check=True,
        )
        for collection in mongo.rehearsal.list_collection_names():
            assert mongo.rehearsal[collection].count_documents({}) == mongo.recovered[
                collection
            ].count_documents({})
        assert mongo.recovered.analysis_jobs.find_one({"job_id": job, "status": "done"})
        assert pdf.content == (root / "backup_reports" / job / "report.pdf").read_bytes()
        with TestClient(app, base_url="https://pilot.invalid") as client:
            assert client.get(f"/api/reports/{job}.pdf", headers=analyst).content == pdf.content
            client.delete(f"/api/assessments/{agent_job}", headers=admin).raise_for_status()
            assert client.get(f"/api/reports/{agent_job}.json", headers=analyst).status_code == 404
            assert client.post("/api/agents/ingest", headers=agent, json=batch).status_code == 410


if __name__ == "__main__":
    deliveries = []

    class Receiver(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            signature = "sha256=" + hmac.new(b"fixture", body, hashlib.sha256).hexdigest()
            if hmac.compare_digest(signature, self.headers.get("X-SecureSMTP-Signature", "")):
                deliveries.append(json.loads(body))
                self.send_response(204)
            else:
                self.send_response(403)
            self.end_headers()

        def log_message(self, *args):
            pass

    with tempfile.TemporaryDirectory() as path, HTTPServer(("127.0.0.1", 0), Receiver) as receiver:
        threading.Thread(target=receiver.serve_forever, daemon=True).start()
        with disposable_mongo(Path(path)) as (uri, mongo):
            rehearse(Path(path), uri, mongo, f"http://127.0.0.1:{receiver.server_port}/notify")
        receiver.shutdown()
        assert deliveries
    print(
        "Passed pilot API journey, signed local webhook, restart and independent database restore."
    )
