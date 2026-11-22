"""Adversarial pilot boundaries, isolated from the developer database and network."""

import asyncio
import struct
import time
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from secure_smtp.api.auth import Principal, verify_api_key
from secure_smtp.api.routers import analysis, compliance, copilot, hosts, reports, sessions
from secure_smtp.ingest.validation import validate_capture

PILOT = Principal("analyst", "org_a", "member", int(time.time()) + 300)


class Cursor(list):
    def sort(self, *args, **kwargs):
        return self

    def limit(self, limit):
        return Cursor(self[:limit])


class Collection:
    def __init__(self, records=()):
        self.records = list(records)

    def find(self, query=None, *args, **kwargs):
        return Cursor(
            dict(r)
            for r in self.records
            if all(
                (r.get(k) != v["$ne"] if isinstance(v, dict) and "$ne" in v else r.get(k) == v)
                for k, v in (query or {}).items()
            )
        )

    def find_one(self, query=None, *args, **kwargs):
        return next(iter(self.find(query)), None)

    def insert_one(self, record):
        self.records.append(record)

    def update_one(self, *args, **kwargs):
        pass


@pytest.fixture
def client(monkeypatch):
    app = FastAPI()
    for module in [hosts, sessions, analysis, reports, compliance, copilot]:
        app.include_router(module.router)
    app.dependency_overrides[verify_api_key] = lambda: PILOT
    records = Collection(
        [
            {
                "id": 1,
                "org_id": "org_a",
                "ip_or_hostname": "a.test",
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "src_port": 50000,
                "dst_port": 25,
            },
            {"id": 2, "org_id": "org_b", "ip_or_hostname": "b.test"},
            {"id": 3, "ip_or_hostname": "legacy.test"},
        ]
    )
    for module in [hosts, sessions, compliance]:
        monkeypatch.setattr(module, "get_sessions_col", lambda: records)
    monkeypatch.setattr(hosts, "get_hosts_col", lambda: records)
    monkeypatch.setattr(copilot, "_get_sessions_col", lambda: records)
    return TestClient(app)


def test_lists_exclude_foreign_and_unowned_records(client):
    assert [r["host_id"] for r in client.get("/api/hosts").json()] == [1]
    assert [r["id"] for r in client.get("/api/sessions").json()] == [1]
    assert client.get("/api/sessions?limit=0").status_code == 422


@pytest.mark.parametrize("record_id", [2, 3])
@pytest.mark.parametrize(
    "path",
    [
        "/api/hosts/{}",
        "/api/sessions/{}",
        "/api/sessions/{}/explain",
        "/api/sessions/{}/compliance",
    ],
)
def test_foreign_and_legacy_details_hidden(client, path, record_id):
    assert client.get(path.format(record_id)).status_code == 404


def test_explicit_unauthorized_copilot_context_never_falls_back(client):
    assert (
        client.post("/api/ai/copilot/ask", json={"session_id": 2, "query": "Summarize"}).status_code
        == 404
    )


def test_report_requires_owned_completed_job_even_when_file_exists(client, monkeypatch, tmp_path):
    ids = [str(uuid4()) for _ in range(3)]
    jobs = Collection(
        [
            {"job_id": ids[0], "org_id": "org_a", "status": "done"},
            {"job_id": ids[1], "org_id": "org_b", "status": "done"},
            {"job_id": ids[2], "org_id": "org_a", "status": "failed"},
        ]
    )
    monkeypatch.setattr(reports, "get_jobs_col", lambda: jobs)
    monkeypatch.setattr(reports, "get_settings", lambda: SimpleNamespace(reports_dir=tmp_path))
    for job in ids:
        directory = tmp_path / job
        directory.mkdir()
        (directory / "report.json").write_text("{}")
    assert client.get(f"/api/reports/{ids[0]}.json").status_code == 200
    for job in ids[1:]:
        assert client.get(f"/api/reports/{job}.json").status_code == 404
    assert client.get("/api/reports/not-a-uuid.json").status_code == 422


def capture(payload=b"test"):
    return (
        b"\xd4\xc3\xb2\xa1"
        + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
        + struct.pack("<IIII", 0, 0, len(payload), len(payload))
        + payload
    )


@pytest.mark.parametrize(
    "data",
    [b"", b"not a capture", capture()[:-1], capture()[:24], b"\x0a\x0d\x0d\x0a" + b"\0" * 24],
)
def test_corrupt_capture_rejected(tmp_path, data):
    path = tmp_path / "bad.pcap"
    path.write_bytes(data)
    with pytest.raises(ValueError):
        validate_capture(path)


def test_packet_limit(tmp_path):
    path = tmp_path / "large.pcap"
    path.write_bytes(capture() + capture()[24:])
    with pytest.raises(ValueError, match="limit"):
        validate_capture(path, max_packets=1)


def test_tcp_sequence_gap_is_bounded_before_allocation():
    from secure_smtp.ingest.pcap_reader import RawPacket
    from secure_smtp.ingest.tcp_stream import _reassemble_direction

    packets = [RawPacket("a", "b", 50000, 25, seq, 0, "P", b"x", 0) for seq in [1, 2**32 - 1]]
    with pytest.raises(ValueError, match="8 MiB"):
        _reassemble_direction(packets)


def test_upload_limits_and_slot_cleanup(client, monkeypatch, tmp_path):
    monkeypatch.setattr(
        analysis,
        "get_settings",
        lambda: SimpleNamespace(upload_dir=tmp_path, max_upload_bytes=50, max_capture_packets=10),
    )
    response = client.post("/api/analyze", files={"file": ("bad.pcap", b"wrong")})
    assert response.status_code == 400
    assert not analysis._slot.locked()
    response = client.post("/api/analyze", files={"file": ("big.pcap", b"x" * 60)})
    assert response.status_code == 413
    assert not list(tmp_path.iterdir())
    assert not analysis._slot.locked()
    analysis._slot.acquire()
    try:
        assert (
            client.post("/api/analyze", files={"file": ("busy.pcap", capture())}).status_code == 429
        )
    finally:
        analysis._slot.release()


def test_reports_only_include_current_job_and_recompute_host_counts(monkeypatch, tmp_path):
    from secure_smtp.api import pipeline

    jobs = Collection([{"job_id": "a", "org_id": "org_a"}])
    records = Collection(
        [
            {"id": 1, "job_id": "a", "org_id": "org_a", "host_id": 1},
            {"id": 2, "job_id": "b", "org_id": "org_a", "host_id": 1},
            {"id": 3, "job_id": "a", "org_id": "org_b", "host_id": 2},
        ]
    )
    monkeypatch.setattr(pipeline, "get_jobs_col", lambda: jobs)
    monkeypatch.setattr(pipeline, "get_sessions_col", lambda: records)
    monkeypatch.setattr(
        pipeline,
        "get_hosts_col",
        lambda: Collection([{"id": 1, "org_id": "org_a", "session_count": 99}]),
    )
    monkeypatch.setattr(pipeline, "get_settings", lambda: SimpleNamespace(reports_dir=tmp_path))
    result = []
    monkeypatch.setattr(
        "secure_smtp.reporting.json_export.generate_json_report",
        lambda data, path: result.append(data),
    )
    monkeypatch.setattr("secure_smtp.reporting.html_export.generate_html_report", lambda *a: None)
    monkeypatch.setattr(
        "secure_smtp.reporting.pdf_export.generate_pdf_report", lambda *a, **kw: None
    )
    pipeline.generate_job_reports("a")
    assert [s["id"] for s in result[0]["sessions"]] == [1]
    assert result[0]["hosts"][0]["session_count"] == 1


def test_report_html_escapes_untrusted_fields(tmp_path):
    from secure_smtp.api.pipeline import build_report_data
    from secure_smtp.reporting.html_export import generate_html_report

    data = build_report_data([{"ip_or_hostname": '<img src="https://internal/">'}], [])
    path = tmp_path / "report.html"
    generate_html_report(data, str(path))
    html = path.read_text()
    assert '<img src="https://internal/">' not in html
    assert "&lt;img" in html


def test_broker_never_broadcasts_unowned_or_foreign_events():
    from unittest.mock import AsyncMock

    from secure_smtp.api.broker import ConnectionManager

    async def exercise():
        manager = ConnectionManager()
        socket = Mock(accept=AsyncMock(), send_json=AsyncMock())
        await manager.connect(socket, PILOT)
        await manager.broadcast({"org_id": "org_b"})
        await manager.broadcast({"event": "unowned"})
        socket.send_json.assert_not_called()
        await manager.broadcast({"org_id": "org_a"})
        socket.send_json.assert_called_once()

    asyncio.run(exercise())


def test_analysis_deadline_marks_failure_and_releases_slot(monkeypatch, tmp_path):
    import subprocess

    path = tmp_path / "capture.pcap"
    path.write_bytes(capture())
    jobs = Mock()
    monkeypatch.setattr(analysis, "get_jobs_col", lambda: jobs)
    monkeypatch.setattr(
        analysis, "get_settings", lambda: SimpleNamespace(analysis_timeout_seconds=1)
    )
    monkeypatch.setattr(
        analysis.subprocess, "run", Mock(side_effect=subprocess.TimeoutExpired("worker", 1))
    )
    analysis._slot.acquire()
    analysis.process_job("job-a", str(path))
    assert not path.exists()
    assert not analysis._slot.locked()
    assert jobs.update_one.call_args.args[1]["$set"]["status"] == "failed"


def test_raw_request_limit_runs_before_multipart_spooling(monkeypatch):
    from secure_smtp.api import main

    app = FastAPI()
    app.include_router(analysis.router)
    app.add_middleware(main.UploadBodyLimit)
    app.dependency_overrides[verify_api_key] = lambda: PILOT
    monkeypatch.setattr(main, "get_settings", lambda: SimpleNamespace(max_upload_bytes=10))
    response = TestClient(app).post("/api/analyze", files={"file": ("huge.pcap", b"x" * 70000)})
    assert response.status_code == 413


@pytest.mark.parametrize("path", ["/api/ai/copilot/ask", "/api/sessions/1/copilot/ask"])
def test_json_request_size_limit_and_copilot_query_validation(client, path):
    from secure_smtp.api.main import UploadBodyLimit

    client.app.add_middleware(UploadBodyLimit)
    assert client.post(path, json={"query": "x" * 524288}).status_code == 413
    assert client.post(path, json={"query": "x" * 4001}).status_code == 422
    assert client.post(path, json={"query": ""}).status_code == 422


def test_request_limit_counts_chunked_body_before_handler_runs():
    from fastapi import Request

    from secure_smtp.api.main import UploadBodyLimit

    app = FastAPI()
    completed = []

    @app.post("/api/test-body")
    async def consume(request: Request):
        await request.body()
        completed.append(True)
        return {}

    app.add_middleware(UploadBodyLimit)

    async def exercise():
        chunks = iter([b"x" * 300000, b"x" * 300000])
        output = []

        async def receive():
            return {"type": "http.request", "body": next(chunks), "more_body": True}

        async def send(message):
            output.append(message)

        await app(
            {
                "type": "http",
                "method": "POST",
                "path": "/api/test-body",
                "headers": [],
                "query_string": b"",
            },
            receive,
            send,
        )
        assert output[0]["status"] == 413
        assert not completed

    asyncio.run(exercise())
