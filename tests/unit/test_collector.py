"""Offline collector invariants: durable delivery, bounded memory and metadata only."""
from __future__ import annotations

import json
import stat
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import httpx
import pytest

from secure_smtp.agent import observe, runner
from secure_smtp.agent.outbox import Outbox
from secure_smtp.db.models import KeyExchangeType
from secure_smtp.ingest.pcap_reader import PacketStream, RawPacket, StreamKey
from secure_smtp.monitoring.schema import Observation


def observation(**changes):
    return Observation.model_validate({
        'event_id': str(uuid4()), 'observed_at': datetime.now(UTC),
        'src_ip': '192.0.2.1', 'dst_ip': '192.0.2.2', 'src_port': 40000,
        'dst_port': 25, 'protocol': 'smtp', 'tls_mode': 'none', **changes,
    })


@pytest.fixture
def queue(tmp_path):
    box = Outbox(tmp_path / 'state' / 'outbox.sqlite')
    yield box
    box.close()


def test_restart_preserves_batch_identity_payload_counters_and_permissions(tmp_path):
    path = tmp_path / 'state' / 'outbox.sqlite'
    first = Outbox(path)
    assert first.enqueue([observation()])
    first.increment('capture_errors')
    original = first.oldest()
    first.close()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    second = Outbox(path)
    try:
        assert second.oldest() == original
        assert second.health()['capture_errors'] == 1
        second.acknowledge('unknown-batch')
        assert second.oldest() == original
        second.acknowledge(original[0])
    finally:
        second.close()
    third = Outbox(path)
    try:
        assert third.oldest() is None
        assert third.health()['queued_events'] == 0
    finally:
        third.close()


def test_capacity_rejects_newest_without_evicting_unacknowledged_data(tmp_path):
    box = Outbox(tmp_path / 'queue.sqlite', max_batches=1)
    try:
        assert box.enqueue([observation(), observation()])
        original = box.oldest()
        assert box.enqueue([observation(), observation(), observation()]) is False
        assert box.oldest() == original
        assert box.health()['dropped_events'] == 3
        assert box.health()['queued_events'] == 2
    finally:
        box.close()


def test_queue_byte_bound_counts_utf8_bytes_of_existing_records(tmp_path):
    box = Outbox(tmp_path / 'queue.sqlite')
    event = observation(tls_mode='implicit', handshake={'cipher_suite_negotiated': 'é' * 160})
    try:
        assert box.enqueue([event])
        encoded = box.oldest()[1]
        box.max_bytes = 2 * len(encoded.encode('utf-8')) - 1
        assert box.enqueue([event]) is False
        assert box.health()['dropped_events'] == 1
        assert box.oldest()[1] == encoded
    finally:
        box.close()


def test_single_oversized_batch_is_rejected_without_persisting_it(tmp_path):
    box = Outbox(tmp_path / 'queue.sqlite', max_bytes=1)
    try:
        assert box.enqueue([observation()]) is False
        assert box.oldest() is None
        assert box.health()['dropped_events'] == 1
    finally:
        box.close()


@pytest.mark.parametrize('status,payload', [
    (200, {'status': 'running'}), (202, {'status': 'queued'}),
    (401, {}), (403, {}), (429, {}), (500, {}), (503, {}),
])
def test_retryable_or_unacknowledged_responses_preserve_batch(queue, status, payload):
    queue.enqueue([observation()])
    original = queue.oldest()
    client = Mock()
    client.post.return_value = httpx.Response(status, json=payload)
    assert runner.deliver(client, 'https://pilot.example.test', 'sa_test.secret', queue) is False
    assert queue.oldest() == original


def test_retry_uses_identical_event_and_batch_ids_then_acknowledges_only_oldest(queue):
    queue.enqueue([observation()])
    oldest = queue.oldest()
    queue.enqueue([observation()])
    client = Mock()
    client.post.side_effect = [httpx.Response(503), httpx.Response(200, json={'status': 'done'})]
    assert runner.deliver(client, 'https://pilot.example.test', 'sa_test.secret', queue) is False
    assert runner.deliver(client, 'https://pilot.example.test', 'sa_test.secret', queue) is True
    calls = client.post.call_args_list
    assert calls[0] == calls[1]
    assert calls[0].kwargs['content'] == oldest[1]
    assert calls[0].kwargs['headers']['Authorization'] == 'Bearer sa_test.secret'
    assert queue.oldest()[0] != oldest[0]
    assert queue.health()['queued_events'] == 1


def test_lost_response_keeps_batch_available_after_network_exception(queue):
    queue.enqueue([observation()])
    original = queue.oldest()
    client = Mock()
    client.post.side_effect = httpx.ReadTimeout('response lost')
    with pytest.raises(httpx.ReadTimeout):
        runner.deliver(client, 'https://pilot.example.test', 'sa_test.secret', queue)
    assert queue.oldest() == original


def test_invalid_success_json_does_not_remove_evidence(queue):
    queue.enqueue([observation()])
    original = queue.oldest()
    client = Mock()
    client.post.return_value = httpx.Response(200, content=b'not-json')
    with pytest.raises(ValueError):
        runner.deliver(client, 'https://pilot.example.test', 'sa_test.secret', queue)
    assert queue.oldest() == original


@pytest.mark.parametrize('status', [410, 422])
def test_permanent_rejection_records_every_dropped_event(queue, status):
    queue.enqueue([observation(), observation(), observation()])
    client = Mock()
    client.post.return_value = httpx.Response(status)
    assert runner.deliver(client, 'https://pilot.example.test', 'sa_test.secret', queue)
    assert queue.oldest() is None
    assert queue.health()['dropped_events'] == 3


def test_processing_conflict_must_not_drop_retryable_batch(queue):
    queue.enqueue([observation()])
    original = queue.oldest()
    client = Mock()
    client.post.return_value = httpx.Response(409, json={'detail': 'Assessment is already processing or deleting'})
    assert runner.deliver(client, 'https://pilot.example.test', 'sa_test.secret', queue) is False
    assert queue.oldest() == original


def packet(payload=b'', *, reverse=False, flags='PA', seq=1, port=25):
    src, dst, sport, dport = '192.0.2.1', '192.0.2.2', 40000, port
    if reverse:
        src, dst, sport, dport = dst, src, dport, sport
    return RawPacket(src, dst, sport, dport, seq, 0, flags, payload, datetime.now(UTC).timestamp())


def stream(*packets):
    return PacketStream(StreamKey.from_packet(packets[0]), list(packets))


def test_plain_mail_observation_excludes_bodies_addresses_credentials_and_banner(queue):
    private = [b'body-secret-6c52', b'sender-secret@example.test', b'recipient-secret@example.test', b'auth-secret-28ca']
    mail = stream(packet(flags='S'),
        packet(b'220 private-mail-host ESMTP\r\n', reverse=True),
        packet(b'EHLO private-client\r\nAUTH PLAIN ' + private[3] + b'\r\nMAIL FROM:<' + private[1] +
               b'>\r\nRCPT TO:<' + private[2] + b'>\r\nDATA\r\nSubject: classified\r\n\r\n' + private[0] + b'\r\n.\r\n'))
    result = observe.observe_stream(mail, complete=True)
    assert result.protocol == 'smtp'
    assert result.tls_mode == 'none'
    assert result.capture_complete is True
    assert queue.enqueue([result])
    encoded = queue.oldest()[1]
    for secret in private + [b'private-mail-host', b'private-client', b'classified']:
        assert secret.decode() not in encoded
    assert set(json.loads(encoded)['observations'][0]) == {
        'event_id', 'observed_at', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
        'protocol', 'tls_mode', 'starttls_advertised', 'starttls_completed',
        'capture_complete', 'handshake', 'certificates',
    }


def test_partial_implicit_tls_has_unknown_forward_secrecy_and_unobserved_certificate():
    # Only a TLS record prefix is present; no ServerHello or certificate is observable.
    captured = stream(packet(flags='S', port=465), packet(b'\x16\x03\x03\x00\x04\x01\x00\x00\x00', port=465))
    result = observe.observe_stream(captured)
    assert result.tls_mode == 'implicit'
    assert result.handshake.forward_secrecy is None
    assert result.handshake.tls_version_negotiated == ''
    assert result.certificates == []
    assert result.capture_complete is False


def test_observer_discards_certificate_identity_and_never_asserts_trust(monkeypatch):
    captured = stream(packet(flags='S', port=465), packet(b'\x16\x03\x03\x00\x04\x01\x00\x00\x00', port=465))
    parsed = SimpleNamespace(client_hello=None, server_hello=object(), tls_version_negotiated='TLS1.2',
        cipher_suite_negotiated='TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', key_exchange_type=KeyExchangeType.ECDHE,
        forward_secrecy=True, visibility_limited=False, raw_certificates=[b'local-cert'])
    monkeypatch.setattr(observe, 'parse_handshake', lambda *args: parsed)
    monkeypatch.setattr(observe, 'compute_fingerprints', lambda *args: SimpleNamespace(ja3='', ja3s=''))
    cert = SimpleNamespace(chain_position=0, not_before=None, not_after=None, public_key_algorithm='RSA',
        key_length_bits=2048, signature_algorithm='sha256WithRSAEncryption', self_signed=False,
        subject='private-subject', issuer='private-issuer', san=['private-dns'], chain_valid=True)
    monkeypatch.setattr(observe, 'parse_certificate_chain', lambda *args: [cert])
    result = observe.observe_stream(captured)
    assert result.certificates[0].chain_valid is None
    assert all(secret not in result.model_dump_json() for secret in ('private-subject', 'private-issuer', 'private-dns'))


@pytest.fixture
def collector(monkeypatch, queue):
    monkeypatch.setattr(runner, '_extract_packet', lambda p, timestamp: p.raw)
    return runner.Collector(queue)


def receive(collector, raw):
    collector.receive(SimpleNamespace(raw=raw, time=raw.timestamp))


def test_non_mail_port_is_not_retained(collector):
    receive(collector, packet(b'not-mail', port=443))
    assert collector.flows == {}
    assert collector.bytes == 0


def test_collector_flush_releases_payload_and_marks_timeout_incomplete(collector, monkeypatch):
    observation_mock = Mock(return_value=observation())
    monkeypatch.setattr(runner, 'observe_stream', observation_mock)
    receive(collector, packet(b'private-local-body'))
    assert collector.bytes > 0
    collector.expire(all_flows=True)
    assert collector.flows == {}
    assert collector.bytes == 0
    assert observation_mock.call_args.args[1] is False
    assert 'private-local-body' not in collector.outbox.oldest()[1]


def test_collector_parser_error_discards_raw_data_and_records_failure(collector, monkeypatch):
    monkeypatch.setattr(runner, 'observe_stream', Mock(side_effect=ValueError('private payload')))
    receive(collector, packet(b'secret'))
    collector.expire(all_flows=True)
    assert collector.bytes == 0
    assert collector.flows == {}
    assert collector.outbox.oldest() is None
    assert collector.outbox.health()['capture_errors'] == 1


def test_per_flow_payload_limit_flushes_partial_evidence_without_overshoot(collector, monkeypatch):
    observed = Mock(return_value=observation())
    monkeypatch.setattr(runner, 'observe_stream', observed)
    receive(collector, packet(b'a' * (256 * 1024)))
    receive(collector, packet(b'b', seq=256 * 1024 + 1))
    assert collector.bytes == 0
    assert collector.flows == {}
    assert collector.outbox.health()['capture_errors'] == 1
    assert observed.call_args.args[1] is False
    assert sum(len(p.payload) for p in observed.call_args.args[0].packets) == 256 * 1024


def test_flow_count_bound_does_not_grow_on_new_connections(collector):
    for index in range(513):
        raw = packet(flags='S')
        raw.src_port = 40000 + index
        receive(collector, raw)
    assert len(collector.flows) == 512
    assert collector.outbox.health()['dropped_events'] == 1
