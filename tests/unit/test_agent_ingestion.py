"""Adversarial agent boundaries using an isolated Mongo-compatible store, no network."""
from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import mongomock
import pytest
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.testclient import TestClient
from pydantic import ValidationError

from secure_smtp.api import pipeline
from secure_smtp.api.auth import Principal, http_bearer, verify_api_key
from secure_smtp.api.routers import agents
from secure_smtp.monitoring import service
from secure_smtp.monitoring.schema import ObservationBatch


@pytest.fixture
def environment(monkeypatch):
    database = mongomock.MongoClient(tz_aware=True).pilot_test
    database.agents.create_index('agent_id', unique=True)
    database.analysis_jobs.create_index('job_id', unique=True)
    database.hosts.create_index([('org_id', 1), ('ip_or_hostname', 1)], unique=True)
    database.sessions.create_index([('agent_id', 1), ('event_id', 1)], unique=True,
                                   partialFilterExpression={'event_id': {'$type': 'string'}})
    database.event_tombstones.create_index([('agent_id', 1), ('event_id', 1)], unique=True)
    settings = SimpleNamespace(pilot_org_id='org_pilot', retention_days=30,
                               agent_allow_insecure_local=False, agent_offline_seconds=90)
    monkeypatch.setattr(service, 'get_database', lambda: database)
    monkeypatch.setattr(agents, 'get_database', lambda: database)
    monkeypatch.setattr(service, 'get_settings', lambda: settings)
    monkeypatch.setattr(agents, 'get_settings', lambda: settings)
    counters = {}

    def sequence(name):
        counters[name] = counters.get(name, 0) + 1
        return counters[name]

    monkeypatch.setattr(service, 'get_next_sequence', sequence)
    generate = Mock()
    monkeypatch.setattr(pipeline, 'generate_job_reports', generate)
    from secure_smtp.operations import integrations
    monkeypatch.setattr(integrations, 'run_integrations', Mock())
    app = FastAPI()
    app.include_router(agents.router)
    context = SimpleNamespace(db=database, settings=settings, reports=generate, app=app,
                              principal=Principal('admin', 'org_pilot', 'admin', 4102444800))

    async def user_identity(credentials: HTTPAuthorizationCredentials | None = Depends(http_bearer)):
        # JWT verification is covered by test_auth; this route fixture admits one user session.
        if credentials is None or credentials.credentials != 'verified-user-session':
            raise HTTPException(401, 'Sign in required')
        return context.principal

    app.dependency_overrides[verify_api_key] = user_identity
    context.client = TestClient(app, base_url='https://pilot.example.test')
    context.http = TestClient(app, base_url='http://pilot.example.test')
    return context


def observation(**updates):
    payload = {
        'event_id': str(uuid4()), 'observed_at': datetime.now(UTC).isoformat(),
        'src_ip': '192.0.2.1', 'dst_ip': '192.0.2.2', 'src_port': 40000, 'dst_port': 25,
        'protocol': 'smtp', 'tls_mode': 'none', 'capture_complete': True,
    }
    return {**payload, **updates}


def batch(*records, **updates):
    return {'batch_id': str(uuid4()), 'observations': list(records) or [observation()], **updates}


def user_headers():
    return {'Authorization': 'Bearer verified-user-session'}


def provision(environment, name='Mail server'):
    response = environment.client.post('/api/agents', json={'name': name}, headers=user_headers())
    assert response.status_code == 201
    data = response.json()
    return data, {'Authorization': f'Bearer {data["credential"]}'}


def test_agent_credential_is_unique_and_only_hash_is_persisted(environment):
    first, _ = provision(environment)
    second, _ = provision(environment)
    assert first['credential'] != second['credential']
    secret = first['credential'].split('.', 1)[1]
    record = environment.db.agents.find_one({'agent_id': first['agent_id']})
    assert record['secret_hash'] == hashlib.sha256(secret.encode()).hexdigest()
    assert secret not in repr(list(environment.db.agents.find()))
    assert first['credential'] not in repr(list(environment.db.audit.find()))
    listing = environment.client.get('/api/agents', headers=user_headers())
    assert listing.status_code == 200
    assert all('secret_hash' not in item and 'credential' not in item for item in listing.json())
    assert {item['status'] for item in listing.json()} == {'offline'}


def test_heartbeat_updates_health_and_revocation_immediately_denies_ingestion(environment):
    created, headers = provision(environment)
    assert environment.client.post('/api/agents/heartbeat', json={'capture_active': True}, headers=headers).status_code == 200
    record = environment.db.agents.find_one({'agent_id': created['agent_id']})
    assert record['last_seen'] is not None
    listing = environment.client.get('/api/agents', headers=user_headers()).json()
    assert listing[0]['status'] == 'online'
    assert environment.client.post(f'/api/agents/{created["agent_id"]}/revoke', headers=user_headers()).status_code == 200
    assert environment.client.post('/api/agents/heartbeat', json={}, headers=headers).status_code == 401
    assert environment.client.post('/api/agents/ingest', json=batch(), headers=headers).status_code == 401
    assert environment.db.sessions.count_documents({}) == 0


def test_wrong_org_agents_are_hidden_and_rejected(environment):
    created, headers = provision(environment)
    environment.db.agents.update_one({'agent_id': created['agent_id']}, {'$set': {'org_id': 'org_other'}})
    assert environment.client.get('/api/agents', headers=user_headers()).json() == []
    assert environment.client.post(f'/api/agents/{created["agent_id"]}/revoke', headers=user_headers()).status_code == 404
    assert environment.client.post('/api/agents/heartbeat', json={}, headers=headers).status_code == 403
    assert environment.client.post('/api/agents/ingest', json=batch(), headers=headers).status_code == 403
    assert environment.db.agents.find_one()['revoked'] is False


def test_analyst_cannot_provision_or_revoke_agents(environment):
    created, _ = provision(environment)
    environment.principal = Principal('analyst', 'org_pilot', 'member', 4102444800)
    assert environment.client.post('/api/agents', json={'name': 'New'}, headers=user_headers()).status_code == 403
    assert environment.client.post(f'/api/agents/{created["agent_id"]}/revoke', headers=user_headers()).status_code == 403
    assert environment.db.agents.find_one()['revoked'] is False


def test_user_and_agent_credentials_are_not_interchangeable(environment):
    _, agent_headers = provision(environment)
    assert environment.client.post('/api/agents/heartbeat', json={}, headers=user_headers()).status_code == 401
    assert environment.client.post('/api/agents/ingest', json=batch(), headers=user_headers()).status_code == 401
    assert environment.client.get('/api/agents', headers=agent_headers).status_code == 401
    assert environment.client.post('/api/agents', json={'name': 'Escalation'}, headers=agent_headers).status_code == 401


@pytest.mark.parametrize('token', ['', 'invalid', 'sa_bad.secret', 'sa_' + str(uuid4()) + '.secret', 'Bearer.jwt.session'])
def test_invalid_agent_credentials_fail_closed(environment, token):
    response = environment.client.post('/api/agents/heartbeat', json={}, headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 401
    assert environment.db.agents.count_documents({}) == 0


def test_tls_is_required_and_forwarded_header_cannot_bypass_it(environment):
    _, headers = provision(environment)
    assert environment.http.post('/api/agents/heartbeat', json={}, headers=headers).status_code == 403
    assert environment.http.post('/api/agents/ingest', json=batch(), headers={**headers, 'X-Forwarded-Proto': 'https'}).status_code == 403
    assert environment.client.post('/api/agents/heartbeat', json={}, headers=headers).status_code == 200


@pytest.mark.parametrize('field,value', [('body', 'private message'), ('sender', 'person@example.test'), ('org_id', 'org_other'), ('risk_score', 0), ('raw_payload', 'base64')])
def test_telemetry_rejects_unapproved_payload_and_identity_fields(environment, field, value):
    _, headers = provision(environment)
    response = environment.client.post('/api/agents/ingest', json=batch(observation(**{field: value})), headers=headers)
    assert response.status_code == 422
    assert environment.db.sessions.count_documents({}) == 0


@pytest.mark.parametrize('validity', [True, False])
def test_collector_cannot_claim_certificate_trust_validity(environment, validity):
    _, headers = provision(environment)
    data = observation(tls_mode='implicit', certificates=[{'chain_position': 0, 'chain_valid': validity}])
    assert environment.client.post('/api/agents/ingest', json=batch(data), headers=headers).status_code == 422


@pytest.mark.parametrize('updates', [
    {'tls_mode': 'none', 'handshake': {'tls_version_negotiated': 'TLS1.3'}},
    {'tls_mode': 'unknown', 'starttls_completed': True},
    {'tls_mode': 'implicit', 'starttls_completed': True},
    {'src_ip': 'not-an-ip'}, {'dst_port': 65536},
    {'observed_at': '2026-01-01T00:00:00'},
    {'observed_at': (datetime.now(UTC) + timedelta(hours=1)).isoformat()},
])
def test_inconsistent_or_unbounded_observation_rejected(updates):
    with pytest.raises(ValidationError):
        ObservationBatch.model_validate(batch(observation(**updates)))


def test_batch_enforces_unique_events_and_bounded_count():
    same = observation()
    for payload in [batch(same, same), batch(observations=[]), batch(*[observation() for _ in range(26)])]:
        with pytest.raises(ValidationError):
            ObservationBatch.model_validate(payload)


def test_batch_retries_do_not_duplicate_sessions_jobs_or_reports(environment):
    created, headers = provision(environment)
    payload = batch(observation(), observation(dst_ip='192.0.2.3'))
    first = environment.client.post('/api/agents/ingest', json=payload, headers=headers)
    assert first.status_code == 200
    assert first.json()['duplicate'] is False
    second = environment.client.post('/api/agents/ingest', json=payload, headers=headers)
    assert second.status_code == 200
    assert second.json()['duplicate'] is True
    assert first.json()['job_id'] == second.json()['job_id']
    assert environment.db.sessions.count_documents({}) == 2
    assert environment.db.analysis_jobs.count_documents({}) == 1
    assert environment.reports.call_count == 1
    for session in environment.db.sessions.find():
        assert session['org_id'] == 'org_pilot'
        assert session['owner_id'] == created['agent_id']
        assert session['job_id'] == first.json()['job_id']
        assert session['source_kind'] == 'passive_agent'


def test_same_event_across_different_batches_is_not_inserted_twice(environment):
    _, headers = provision(environment)
    event = observation()
    first = environment.client.post('/api/agents/ingest', json=batch(event), headers=headers).json()
    second = environment.client.post('/api/agents/ingest', json=batch(event), headers=headers)
    assert second.status_code == 200
    assert environment.db.sessions.count_documents({}) == 1
    assert environment.db.sessions.find_one()['job_id'] == first['job_id']
    assert environment.db.hosts.find_one()['session_count'] == 1


def test_reusing_batch_id_with_changed_content_is_a_conflict(environment):
    _, headers = provision(environment)
    payload = batch()
    assert environment.client.post('/api/agents/ingest', json=payload, headers=headers).status_code == 200
    payload['observations'][0]['src_port'] += 1
    assert environment.client.post('/api/agents/ingest', json=payload, headers=headers).status_code == 409
    assert environment.db.sessions.count_documents({}) == 1
    assert environment.reports.call_count == 1


def test_reusing_event_id_with_changed_content_is_a_conflict(environment):
    _, headers = provision(environment)
    event = observation()
    assert environment.client.post('/api/agents/ingest', json=batch(event), headers=headers).status_code == 200
    changed = {**event, 'src_port': event['src_port'] + 1}
    assert environment.client.post('/api/agents/ingest', json=batch(changed), headers=headers).status_code == 409
    assert environment.db.sessions.count_documents({}) == 1
    assert environment.db.sessions.find_one()['src_port'] == event['src_port']


def test_report_failure_is_retryable_without_duplicate_events(environment):
    _, headers = provision(environment)
    payload = batch()
    environment.reports.side_effect = [RuntimeError('private error details'), None]
    failure = environment.client.post('/api/agents/ingest', json=payload, headers=headers)
    assert failure.status_code == 503
    assert 'private error details' not in failure.text
    assert environment.db.analysis_jobs.find_one()['status'] == 'failed'
    assert environment.db.agents.find_one()['last_error'] == 'ingestion_failed'
    retry = environment.client.post('/api/agents/ingest', json=payload, headers=headers)
    assert retry.status_code == 200
    assert environment.db.sessions.count_documents({}) == 1
    assert environment.db.analysis_jobs.find_one()['status'] == 'done'
    assert environment.db.agents.find_one()['last_error'] is None


def test_retention_and_deleted_assessments_cannot_be_replayed(environment):
    _, headers = provision(environment)
    too_old = observation(observed_at=(datetime.now(UTC) - timedelta(days=31)).isoformat())
    assert environment.client.post('/api/agents/ingest', json=batch(too_old), headers=headers).status_code == 422
    assert environment.db.sessions.count_documents({}) == 0
    payload = batch()
    result = environment.client.post('/api/agents/ingest', json=payload, headers=headers).json()
    environment.db.analysis_jobs.update_one({'job_id': result['job_id']}, {'$set': {'status': 'deleted'}})
    assert environment.client.post('/api/agents/ingest', json=payload, headers=headers).status_code == 410


def test_event_tombstone_prevents_delayed_retry_recreating_evidence(environment):
    created, headers = provision(environment)
    event = observation()
    environment.db.event_tombstones.insert_one({'org_id': 'org_pilot', 'agent_id': created['agent_id'], 'event_id': event['event_id']})
    response = environment.client.post('/api/agents/ingest', json=batch(event), headers=headers)
    assert response.status_code == 200
    assert environment.db.sessions.count_documents({}) == 0


def test_revocation_is_rechecked_after_dependency_validation(environment):
    created, headers = provision(environment)
    agent = environment.db.agents.find_one({'agent_id': created['agent_id']})
    environment.app.dependency_overrides[agents.agent_identity] = lambda: agent
    environment.db.agents.update_one({'agent_id': created['agent_id']}, {'$set': {'revoked': True}})
    assert environment.client.post('/api/agents/ingest', json=batch(), headers=headers).status_code == 401
    assert environment.db.sessions.count_documents({}) == 0


def test_unobserved_tls_and_certificate_properties_remain_unknown(environment):
    _, headers = provision(environment)
    events = [observation(tls_mode='unknown'), observation(tls_mode='implicit', handshake={}, certificates=[{'chain_position': 0}])]
    response = environment.client.post('/api/agents/ingest', json=batch(*events), headers=headers)
    assert response.status_code == 200
    unknown = environment.db.sessions.find_one({'event_id': events[0]['event_id']})
    assert unknown['risk_score'] is None
    partial = environment.db.sessions.find_one({'event_id': events[1]['event_id']})
    assert partial['handshake']['forward_secrecy'] is None
    assert partial['certificates'][0]['chain_valid'] is None
    assert partial['certificates'][0]['self_signed'] is None


def test_extra_fields_are_rejected_at_batch_heartbeat_and_nested_levels(environment):
    _, headers = provision(environment)
    assert environment.client.post('/api/agents/heartbeat', json={'body': 'private'}, headers=headers).status_code == 422
    assert environment.client.post('/api/agents/ingest', json=batch(org_id='org_other'), headers=headers).status_code == 422
    nested = observation(tls_mode='implicit', handshake={'raw_payload': 'private'})
    assert environment.client.post('/api/agents/ingest', json=batch(nested), headers=headers).status_code == 422


def test_done_batch_retry_repairs_interrupted_publication(environment):
    _, headers = provision(environment)
    payload = batch()
    response = environment.client.post('/api/agents/ingest', headers=headers, json=payload)
    assert response.status_code == 200
    job_id = response.json()['job_id']
    environment.db.sessions.update_many({'job_id': job_id}, {'$set': {'published': False}})
    environment.db.hosts.update_many({}, {'$set': {'published': False, 'session_count': 0}})
    retry = environment.client.post('/api/agents/ingest', headers=headers, json=payload)
    assert retry.json()['duplicate']
    assert environment.db.sessions.count_documents({'published': True}) == 1
    assert environment.db.hosts.find_one()['session_count'] == 1
