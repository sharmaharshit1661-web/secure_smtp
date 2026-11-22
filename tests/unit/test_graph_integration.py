from types import SimpleNamespace
from unittest.mock import MagicMock

from secure_smtp.operations import integrations


def test_graph_sync_scopes_evidence_and_creates_unique_constraints(monkeypatch):
    import neo4j
    driver = MagicMock()
    factory = MagicMock()
    factory.return_value.__enter__.return_value = driver
    monkeypatch.setattr(neo4j.GraphDatabase, 'driver', factory)
    monkeypatch.setattr(integrations, 'get_settings', lambda: SimpleNamespace(
        neo4j_uri='bolt://graph:7687', neo4j_user='app', neo4j_password='fixture'))
    db = MagicMock()
    db.sessions.find.return_value = [{'id': 1, 'host_id': 2, 'dst_ip': '192.0.2.1',
                                     'findings': [{'rule_id': 'no-tls'}]}]
    monkeypatch.setattr(integrations, 'get_database', lambda: db)
    assert integrations.sync_graph('org_a', 'job_a') == {'status': 'synced', 'sessions': 1}
    db.sessions.find.assert_called_once_with({'org_id': 'org_a', 'job_id': 'job_a', 'published': {'$ne': False}})
    calls = driver.execute_query.call_args_list
    assert len(calls) == 4
    assert all('IS UNIQUE' in call.args[0] for call in calls[:3])
    assert calls[-1].kwargs['org'] == 'org_a'
    assert calls[-1].kwargs['job'] == 'job_a'
