"""Organization operations, audit history, assessment lifecycle, and remediation evidence."""
from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from secure_smtp.api.auth import Principal, require_admin, scope, verify_api_key, visible_scope
from secure_smtp.config import get_settings
from secure_smtp.db.mongodb import get_database, serialize_doc
from secure_smtp.monitoring.service import audit
from secure_smtp.operations.integrations import graph_shared_weaknesses, run_integrations
from secure_smtp.operations.lifecycle import delete_assessment

router = APIRouter(prefix='/api', tags=['Operations'])


@router.get('/identity')
def identity(principal: Principal = Depends(verify_api_key)):
    return {'user_id': principal.user_id, 'org_id': principal.org_id, 'role': principal.role,
            'lab_enabled': get_settings().enable_live_lab, 'retention_days': get_settings().retention_days}


@router.get('/assessments')
def assessments(principal: Principal = Depends(verify_api_key)):
    return [serialize_doc(j) for j in get_database().analysis_jobs.find(scope(principal, {'status': {'$ne': 'deleted'}}), {'_id':0, 'payload_hash':0}).sort('created_at', -1).limit(100)]


@router.delete('/assessments/{job_id}')
def delete_job(job_id: UUID, principal: Principal = Depends(require_admin)):
    try:
        return delete_assessment(principal.org_id, str(job_id), principal.user_id)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(503, 'Deletion is incomplete. Check integration availability and retry.') from None


@router.post('/assessments/{job_id}/retry-integrations')
def retry_integrations(job_id: UUID, principal: Principal = Depends(require_admin)):
    if not get_database().analysis_jobs.find_one(scope(principal, {'job_id':str(job_id), 'status':'done'})):
        raise HTTPException(404, 'Completed assessment not found')
    result = run_integrations(principal.org_id, str(job_id))
    audit(principal.org_id, principal.user_id, 'integrations.retry', str(job_id))
    return result


@router.get('/operations')
def operations(principal: Principal = Depends(verify_api_key)):
    db = get_database()
    return {'alerts': [serialize_doc(d) for d in db.alert_deliveries.find(scope(principal), {'_id':0, 'dedupe_key':0}).sort('updated_at',-1).limit(50)],
            'audit': [serialize_doc(d) for d in db.audit.find(scope(principal), {'_id':0}).sort('created_at',-1).limit(50)] if principal.role == 'admin' else [],
            'retention': serialize_doc(db.operations.find_one(scope(principal, {'kind':'retention'}), {'_id':0}))}


@router.get('/graph/weaknesses')
def shared_weaknesses(principal: Principal = Depends(verify_api_key)):
    try:
        return graph_shared_weaknesses(principal.org_id)
    except Exception:
        raise HTTPException(503, 'Graph integration unavailable; evidence may be incomplete') from None


class RemediationRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    session_id: int
    rule_id: str = Field(min_length=1, max_length=100)


@router.post('/remediations')
def track_remediation(body: RemediationRequest, principal: Principal = Depends(verify_api_key)):
    db = get_database()
    session = db.sessions.find_one(visible_scope(principal, {'id':body.session_id}))
    if not session or body.rule_id not in [f['rule_id'] for f in session.get('findings',[])]:
        raise HTTPException(404, 'Observed finding not found')
    key = scope(principal, {'session_id':body.session_id, 'rule_id':body.rule_id})
    db.remediations.update_one(key, {'$setOnInsert': {**key, 'host_id':session['host_id'], 'job_id':session.get('job_id'), 'source_kind': session.get('source_kind'), 'protocol':session['protocol'], 'dst_port':session['dst_port'], 'created_at':datetime.now(UTC)}}, upsert=True)
    audit(principal.org_id, principal.user_id, 'remediation.track', f'{body.session_id}:{body.rule_id}')
    return {'status':'tracked'}


@router.get('/remediations')
def remediation_evidence(principal: Principal = Depends(verify_api_key)):
    db, result = get_database(), []
    for item in db.remediations.find(scope(principal), {'_id':0}).limit(100):
        subsequent = list(db.sessions.find(visible_scope(principal, {'source_kind': item.get('source_kind'), 'host_id':item['host_id'], 'protocol':item['protocol'], 'dst_port':item['dst_port'], 'id':{'$gt':item['session_id']}})).sort('id',-1).limit(10))
        evidence = [{'session_id':s['id'], 'still_observed':item['rule_id'] in [f['rule_id'] for f in s.get('findings',[])], 'capture_complete':s.get('capture_complete',False)} for s in subsequent]
        item['evidence'] = evidence
        item['status'] = 'still_observed' if any(e['still_observed'] for e in evidence) else 'not_observed_in_later_samples' if evidence else 'awaiting_observations'
        # Absence in sampled traffic does not prove resolution.
        item['resolution_verified'] = False
        result.append(serialize_doc(item))
    return result
