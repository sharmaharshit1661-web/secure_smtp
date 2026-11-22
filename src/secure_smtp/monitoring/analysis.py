"""Recompute findings on validated evidence; collectors never supply risk scores."""

from secure_smtp.ai.explain import enrich_risk_score_with_explanation
from secure_smtp.ai.features import build_feature_vector
from secure_smtp.ai.risk_model import RiskModel
from secure_smtp.db.models import Certificate, Session, TLSHandshake
from secure_smtp.rules.engine import RuleEngine


def score_observation(observation, session_id, host_id):
    values = observation.model_dump(mode="json")
    session = Session(
        id=session_id,
        host_id=host_id,
        pcap_source="agent_metadata",
        **{
            k: values[k]
            for k in [
                "src_ip",
                "dst_ip",
                "src_port",
                "dst_port",
                "protocol",
                "tls_mode",
                "starttls_advertised",
                "starttls_completed",
            ]
        },
    )
    handshake = TLSHandshake(**values["handshake"]) if values["handshake"] else None
    certificates = [Certificate(**cert) for cert in values["certificates"]]
    findings = RuleEngine().evaluate_session(session, handshake, certificates)
    # A truncated capture can miss the upgrade completion. Keep uncertainty explicit.
    if not observation.capture_complete:
        findings = [finding for finding in findings if finding.rule_id != "starttls-stripped"]
    for finding in findings:
        finding.session_id = session_id
    session.handshake, session.certificates, session.findings = handshake, certificates, findings
    if observation.tls_mode != "unknown":
        fv = build_feature_vector(session, handshake, certificates, findings)
        risk = RiskModel().score_session(fv, findings)
        risk.session_id = session_id
        session.risk_score = enrich_risk_score_with_explanation(risk, findings, fv)
    return session.model_dump()
