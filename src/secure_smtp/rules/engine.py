"""
Crypto weakness rule engine — Stage 4.

Loads the YAML ruleset, evaluates each rule's condition against
Session/TLSHandshake/Certificate data using a restricted safe-eval DSL,
and emits Finding rows for every match.

The condition language is intentionally simple — no raw eval() on untrusted input.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from secure_smtp.db.models import (
    Certificate,
    Finding,
    Session,
    Severity,
    TLSHandshake,
)
from secure_smtp.tls.handshake_parser import CIPHER_NAMES, WEAK_CIPHER_IDS

logger = logging.getLogger(__name__)

# Path to the default ruleset
DEFAULT_RULESET_PATH = Path(__file__).parent / "ruleset.yaml"

# Weak cipher names for the rule engine
WEAK_CIPHER_NAMES = set()
for cid in WEAK_CIPHER_IDS:
    name = CIPHER_NAMES.get(cid, f"0x{cid:04X}")
    WEAK_CIPHER_NAMES.add(name)
# Also match by common substrings
WEAK_CIPHER_SUBSTRINGS = ["RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5"]


def is_weak_cipher(cipher_name: str) -> bool:
    """Check if a cipher suite name represents a weak cipher."""
    if cipher_name in WEAK_CIPHER_NAMES:
        return True
    upper = cipher_name.upper()
    return any(sub in upper for sub in WEAK_CIPHER_SUBSTRINGS)


def is_expired(dt: Any) -> bool:
    """Check if a datetime is in the past."""
    if dt is None:
        return False
    now = datetime.now(UTC)
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return now > dt
    return False


def is_expiring_soon(dt: Any, days: int = 30) -> bool:
    """Check if a datetime is within N days from now."""
    if dt is None:
        return False
    now = datetime.now(UTC)
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        delta = dt - now
        return 0 <= delta.days <= days
    return False


class RuleEngine:
    """
    Evaluates YAML-defined crypto weakness rules against session data.

    Uses a restricted condition evaluation approach (not raw eval)
    to safely process rule conditions.
    """

    def __init__(self, ruleset_path: str | Path | None = None):
        self.ruleset_path = Path(ruleset_path) if ruleset_path else DEFAULT_RULESET_PATH
        self.rules: list[dict] = []
        self._load_rules()

    def _load_rules(self) -> None:
        """Load and validate the YAML ruleset."""
        if not self.ruleset_path.exists():
            logger.error("Ruleset not found: %s", self.ruleset_path)
            return

        with open(self.ruleset_path) as f:
            raw = yaml.safe_load(f)

        if not isinstance(raw, list):
            logger.error("Ruleset must be a YAML list of rules")
            return

        for rule in raw:
            required = ["id", "applies_to", "condition", "severity", "message", "recommendation"]
            if all(k in rule for k in required):
                self.rules.append(rule)
            else:
                missing = [k for k in required if k not in rule]
                logger.warning("Skipping rule with missing fields %s: %s", missing, rule.get("id"))

        logger.info("Loaded %d rules from %s", len(self.rules), self.ruleset_path)

    def evaluate_session(
        self,
        session: Session,
        handshake: TLSHandshake | None,
        certificates: list[Certificate],
    ) -> list[Finding]:
        """
        Evaluate all rules against a session and return findings.

        Args:
            session: The email session to evaluate.
            handshake: The TLS handshake (may be None for plaintext sessions).
            certificates: List of certificates from the handshake.

        Returns:
            List of Finding objects for triggered rules.
        """
        findings: list[Finding] = []

        for rule in self.rules:
            rule_findings = self._evaluate_rule(rule, session, handshake, certificates)
            findings.extend(rule_findings)

        logger.info(
            "Session %s:%d→%s:%d: %d findings from %d rules",
            session.src_ip,
            session.src_port,
            session.dst_ip,
            session.dst_port,
            len(findings),
            len(self.rules),
        )

        return findings

    def _evaluate_rule(
        self,
        rule: dict,
        session: Session,
        handshake: TLSHandshake | None,
        certificates: list[Certificate],
    ) -> list[Finding]:
        """Evaluate a single rule against session data."""
        findings: list[Finding] = []
        applies_to = rule["applies_to"]

        try:
            if applies_to.startswith("session."):
                # Session-level rule
                result = self._eval_session_rule(rule, session, handshake)
                if result:
                    findings.append(result)

            elif applies_to.startswith("handshake."):
                # Handshake-level rule
                if handshake is not None:
                    result = self._eval_handshake_rule(rule, handshake, session)
                    if result:
                        findings.append(result)

            elif applies_to.startswith("certificate."):
                # Certificate-level rule — evaluate per certificate
                for cert in certificates:
                    result = self._eval_cert_rule(rule, cert, session)
                    if result:
                        findings.append(result)
        except Exception as e:
            logger.warning("Error evaluating rule '%s': %s", rule["id"], e)

        return findings

    def _eval_session_rule(
        self,
        rule: dict,
        session: Session,
        handshake: TLSHandshake | None,
    ) -> Finding | None:
        """Evaluate a session-level rule."""
        field_name = rule["applies_to"].split(".", 1)[1]
        value = getattr(session, field_name, None)

        # Handle enum values
        if hasattr(value, "value"):
            value = value.value

        context = {
            "value": value,
            "session": self._session_context(session),
        }

        if self._eval_condition(rule["condition"], context):
            return self._create_finding(rule, session, value)
        return None

    def _eval_handshake_rule(
        self,
        rule: dict,
        handshake: TLSHandshake,
        session: Session,
    ) -> Finding | None:
        """Evaluate a handshake-level rule."""
        field_name = rule["applies_to"].split(".", 1)[1]
        value = getattr(handshake, field_name, None)

        # Handle enum values
        if hasattr(value, "value"):
            value = value.value

        context = {
            "value": value,
            "handshake": self._handshake_context(handshake),
            "session": self._session_context(session),
        }

        if self._eval_condition(rule["condition"], context):
            return self._create_finding(rule, session, value)
        return None

    def _eval_cert_rule(
        self,
        rule: dict,
        cert: Certificate,
        session: Session,
    ) -> Finding | None:
        """Evaluate a certificate-level rule."""
        field_name = rule["applies_to"].split(".", 1)[1]
        value = getattr(cert, field_name, None)

        context = {
            "value": value,
            "certificate": self._cert_context(cert),
        }

        if self._eval_condition(rule["condition"], context):
            return self._create_finding(rule, session, value, cert_position=cert.chain_position)
        return None

    def _eval_condition(self, condition: str, context: dict) -> bool:
        """
        Safely evaluate a rule condition.

        Uses a restricted evaluation approach — no raw eval() on untrusted input.
        Conditions are parsed as simple expressions with a limited set of operations.
        """
        value = context.get("value")
        session = context.get("session", {})
        certificate = context.get("certificate", {})

        try:
            # Handle function-style conditions
            if condition.startswith("is_weak_cipher("):
                return is_weak_cipher(str(value)) if value else False

            if condition.startswith("is_expired("):
                return is_expired(value)

            if condition.startswith("is_expiring_soon("):
                # Extract the days parameter
                parts = condition.split(",")
                days = 30
                if len(parts) > 1:
                    days_str = parts[1].strip().rstrip(")")
                    try:
                        days = int(days_str)
                    except ValueError:
                        pass
                return is_expiring_soon(value, days)

            # Handle complex session-level conditions
            if "session." in condition and ("value ==" in condition or "value in" in condition):
                # Parse compound conditions with 'and'
                parts = condition.split(" and ")
                results = []
                for part in parts:
                    part = part.strip()
                    if "session." in part:
                        field_val = self._resolve_nested(part, {"session": session})
                        results.append(bool(field_val))
                    elif "value ==" in part:
                        expected = part.split("==")[1].strip().strip("'\"")
                        if expected == "true":
                            results.append(bool(value))
                        elif expected == "false":
                            results.append(not bool(value))
                        else:
                            results.append(str(value) == expected)
                return all(results)

            # Handle 'value in [...]' conditions
            if "value in [" in condition:
                list_str = condition.split("[")[1].rstrip("]").strip()
                items = [s.strip().strip("'\"") for s in list_str.split(",")]
                return str(value) in items

            # Handle 'value == ...' conditions
            if "value ==" in condition:
                expected = condition.split("==")[1].strip().strip("'\"")
                if expected == "true":
                    return bool(value)
                elif expected == "false":
                    return not bool(value)
                return str(value) == expected

            # Handle compound conditions with 'and'
            if " and " in condition:
                # Certificate compound conditions need special handling
                if "certificate." in condition:
                    return self._eval_cert_compound(condition, certificate, value)
                return all(
                    self._eval_condition(p.strip(), context) for p in condition.split(" and ")
                )

            # Handle certificate compound conditions (no 'and')
            if "certificate." in condition:
                return self._eval_cert_compound(condition, certificate, value)

            logger.debug("Unrecognized condition format: %s", condition)
            return False

        except Exception as e:
            logger.debug("Condition evaluation error for '%s': %s", condition, e)
            return False

    def _eval_cert_compound(self, condition: str, cert_ctx: dict, value: Any) -> bool:
        """Evaluate certificate-specific compound conditions."""
        # Handle "certificate.field == X and value < Y"
        parts = condition.split(" and ")
        results = []

        for part in parts:
            part = part.strip()
            if part.startswith("certificate."):
                # Extract field and comparison
                tokens = part.replace("certificate.", "").split()
                if len(tokens) >= 3:
                    field = tokens[0]
                    op = tokens[1]
                    expected = tokens[2].strip("'\"")
                    actual = cert_ctx.get(field, "")
                    results.append(self._compare(actual, op, expected))
            elif part.startswith("value"):
                tokens = part.split()
                if len(tokens) >= 3:
                    op = tokens[1]
                    expected = tokens[2].strip("'\"")
                    results.append(self._compare(value, op, expected))
            elif "in [" in part:
                list_str = part.split("[")[1].rstrip("]").strip()
                items = [s.strip().strip("'\"") for s in list_str.split(",")]
                results.append(str(value) in items)

        return all(results) if results else False

    def _compare(self, actual: Any, op: str, expected: str) -> bool:
        """Perform a comparison operation."""
        try:
            if op == "==":
                if expected in ("true", "True"):
                    return bool(actual)
                if expected in ("false", "False"):
                    return not bool(actual)
                return str(actual) == expected
            elif op == "!=":
                return str(actual) != expected
            elif op == "<":
                return float(actual) < float(expected)
            elif op == "<=":
                return float(actual) <= float(expected)
            elif op == ">":
                return float(actual) > float(expected)
            elif op == ">=":
                return float(actual) >= float(expected)
        except (ValueError, TypeError):
            return False
        return False

    def _resolve_nested(self, expr: str, context: dict) -> Any:
        """Resolve a nested field reference like 'session.tls_mode'."""
        parts = expr.split("==")
        if len(parts) == 2:
            field_path = parts[0].strip()
            expected = parts[1].strip().strip("'\"")
            obj_parts = field_path.split(".")
            obj = context
            for p in obj_parts:
                if isinstance(obj, dict):
                    obj = obj.get(p)
                else:
                    obj = getattr(obj, p, None)
                if obj is None:
                    return False
            if expected in ("true", "True"):
                return bool(obj)
            if expected in ("false", "False"):
                return not bool(obj)
            return str(obj) == expected
        return False

    def _session_context(self, session: Session) -> dict:
        """Create a dict context for a session."""
        return {
            "tls_mode": session.tls_mode.value if hasattr(session.tls_mode, "value") else str(session.tls_mode),
            "starttls_advertised": session.starttls_advertised,
            "starttls_completed": session.starttls_completed,
            "protocol": session.protocol.value if hasattr(session.protocol, "value") else str(session.protocol),
        }

    def _handshake_context(self, handshake: TLSHandshake) -> dict:
        """Create a dict context for a handshake."""
        return {
            "tls_version_negotiated": handshake.tls_version_negotiated,
            "cipher_suite_negotiated": handshake.cipher_suite_negotiated,
            "key_exchange_type": handshake.key_exchange_type.value if hasattr(handshake.key_exchange_type, "value") else str(handshake.key_exchange_type),
            "forward_secrecy": handshake.forward_secrecy,
            "visibility_limited": handshake.visibility_limited,
        }

    def _cert_context(self, cert: Certificate) -> dict:
        """Create a dict context for a certificate."""
        return {
            "public_key_algorithm": cert.public_key_algorithm,
            "key_length_bits": cert.key_length_bits,
            "signature_algorithm": cert.signature_algorithm,
            "self_signed": cert.self_signed,
            "not_after": cert.not_after,
            "not_before": cert.not_before,
            "chain_valid": cert.chain_valid,
            "chain_position": cert.chain_position,
        }

    def _create_finding(
        self,
        rule: dict,
        session: Session,
        value: Any,
        cert_position: int | None = None,
    ) -> Finding:
        """Create a Finding from a triggered rule."""
        import json

        evidence = {"triggered_value": str(value)}
        if cert_position is not None:
            evidence["certificate_chain_position"] = cert_position

        message = rule["message"].format(value=value)
        recommendation = rule["recommendation"].format(value=value)

        return Finding(
            session_id=session.id or 0,
            rule_id=rule["id"],
            severity=Severity(rule["severity"]),
            evidence=json.dumps(evidence),
            message=message,
            recommendation_text=recommendation,
        )
