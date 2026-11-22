"""
X.509 certificate parser — Stage 3.

Extracts full certificate chains from TLS handshakes and parses
them using the `cryptography` library. Validates expiry, key
algorithm/length, signature algorithm, chain completeness,
and self-signed status.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID

logger = logging.getLogger(__name__)


@dataclass
class ParsedCertificate:
    """Parsed X.509 certificate information."""

    chain_position: int = 0
    subject: str = ""
    issuer: str = ""
    san: list[str] = field(default_factory=list)
    not_before: datetime | None = None
    not_after: datetime | None = None
    public_key_algorithm: str = ""
    key_length_bits: int = 0
    signature_algorithm: str = ""
    self_signed: bool = False
    chain_valid: bool | None = None
    serial_number: str = ""

    # Raw certificate for further inspection
    raw_der: bytes = b""


def _get_key_info(cert: x509.Certificate) -> tuple[str, int]:
    """Extract public key algorithm and key size from a certificate."""
    public_key = cert.public_key()

    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        return "ECDSA", public_key.key_size
    elif isinstance(public_key, dsa.DSAPublicKey):
        return "DSA", public_key.key_size
    elif isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    elif isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448", 448
    else:
        return "Unknown", 0


def _normalize_sig_algorithm(oid_name: str) -> str:
    """Normalize signature algorithm name for rule engine consumption."""
    name_lower = oid_name.lower()

    # Map to simplified names used in the rule engine
    if "md5" in name_lower:
        return "md5"
    elif "sha1" in name_lower and "sha1" in name_lower:
        return "sha1"
    elif "sha256" in name_lower:
        return "sha256"
    elif "sha384" in name_lower:
        return "sha384"
    elif "sha512" in name_lower:
        return "sha512"
    elif "ed25519" in name_lower:
        return "ed25519"
    elif "ed448" in name_lower:
        return "ed448"
    else:
        return oid_name


def _get_subject_str(name: x509.Name) -> str:
    """Convert an X.509 Name to a readable string."""
    parts = []
    for attr in name:
        try:
            oid_name = attr.oid._name
            parts.append(f"{oid_name}={attr.value}")
        except Exception:
            parts.append(str(attr))
    return ", ".join(parts)


def _get_san_list(cert: x509.Certificate) -> list[str]:
    """Extract Subject Alternative Names from a certificate."""
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_value = san_ext.value
        names = []
        for name in san_value:
            if isinstance(name, x509.DNSName):
                names.append(f"DNS:{name.value}")
            elif isinstance(name, x509.IPAddress):
                names.append(f"IP:{name.value}")
            elif isinstance(name, x509.RFC822Name):
                names.append(f"email:{name.value}")
            else:
                names.append(str(name.value))
        return names
    except x509.ExtensionNotFound:
        return []
    except Exception as e:
        logger.debug("Failed to extract SAN: %s", e)
        return []


def parse_certificate(der_bytes: bytes, chain_position: int = 0) -> ParsedCertificate | None:
    """
    Parse a single DER-encoded X.509 certificate.

    Args:
        der_bytes: DER-encoded certificate bytes.
        chain_position: Position in the certificate chain (0 = leaf).

    Returns:
        ParsedCertificate or None if parsing fails.
    """
    try:
        cert = x509.load_der_x509_certificate(der_bytes)

        key_algo, key_length = _get_key_info(cert)
        sig_algo = _normalize_sig_algorithm(cert.signature_algorithm_oid._name)

        # Check if self-signed (subject == issuer)
        is_self_signed = cert.subject == cert.issuer

        # Handle timezone-aware datetimes
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc

        return ParsedCertificate(
            chain_position=chain_position,
            subject=_get_subject_str(cert.subject),
            issuer=_get_subject_str(cert.issuer),
            san=_get_san_list(cert),
            not_before=not_before,
            not_after=not_after,
            public_key_algorithm=key_algo,
            key_length_bits=key_length,
            signature_algorithm=sig_algo,
            self_signed=is_self_signed,
            serial_number=str(cert.serial_number),
            raw_der=der_bytes,
        )

    except Exception as e:
        logger.warning("Failed to parse certificate at chain position %d: %s", chain_position, e)
        return None


def parse_certificate_chain(
    der_certs: list[bytes],
) -> list[ParsedCertificate]:
    """
    Parse a complete certificate chain.

    Args:
        der_certs: List of DER-encoded certificates, ordered from leaf to root.

    Returns:
        List of ParsedCertificate objects with chain validation results.
    """
    parsed: list[ParsedCertificate] = []

    for i, der in enumerate(der_certs):
        cert = parse_certificate(der, chain_position=i)
        if cert:
            parsed.append(cert)

    # Validate chain: each cert's issuer should match the next cert's subject
    if len(parsed) > 1:
        for i in range(len(parsed) - 1):
            current = parsed[i]
            next_cert = parsed[i + 1]
            if current.issuer != next_cert.subject:
                current.chain_valid = False
                logger.debug(
                    "Chain break at position %d: issuer '%s' != next subject '%s'",
                    i,
                    current.issuer,
                    next_cert.subject,
                )

    # If the chain has only one cert that is self-signed, it's still valid
    # (but the rule engine will flag self-signed as a finding)
    if len(parsed) == 1 and parsed[0].self_signed:
        parsed[0].chain_valid = None  # Trust and signatures are not validated by issuer-name matching.

    # Check if the chain is complete (root should be self-signed or trusted)
    if parsed and not parsed[-1].self_signed:
        # Incomplete chain — missing root CA
        # Mark this but don't invalidate individual certs
        logger.debug("Certificate chain appears incomplete (root is not self-signed)")

    return parsed


def is_certificate_expired(cert: ParsedCertificate, now: datetime | None = None) -> bool:
    """Check if a certificate is expired."""
    if now is None:
        now = datetime.now(UTC)
    if cert.not_after is None:
        return False
    not_after = cert.not_after
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=UTC)
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    return now > not_after


def days_until_expiry(cert: ParsedCertificate, now: datetime | None = None) -> int:
    """Calculate days until certificate expiry (negative if expired)."""
    if now is None:
        now = datetime.now(UTC)
    if cert.not_after is None:
        return 9999
    not_after = cert.not_after
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=UTC)
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    delta = not_after - now
    return delta.days
