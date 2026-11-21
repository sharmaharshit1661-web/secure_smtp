"""
TLS Handshake Inspection, Certificate Decoding & Fingerprinting Package.

Provides TLS record parsing, cipher suite and extension extraction,
X.509 certificate validation, and JA3/JA3S/JA4/JA4S fingerprint computation.
"""

from __future__ import annotations

from secure_smtp.tls.cert_parser import ParsedCertificate, parse_certificate_chain
from secure_smtp.tls.fingerprint import TLSFingerprints, compute_fingerprints
from secure_smtp.tls.handshake_parser import ParsedHandshake, parse_handshake

__all__ = [
    "parse_handshake",
    "ParsedHandshake",
    "parse_certificate_chain",
    "ParsedCertificate",
    "compute_fingerprints",
    "TLSFingerprints",
]
