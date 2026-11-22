"""
TLS fingerprinting — JA3/JA3S and JA4/JA4S computation.

JA3 spec: https://github.com/salesforce/ja3
JA4 spec: https://github.com/FoxIO-LLC/ja4

JA3/JA3S are well-documented MD5 fingerprints of TLS handshake fields.
JA4/JA4S are best-effort implementations based on the published spec.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass

from secure_smtp.tls.handshake_parser import ParsedClientHello, ParsedServerHello

logger = logging.getLogger(__name__)

# GREASE values to filter out (per JA3 spec)
GREASE_VALUES = {
    0x0A0A,
    0x1A1A,
    0x2A2A,
    0x3A3A,
    0x4A4A,
    0x5A5A,
    0x6A6A,
    0x7A7A,
    0x8A8A,
    0x9A9A,
    0xAAAA,
    0xBABA,
    0xCACA,
    0xDADA,
    0xEAEA,
    0xFAFA,
}


@dataclass
class TLSFingerprints:
    """All computed fingerprints for a session."""

    ja3: str = ""
    ja3s: str = ""
    ja4: str = ""
    ja4s: str = ""
    ja3_raw: str = ""
    ja3s_raw: str = ""


def _filter_grease(values: list[int]) -> list[int]:
    """Remove GREASE values from a list of TLS values."""
    return [v for v in values if v not in GREASE_VALUES]


def _tls_version_to_ja3(version_str: str) -> int:
    """Convert a version string to the JA3 numeric representation."""
    version_map = {
        "SSLv3": 0x0300,
        "TLS1.0": 0x0301,
        "TLS1.1": 0x0302,
        "TLS1.2": 0x0303,
        "TLS1.3": 0x0304,
    }
    return version_map.get(version_str, 0)


def compute_ja3(client_hello: ParsedClientHello) -> tuple[str, str]:
    """
    Compute JA3 fingerprint from a parsed ClientHello.

    JA3 = MD5(TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)

    Returns:
        Tuple of (ja3_hash, ja3_raw_string)
    """
    # TLS version (use record version for consistency with JA3 spec)
    version = _tls_version_to_ja3(client_hello.client_version)

    # Cipher suites (filter GREASE)
    ciphers = _filter_grease(client_hello.cipher_suites)
    ciphers_str = "-".join(str(c) for c in ciphers)

    # Extensions (filter GREASE)
    extensions = _filter_grease(client_hello.extension_types)
    extensions_str = "-".join(str(e) for e in extensions)

    # Elliptic curves (supported_groups extension, type 10)
    curves_str = ""
    if 10 in client_hello.extensions:
        ec_data = client_hello.extensions[10]
        if len(ec_data) >= 2:
            import struct

            list_len = struct.unpack("!H", ec_data[0:2])[0]
            curves = []
            pos = 2
            while pos + 2 <= 2 + list_len and pos + 2 <= len(ec_data):
                curve = struct.unpack("!H", ec_data[pos : pos + 2])[0]
                if curve not in GREASE_VALUES:
                    curves.append(curve)
                pos += 2
            curves_str = "-".join(str(c) for c in curves)

    # EC point formats (extension type 11)
    formats_str = ""
    if 11 in client_hello.extensions:
        pf_data = client_hello.extensions[11]
        if len(pf_data) >= 1:
            pf_len = pf_data[0]
            formats = list(pf_data[1 : 1 + pf_len])
            formats_str = "-".join(str(f) for f in formats)

    raw = f"{version},{ciphers_str},{extensions_str},{curves_str},{formats_str}"
    ja3_hash = hashlib.md5(raw.encode()).hexdigest()

    return ja3_hash, raw


def compute_ja3s(server_hello: ParsedServerHello) -> tuple[str, str]:
    """
    Compute JA3S fingerprint from a parsed ServerHello.

    JA3S = MD5(TLSVersion,CipherSuite,Extensions)

    Returns:
        Tuple of (ja3s_hash, ja3s_raw_string)
    """
    version = _tls_version_to_ja3(server_hello.server_version)
    cipher = server_hello.cipher_suite

    extensions = _filter_grease(server_hello.extension_types)
    extensions_str = "-".join(str(e) for e in extensions)

    raw = f"{version},{cipher},{extensions_str}"
    ja3s_hash = hashlib.md5(raw.encode()).hexdigest()

    return ja3s_hash, raw


def _compute_ja4_a_section(client_hello: ParsedClientHello) -> str:
    """
    Compute the 'a' section of JA4 fingerprint.

    Format: [protocol][version][SNI][cipher_count][ext_count][ALPN_first_value]
    """
    # Protocol: 't' for TCP TLS (we don't handle QUIC/DTLS)
    proto = "t"

    # TLS version: highest version from supported_versions or client_version
    version_str = client_hello.client_version
    if client_hello.supported_versions:
        # Use the highest version
        version_priority = {"TLS1.3": 4, "TLS1.2": 3, "TLS1.1": 2, "TLS1.0": 1, "SSLv3": 0}
        best = max(client_hello.supported_versions, key=lambda v: version_priority.get(v, -1))
        version_str = best

    version_map = {"TLS1.3": "13", "TLS1.2": "12", "TLS1.1": "11", "TLS1.0": "10", "SSLv3": "s3"}
    ver = version_map.get(version_str, "00")

    # SNI: 'd' if SNI present, 'i' if not
    sni = "d" if client_hello.sni else "i"

    # Cipher count (2 chars, zero padded, excluding GREASE)
    cipher_count = len(_filter_grease(client_hello.cipher_suites))
    cc = f"{min(cipher_count, 99):02d}"

    # Extension count (2 chars, zero padded, excluding GREASE + SNI + ALPN)
    ext_list = _filter_grease(client_hello.extension_types)
    # Remove SNI (0) and ALPN (16) from count per JA4 spec
    ext_filtered = [e for e in ext_list if e not in (0, 16)]
    ec = f"{min(len(ext_filtered), 99):02d}"

    # ALPN first value (extension type 16)
    alpn = "00"
    if 16 in client_hello.extensions:
        alpn_data = client_hello.extensions[16]
        if len(alpn_data) >= 4:
            alpn_str_len = alpn_data[2]
            if alpn_str_len > 0 and 3 + alpn_str_len <= len(alpn_data):
                first_alpn = alpn_data[3 : 3 + alpn_str_len].decode("ascii", errors="replace")
                # Take first and last character
                if len(first_alpn) >= 2:
                    alpn = first_alpn[0] + first_alpn[-1]
                elif len(first_alpn) == 1:
                    alpn = first_alpn[0] + "0"

    return f"{proto}{ver}{sni}{cc}{ec}{alpn}"


def compute_ja4(client_hello: ParsedClientHello) -> str:
    """
    Compute JA4 fingerprint from a parsed ClientHello.

    JA4 = a_section_b_section_c_section
    where:
      a = protocol + version + SNI + cipher_count + ext_count + ALPN
      b = sha256(sorted cipher suites)[:12]
      c = sha256(sorted extensions + signature algorithms)[:12]

    Returns:
        JA4 fingerprint string.
    """
    a_section = _compute_ja4_a_section(client_hello)

    # b section: SHA256 of sorted cipher suites (excluding GREASE), truncated to 12 hex chars
    ciphers = _filter_grease(client_hello.cipher_suites)
    ciphers_sorted = sorted(ciphers)
    ciphers_str = ",".join(f"{c:04x}" for c in ciphers_sorted)
    b_section = hashlib.sha256(ciphers_str.encode()).hexdigest()[:12]

    # c section: SHA256 of sorted extensions (excluding GREASE, SNI, ALPN)
    ext_list = _filter_grease(client_hello.extension_types)
    ext_filtered = sorted(e for e in ext_list if e not in (0, 16))
    ext_str = ",".join(f"{e:04x}" for e in ext_filtered)

    # Append signature algorithms (extension type 13) if present
    if 13 in client_hello.extensions:
        sig_data = client_hello.extensions[13]
        if len(sig_data) >= 2:
            import struct

            sig_len = struct.unpack("!H", sig_data[0:2])[0]
            sig_algos = []
            pos = 2
            while pos + 2 <= 2 + sig_len and pos + 2 <= len(sig_data):
                sa = struct.unpack("!H", sig_data[pos : pos + 2])[0]
                sig_algos.append(sa)
                pos += 2
            sig_str = ",".join(f"{s:04x}" for s in sig_algos)
            if ext_str:
                ext_str += "_" + sig_str
            else:
                ext_str = sig_str

    c_section = hashlib.sha256(ext_str.encode()).hexdigest()[:12]

    return f"{a_section}_{b_section}_{c_section}"


def compute_ja4s(server_hello: ParsedServerHello) -> str:
    """
    Compute JA4S fingerprint from a parsed ServerHello.

    JA4S = a_section_b_section_c_section

    Returns:
        JA4S fingerprint string.
    """
    # a section: protocol + version + ext_count + ALPN
    proto = "t"
    version_map = {"TLS1.3": "13", "TLS1.2": "12", "TLS1.1": "11", "TLS1.0": "10", "SSLv3": "s3"}
    ver = version_map.get(server_hello.server_version, "00")

    ext_list = _filter_grease(server_hello.extension_types)
    ec = f"{min(len(ext_list), 99):02d}"

    # ALPN from server
    alpn = "00"
    if 16 in server_hello.extensions:
        alpn_data = server_hello.extensions[16]
        if len(alpn_data) >= 4:
            alpn_str_len = alpn_data[2]
            if alpn_str_len > 0 and 3 + alpn_str_len <= len(alpn_data):
                first_alpn = alpn_data[3 : 3 + alpn_str_len].decode("ascii", errors="replace")
                if len(first_alpn) >= 2:
                    alpn = first_alpn[0] + first_alpn[-1]
                elif len(first_alpn) == 1:
                    alpn = first_alpn[0] + "0"

    a_section = f"{proto}{ver}{ec}{alpn}"

    # b section: single cipher suite
    cipher = server_hello.cipher_suite
    b_section = hashlib.sha256(f"{cipher:04x}".encode()).hexdigest()[:12]

    # c section: sorted extensions
    ext_sorted = sorted(ext_list)
    ext_str = ",".join(f"{e:04x}" for e in ext_sorted)
    c_section = hashlib.sha256(ext_str.encode()).hexdigest()[:12]

    return f"{a_section}_{b_section}_{c_section}"


def compute_fingerprints(
    client_hello: ParsedClientHello | None,
    server_hello: ParsedServerHello | None,
) -> TLSFingerprints:
    """
    Compute all TLS fingerprints (JA3, JA3S, JA4, JA4S).

    Args:
        client_hello: Parsed ClientHello (may be None).
        server_hello: Parsed ServerHello (may be None).

    Returns:
        TLSFingerprints with all computed hashes.
    """
    result = TLSFingerprints()

    if client_hello:
        result.ja3, result.ja3_raw = compute_ja3(client_hello)
        result.ja4 = compute_ja4(client_hello)

    if server_hello:
        result.ja3s, result.ja3s_raw = compute_ja3s(server_hello)
        result.ja4s = compute_ja4s(server_hello)

    return result
