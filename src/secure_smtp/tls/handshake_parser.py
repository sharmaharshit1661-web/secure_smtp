"""
TLS handshake parser — Stage 3.

Parses ClientHello and ServerHello from raw bytes at the TLS offset
identified by protocol_id. Extracts negotiated version, cipher suite,
extensions, and key exchange type.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field

from secure_smtp.db.models import KeyExchangeType

logger = logging.getLogger(__name__)

# ── TLS Version Constants ──

TLS_VERSIONS = {
    (3, 0): "SSLv3",
    (3, 1): "TLS1.0",
    (3, 2): "TLS1.1",
    (3, 3): "TLS1.2",
    (3, 4): "TLS1.3",
}

# ── Cipher suite classification ──

# Cipher suites that use ECDHE key exchange
ECDHE_CIPHERS = {
    0xC009, 0xC00A, 0xC013, 0xC014, 0xC023, 0xC024, 0xC027, 0xC028,
    0xC02B, 0xC02C, 0xC02F, 0xC030, 0xCCA8, 0xCCA9, 0xCCAA,
    0x1301, 0x1302, 0x1303,  # TLS 1.3 suites (always ECDHE/DHE)
}

# Cipher suites that use DHE key exchange
DHE_CIPHERS = {
    0x0033, 0x0039, 0x0067, 0x006B, 0x009E, 0x009F, 0x00A2, 0x00A3,
    0xCCAD,
}

# Known weak/broken cipher suites
WEAK_CIPHER_IDS = {
    # NULL ciphers
    0x0000, 0x0001, 0x0002, 0x002C, 0x002D, 0x002E,
    # Export ciphers
    0x0003, 0x0006, 0x0008, 0x000B, 0x000E, 0x0011, 0x0014, 0x0017,
    0x0019, 0x0026, 0x0027, 0x0028, 0x0029, 0x002A, 0x002B,
    # RC4 ciphers
    0x0004, 0x0005, 0x0018, 0x0024, 0xC002, 0xC007, 0xC00C, 0xC011,
    # DES ciphers
    0x0009, 0x000C, 0x000F, 0x0012, 0x0015,
    # 3DES ciphers
    0x000A, 0x000D, 0x0010, 0x0013, 0x0016,
}

# Named cipher suites for display
CIPHER_NAMES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x0000: "TLS_NULL_WITH_NULL_NULL",
}


@dataclass
class ParsedClientHello:
    """Parsed TLS ClientHello message."""

    tls_record_version: str = ""
    client_version: str = ""
    supported_versions: list[str] = field(default_factory=list)
    cipher_suites: list[int] = field(default_factory=list)
    cipher_suite_names: list[str] = field(default_factory=list)
    compression_methods: list[int] = field(default_factory=list)
    extensions: dict[int, bytes] = field(default_factory=dict)
    extension_types: list[int] = field(default_factory=list)
    sni: str = ""
    random: bytes = b""


@dataclass
class ParsedServerHello:
    """Parsed TLS ServerHello message."""

    tls_record_version: str = ""
    server_version: str = ""
    cipher_suite: int = 0
    cipher_suite_name: str = ""
    compression_method: int = 0
    extensions: dict[int, bytes] = field(default_factory=dict)
    extension_types: list[int] = field(default_factory=list)
    random: bytes = b""
    is_tls13: bool = False


@dataclass
class ParsedHandshake:
    """Combined result of parsing both ClientHello and ServerHello."""

    client_hello: ParsedClientHello | None = None
    server_hello: ParsedServerHello | None = None
    tls_version_offered: list[str] = field(default_factory=list)
    tls_version_negotiated: str = ""
    cipher_suite_negotiated: str = ""
    cipher_suite_id: int = 0
    key_exchange_type: KeyExchangeType = KeyExchangeType.UNKNOWN
    forward_secrecy: bool | None = None
    visibility_limited: bool = False
    extension_count: int = 0
    raw_certificates: list[bytes] = field(default_factory=list)


def _get_version_string(major: int, minor: int) -> str:
    """Convert TLS version bytes to a human-readable string."""
    return TLS_VERSIONS.get((major, minor), f"Unknown({major}.{minor})")


def _get_cipher_name(cipher_id: int) -> str:
    """Get the human-readable name of a cipher suite."""
    return CIPHER_NAMES.get(cipher_id, f"0x{cipher_id:04X}")


def _classify_key_exchange(cipher_id: int) -> KeyExchangeType:
    """Classify the key exchange type for a cipher suite."""
    if cipher_id in ECDHE_CIPHERS:
        return KeyExchangeType.ECDHE
    if cipher_id in DHE_CIPHERS:
        return KeyExchangeType.DHE
    # TLS 1.3 cipher suites always use (EC)DHE
    if cipher_id in (0x1301, 0x1302, 0x1303):
        return KeyExchangeType.ECDHE
    # Default for RSA key exchange suites
    return KeyExchangeType.RSA


def _parse_extensions(data: bytes, offset: int, length: int) -> tuple[dict[int, bytes], list[int]]:
    """Parse TLS extensions from raw bytes."""
    extensions: dict[int, bytes] = {}
    ext_types: list[int] = []
    end = offset + length
    pos = offset

    while pos + 4 <= end:
        ext_type = struct.unpack("!H", data[pos:pos + 2])[0]
        ext_len = struct.unpack("!H", data[pos + 2:pos + 4])[0]
        pos += 4
        if pos + ext_len > end:
            break
        extensions[ext_type] = data[pos:pos + ext_len]
        ext_types.append(ext_type)
        pos += ext_len

    return extensions, ext_types


def _extract_sni(ext_data: bytes) -> str:
    """Extract the SNI hostname from the server_name extension data."""
    if len(ext_data) < 5:
        return ""
    try:
        # Skip SNI list length (2 bytes), then SNI type (1 byte) + name length (2 bytes)
        pos = 2
        if pos < len(ext_data) and ext_data[pos] == 0:  # host_name type
            pos += 1
            name_len = struct.unpack("!H", ext_data[pos:pos + 2])[0]
            pos += 2
            return ext_data[pos:pos + name_len].decode("ascii", errors="replace")
    except (struct.error, IndexError):
        pass
    return ""


def _extract_supported_versions(ext_data: bytes) -> list[str]:
    """Extract supported versions from the supported_versions extension (0x002B)."""
    versions = []
    if len(ext_data) < 1:
        return versions
    try:
        list_len = ext_data[0]
        pos = 1
        while pos + 2 <= 1 + list_len:
            major = ext_data[pos]
            minor = ext_data[pos + 1]
            versions.append(_get_version_string(major, minor))
            pos += 2
    except IndexError:
        pass
    return versions


def parse_client_hello(data: bytes) -> ParsedClientHello | None:
    """
    Parse a TLS ClientHello message from raw bytes.

    Args:
        data: Raw bytes starting at the TLS record header.

    Returns:
        ParsedClientHello or None if parsing fails.
    """
    if len(data) < 5:
        return None

    try:
        # TLS record header
        content_type = data[0]
        if content_type != 0x16:  # Not a Handshake record
            return None

        record_version_major = data[1]
        record_version_minor = data[2]

        result = ParsedClientHello()
        result.tls_record_version = _get_version_string(record_version_major, record_version_minor)

        # Handshake header
        pos = 5
        if pos >= len(data):
            return None

        handshake_type = data[pos]
        if handshake_type != 1:  # Not ClientHello
            return None
        pos += 1

        # Handshake length (3 bytes)
        pos += 3

        # Client version
        client_major = data[pos]
        client_minor = data[pos + 1]
        result.client_version = _get_version_string(client_major, client_minor)
        pos += 2

        # Random (32 bytes)
        result.random = data[pos:pos + 32]
        pos += 32

        # Session ID
        session_id_len = data[pos]
        pos += 1 + session_id_len

        # Cipher suites
        cipher_suites_len = struct.unpack("!H", data[pos:pos + 2])[0]
        pos += 2
        num_ciphers = cipher_suites_len // 2
        for _ in range(num_ciphers):
            cs = struct.unpack("!H", data[pos:pos + 2])[0]
            result.cipher_suites.append(cs)
            result.cipher_suite_names.append(_get_cipher_name(cs))
            pos += 2

        # Compression methods
        comp_len = data[pos]
        pos += 1
        for i in range(comp_len):
            result.compression_methods.append(data[pos + i])
        pos += comp_len

        # Extensions (if present)
        if pos + 2 <= len(data):
            extensions_len = struct.unpack("!H", data[pos:pos + 2])[0]
            pos += 2
            result.extensions, result.extension_types = _parse_extensions(
                data, pos, extensions_len
            )

            # Extract SNI (extension type 0)
            if 0 in result.extensions:
                result.sni = _extract_sni(result.extensions[0])

            # Extract supported versions (extension type 0x002B = 43)
            if 43 in result.extensions:
                result.supported_versions = _extract_supported_versions(
                    result.extensions[43]
                )
            else:
                result.supported_versions = [result.client_version]

        return result

    except (struct.error, IndexError) as e:
        logger.debug("Failed to parse ClientHello: %s", e)
        return None


def parse_server_hello(data: bytes) -> ParsedServerHello | None:
    """
    Parse a TLS ServerHello message from raw bytes.

    Args:
        data: Raw bytes starting at the TLS record header.

    Returns:
        ParsedServerHello or None if parsing fails.
    """
    if len(data) < 5:
        return None

    try:
        content_type = data[0]
        if content_type != 0x16:
            return None

        record_version_major = data[1]
        record_version_minor = data[2]
        record_length = struct.unpack("!H", data[3:5])[0]

        result = ParsedServerHello()
        result.tls_record_version = _get_version_string(record_version_major, record_version_minor)

        pos = 5
        handshake_type = data[pos]
        if handshake_type != 2:  # Not ServerHello
            return None
        pos += 1

        # Handshake length
        pos += 3

        # Server version
        server_major = data[pos]
        server_minor = data[pos + 1]
        result.server_version = _get_version_string(server_major, server_minor)
        pos += 2

        # Random
        result.random = data[pos:pos + 32]
        pos += 32

        # Session ID
        session_id_len = data[pos]
        pos += 1 + session_id_len

        # Cipher suite (single value)
        result.cipher_suite = struct.unpack("!H", data[pos:pos + 2])[0]
        result.cipher_suite_name = _get_cipher_name(result.cipher_suite)
        pos += 2

        # Compression method
        result.compression_method = data[pos]
        pos += 1

        # Extensions
        if pos + 2 <= 5 + record_length and pos + 2 <= len(data):
            extensions_len = struct.unpack("!H", data[pos:pos + 2])[0]
            pos += 2
            result.extensions, result.extension_types = _parse_extensions(
                data, pos, extensions_len
            )

            # Check for TLS 1.3 via supported_versions extension
            if 43 in result.extensions:
                ext_data = result.extensions[43]
                if len(ext_data) >= 2:
                    major = ext_data[0]
                    minor = ext_data[1]
                    negotiated = _get_version_string(major, minor)
                    if negotiated == "TLS1.3":
                        result.is_tls13 = True
                        result.server_version = "TLS1.3"

        return result

    except (struct.error, IndexError) as e:
        logger.debug("Failed to parse ServerHello: %s", e)
        return None


def _extract_certificates_from_handshake(data: bytes, offset: int = 0) -> list[bytes]:
    """
    Extract DER-encoded certificates from TLS Certificate message.

    Scans for Handshake type 11 (Certificate) in the TLS records
    starting from the given offset.
    """
    certificates: list[bytes] = []
    pos = offset

    while pos + 5 < len(data):
        # Look for TLS record header
        if data[pos] != 0x16:  # Not a Handshake record
            pos += 1
            continue

        try:
            record_len = struct.unpack("!H", data[pos + 3:pos + 5])[0]
            record_start = pos + 5

            # Check if this record contains a Certificate message
            hs_pos = record_start
            while hs_pos + 4 <= record_start + record_len and hs_pos < len(data):
                hs_type = data[hs_pos]
                hs_len = struct.unpack("!I", b"\x00" + data[hs_pos + 1:hs_pos + 4])[0]
                hs_data_start = hs_pos + 4

                if hs_type == 11:  # Certificate message
                    # Parse certificate list
                    cert_pos = hs_data_start
                    if cert_pos + 3 > len(data):
                        break
                    certs_total_len = struct.unpack(
                        "!I", b"\x00" + data[cert_pos:cert_pos + 3]
                    )[0]
                    cert_pos += 3

                    cert_end = cert_pos + certs_total_len
                    while cert_pos + 3 <= cert_end and cert_pos + 3 <= len(data):
                        cert_len = struct.unpack(
                            "!I", b"\x00" + data[cert_pos:cert_pos + 3]
                        )[0]
                        cert_pos += 3
                        if cert_pos + cert_len <= len(data):
                            certificates.append(data[cert_pos:cert_pos + cert_len])
                        cert_pos += cert_len

                hs_pos = hs_data_start + hs_len

            pos += 5 + record_len
        except (struct.error, IndexError):
            pos += 1

    return certificates


def parse_handshake(
    client_data: bytes,
    server_data: bytes,
    tls_offset_client: int = 0,
    tls_offset_server: int = 0,
) -> ParsedHandshake:
    """
    Parse TLS handshake from both directions of a stream.

    Args:
        client_data: Raw bytes from client→server stream.
        server_data: Raw bytes from server→client stream.
        tls_offset_client: Byte offset where TLS begins in client data.
        tls_offset_server: Byte offset where TLS begins in server data.

    Returns:
        ParsedHandshake with all extracted TLS information.
    """
    result = ParsedHandshake()

    # Parse ClientHello from client→server data
    if tls_offset_client >= 0 and tls_offset_client < len(client_data):
        result.client_hello = parse_client_hello(client_data[tls_offset_client:])

    # Parse ServerHello from server→client data
    if tls_offset_server >= 0 and tls_offset_server < len(server_data):
        result.server_hello = parse_server_hello(server_data[tls_offset_server:])

    # Derive combined handshake properties
    if result.client_hello:
        result.tls_version_offered = (
            result.client_hello.supported_versions
            or [result.client_hello.client_version]
        )
        result.extension_count = len(result.client_hello.extension_types)

    if result.server_hello:
        # Negotiated version: prefer supported_versions extension, fall back to ServerHello version
        result.tls_version_negotiated = result.server_hello.server_version
        result.cipher_suite_negotiated = result.server_hello.cipher_suite_name
        result.cipher_suite_id = result.server_hello.cipher_suite
        result.key_exchange_type = _classify_key_exchange(result.server_hello.cipher_suite)
        result.forward_secrecy = result.key_exchange_type in (
            KeyExchangeType.ECDHE,
            KeyExchangeType.DHE,
        )

        # TLS 1.3 visibility limitation
        if result.server_hello.is_tls13 or result.tls_version_negotiated == "TLS1.3":
            result.visibility_limited = True

    # Extract certificates from server→client data
    if tls_offset_server >= 0 and tls_offset_server < len(server_data):
        result.raw_certificates = _extract_certificates_from_handshake(
            server_data, tls_offset_server
        )

    return result
