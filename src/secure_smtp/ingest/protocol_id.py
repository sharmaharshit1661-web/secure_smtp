"""
Protocol identification — Stage 2.

Detects SMTP, IMAP, and POP3 sessions by inspecting banners/commands
(not just well-known ports). Detects STARTTLS/STLS negotiation and
marks the exact byte offset where TLS begins.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from secure_smtp.db.models import ProtocolType, TLSMode
from secure_smtp.ingest.tcp_stream import ReassembledStream

logger = logging.getLogger(__name__)

# ── Well-known ports (used as hints, not sole identifiers) ──

SMTP_PORTS = {25, 587, 2525}
SMTPS_PORTS = {465}
IMAP_PORTS = {143}
IMAPS_PORTS = {993}
POP3_PORTS = {110}
POP3S_PORTS = {995}
IMPLICIT_TLS_PORTS = SMTPS_PORTS | IMAPS_PORTS | POP3S_PORTS

# ── Banner/command patterns ──

# SMTP: "220 hostname ESMTP ..." or "220-hostname ..."
SMTP_BANNER_RE = re.compile(rb"^220[\s-]", re.MULTILINE)
SMTP_EHLO_RE = re.compile(rb"^(EHLO|HELO)\s", re.MULTILINE | re.IGNORECASE)
SMTP_STARTTLS_CMD = re.compile(rb"^STARTTLS\r?\n", re.MULTILINE | re.IGNORECASE)
SMTP_STARTTLS_READY = re.compile(rb"^220 ", re.MULTILINE)  # "220 Ready to start TLS"
SMTP_STARTTLS_ADV = re.compile(rb"250[\s-]STARTTLS", re.MULTILINE | re.IGNORECASE)

# IMAP: "* OK ... IMAP ..." or "* OK [CAPABILITY ...]"
IMAP_BANNER_RE = re.compile(rb"^\* OK\s", re.MULTILINE)
IMAP_STARTTLS_CMD = re.compile(rb"^\S+\s+STARTTLS\r?\n", re.MULTILINE | re.IGNORECASE)
IMAP_STARTTLS_OK = re.compile(rb"^\S+\s+OK\s", re.MULTILINE | re.IGNORECASE)
IMAP_STARTTLS_ADV = re.compile(rb"STARTTLS", re.IGNORECASE)

# POP3: "+OK ... POP3 ..." or "+OK Hello"
POP3_BANNER_RE = re.compile(rb"^\+OK\s", re.MULTILINE)
POP3_STLS_CMD = re.compile(rb"^STLS\r?\n", re.MULTILINE | re.IGNORECASE)
POP3_STLS_OK = re.compile(rb"^\+OK\s", re.MULTILINE)
POP3_STLS_ADV = re.compile(rb"STLS", re.IGNORECASE)

# TLS record header: content_type(1 byte) + version(2 bytes) + length(2 bytes)
# content_type 0x16 = Handshake, version 0x0301-0x0304
TLS_RECORD_RE = re.compile(rb"\x16\x03[\x00-\x04]")


@dataclass
class ProtocolIdentification:
    """Result of protocol and STARTTLS identification for a session."""

    protocol: ProtocolType
    tls_mode: TLSMode
    starttls_advertised: bool
    starttls_completed: bool
    tls_offset_client: int  # Byte offset in C2S where TLS begins (-1 if none)
    tls_offset_server: int  # Byte offset in S2C where TLS begins (-1 if none)
    server_banner: str  # The raw server banner text


def _find_tls_start(data: bytes, search_from: int = 0) -> int:
    """Find the byte offset where TLS records begin in a data stream."""
    match = TLS_RECORD_RE.search(data, search_from)
    if match:
        return match.start()
    return -1


def _detect_smtp(c2s: bytes, s2c: bytes, server_port: int) -> ProtocolIdentification | None:
    """Try to identify SMTP protocol from stream data."""
    # Check for SMTP banner in server→client data
    banner_match = SMTP_BANNER_RE.search(s2c[:2048])
    port_hint = server_port in SMTP_PORTS | SMTPS_PORTS

    if not banner_match and not port_hint:
        return None

    if not banner_match and port_hint:
        # Port matches but no banner — might be implicit TLS
        if server_port in SMTPS_PORTS:
            tls_off_c = _find_tls_start(c2s)
            tls_off_s = _find_tls_start(s2c)
            if tls_off_c >= 0 or tls_off_s >= 0:
                return ProtocolIdentification(
                    protocol=ProtocolType.SMTP,
                    tls_mode=TLSMode.IMPLICIT,
                    starttls_advertised=False,
                    starttls_completed=False,
                    tls_offset_client=max(tls_off_c, 0),
                    tls_offset_server=max(tls_off_s, 0),
                    server_banner="",
                )
        return None

    # Extract banner text
    banner_end = s2c.find(b"\r\n", banner_match.start())
    banner_text = s2c[banner_match.start() : banner_end].decode("ascii", errors="replace")

    # Check for STARTTLS
    starttls_advertised = bool(SMTP_STARTTLS_ADV.search(s2c[:4096]))
    starttls_cmd = SMTP_STARTTLS_CMD.search(c2s)
    starttls_completed = False
    tls_off_c = -1
    tls_off_s = -1

    if starttls_cmd:
        # Find the server's 220 response after the STARTTLS command
        # Look for TLS records after the command
        cmd_offset_c2s = starttls_cmd.end()
        tls_off_c = _find_tls_start(c2s, cmd_offset_c2s)

        # In S2C, look for 220 response then TLS
        # Find where in the server stream the STARTTLS response would be
        tls_off_s = _find_tls_start(s2c, len(s2c) // 3)  # heuristic
        if tls_off_s < 0:
            tls_off_s = _find_tls_start(s2c)

        if tls_off_c >= 0 or tls_off_s >= 0:
            starttls_completed = True

    # Determine TLS mode
    if starttls_completed:
        tls_mode = TLSMode.STARTTLS
    elif server_port in SMTPS_PORTS:
        tls_mode = TLSMode.IMPLICIT
        tls_off_c = _find_tls_start(c2s)
        tls_off_s = _find_tls_start(s2c)
    else:
        tls_mode = TLSMode.NONE

    return ProtocolIdentification(
        protocol=ProtocolType.SMTP,
        tls_mode=tls_mode,
        starttls_advertised=starttls_advertised,
        starttls_completed=starttls_completed,
        tls_offset_client=tls_off_c,
        tls_offset_server=tls_off_s,
        server_banner=banner_text,
    )


def _detect_imap(c2s: bytes, s2c: bytes, server_port: int) -> ProtocolIdentification | None:
    """Try to identify IMAP protocol from stream data."""
    banner_match = IMAP_BANNER_RE.search(s2c[:2048])
    port_hint = server_port in IMAP_PORTS | IMAPS_PORTS

    if not banner_match and not port_hint:
        return None

    if not banner_match and port_hint:
        if server_port in IMAPS_PORTS:
            tls_off_c = _find_tls_start(c2s)
            tls_off_s = _find_tls_start(s2c)
            if tls_off_c >= 0 or tls_off_s >= 0:
                return ProtocolIdentification(
                    protocol=ProtocolType.IMAP,
                    tls_mode=TLSMode.IMPLICIT,
                    starttls_advertised=False,
                    starttls_completed=False,
                    tls_offset_client=max(tls_off_c, 0),
                    tls_offset_server=max(tls_off_s, 0),
                    server_banner="",
                )
        return None

    banner_end = s2c.find(b"\r\n", banner_match.start())
    banner_text = s2c[banner_match.start() : banner_end].decode("ascii", errors="replace")

    starttls_advertised = bool(IMAP_STARTTLS_ADV.search(s2c[:4096]))
    starttls_cmd = IMAP_STARTTLS_CMD.search(c2s)
    starttls_completed = False
    tls_off_c = -1
    tls_off_s = -1

    if starttls_cmd:
        cmd_offset = starttls_cmd.end()
        tls_off_c = _find_tls_start(c2s, cmd_offset)
        tls_off_s = _find_tls_start(s2c, len(s2c) // 3)
        if tls_off_s < 0:
            tls_off_s = _find_tls_start(s2c)
        if tls_off_c >= 0 or tls_off_s >= 0:
            starttls_completed = True

    if starttls_completed:
        tls_mode = TLSMode.STARTTLS
    elif server_port in IMAPS_PORTS:
        tls_mode = TLSMode.IMPLICIT
        tls_off_c = _find_tls_start(c2s)
        tls_off_s = _find_tls_start(s2c)
    else:
        tls_mode = TLSMode.NONE

    return ProtocolIdentification(
        protocol=ProtocolType.IMAP,
        tls_mode=tls_mode,
        starttls_advertised=starttls_advertised,
        starttls_completed=starttls_completed,
        tls_offset_client=tls_off_c,
        tls_offset_server=tls_off_s,
        server_banner=banner_text,
    )


def _detect_pop3(c2s: bytes, s2c: bytes, server_port: int) -> ProtocolIdentification | None:
    """Try to identify POP3 protocol from stream data."""
    banner_match = POP3_BANNER_RE.search(s2c[:2048])
    port_hint = server_port in POP3_PORTS | POP3S_PORTS

    if not banner_match and not port_hint:
        return None

    # Distinguish POP3 "+OK" from IMAP "* OK" — POP3 uses "+OK"
    if banner_match:
        # Make sure this isn't an IMAP server
        if IMAP_BANNER_RE.search(s2c[:2048]):
            return None

    if not banner_match and port_hint:
        if server_port in POP3S_PORTS:
            tls_off_c = _find_tls_start(c2s)
            tls_off_s = _find_tls_start(s2c)
            if tls_off_c >= 0 or tls_off_s >= 0:
                return ProtocolIdentification(
                    protocol=ProtocolType.POP3,
                    tls_mode=TLSMode.IMPLICIT,
                    starttls_advertised=False,
                    starttls_completed=False,
                    tls_offset_client=max(tls_off_c, 0),
                    tls_offset_server=max(tls_off_s, 0),
                    server_banner="",
                )
        return None

    banner_end = s2c.find(b"\r\n", banner_match.start())
    banner_text = s2c[banner_match.start() : banner_end].decode("ascii", errors="replace")

    starttls_advertised = bool(POP3_STLS_ADV.search(s2c[:4096]))
    stls_cmd = POP3_STLS_CMD.search(c2s)
    starttls_completed = False
    tls_off_c = -1
    tls_off_s = -1

    if stls_cmd:
        cmd_offset = stls_cmd.end()
        tls_off_c = _find_tls_start(c2s, cmd_offset)
        tls_off_s = _find_tls_start(s2c, len(s2c) // 3)
        if tls_off_s < 0:
            tls_off_s = _find_tls_start(s2c)
        if tls_off_c >= 0 or tls_off_s >= 0:
            starttls_completed = True

    if starttls_completed:
        tls_mode = TLSMode.STARTTLS
    elif server_port in POP3S_PORTS:
        tls_mode = TLSMode.IMPLICIT
        tls_off_c = _find_tls_start(c2s)
        tls_off_s = _find_tls_start(s2c)
    else:
        tls_mode = TLSMode.NONE

    return ProtocolIdentification(
        protocol=ProtocolType.POP3,
        tls_mode=tls_mode,
        starttls_advertised=starttls_advertised,
        starttls_completed=starttls_completed,
        tls_offset_client=tls_off_c,
        tls_offset_server=tls_off_s,
        server_banner=banner_text,
    )


def identify_protocol(stream: ReassembledStream) -> ProtocolIdentification:
    """
    Identify the email protocol and TLS mode for a reassembled stream.

    Tries SMTP, IMAP, and POP3 detection in order, using both
    banner inspection and port hints (FR-2).

    Args:
        stream: A Reassembled TCP stream.

    Returns:
        ProtocolIdentification with protocol type, TLS mode, and STARTTLS status.
    """
    c2s = stream.client_to_server.data
    s2c = stream.server_to_client.data
    server_port = stream.server_port

    # Try each protocol detector in order
    for detector in [_detect_smtp, _detect_imap, _detect_pop3]:
        result = detector(c2s, s2c, server_port)
        if result is not None:
            logger.info(
                "Identified %s session %s:%d → %s:%d (TLS: %s, STARTTLS adv: %s, completed: %s)",
                result.protocol.value,
                stream.client_ip,
                stream.client_port,
                stream.server_ip,
                stream.server_port,
                result.tls_mode.value,
                result.starttls_advertised,
                result.starttls_completed,
            )
            return result

    # Fallback: check if there's any TLS at all (might be an unrecognized protocol on non-standard port)
    tls_off_c = _find_tls_start(c2s)
    tls_off_s = _find_tls_start(s2c)

    logger.debug(
        "Could not identify protocol for %s:%d → %s:%d",
        stream.client_ip,
        stream.client_port,
        stream.server_ip,
        stream.server_port,
    )

    return ProtocolIdentification(
        protocol=ProtocolType.UNKNOWN,
        tls_mode=TLSMode.IMPLICIT if (tls_off_c >= 0 or tls_off_s >= 0) else TLSMode.NONE,
        starttls_advertised=False,
        starttls_completed=False,
        tls_offset_client=tls_off_c,
        tls_offset_server=tls_off_s,
        server_banner="",
    )
