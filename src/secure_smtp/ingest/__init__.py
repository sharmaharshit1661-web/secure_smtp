"""
PCAP Ingest, TCP Stream Reassembly & Protocol Identification Package.

Provides low-level network packet reading, bi-directional stream reconstruction,
and stateful application layer protocol detection (SMTP, IMAP, POP3) with STARTTLS awareness.
"""

from __future__ import annotations

from secure_smtp.ingest.pcap_reader import PacketStream, read_pcap
from secure_smtp.ingest.protocol_id import ProtocolIdentification, identify_protocol
from secure_smtp.ingest.tcp_stream import ReassembledStream, reassemble_stream

__all__ = [
    "read_pcap",
    "PacketStream",
    "reassemble_stream",
    "ReassembledStream",
    "identify_protocol",
    "ProtocolIdentification",
]
