"""
PCAP reader — Stage 1 entry point.

Loads .pcap/.pcapng files via scapy, filters TCP packets,
and groups them by 5-tuple into streams for reassembly.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from scapy.all import IP, TCP, PcapReader

logger = logging.getLogger(__name__)


@dataclass
class RawPacket:
    """A single TCP packet with metadata."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    seq: int
    ack: int
    flags: str
    payload: bytes
    timestamp: float


@dataclass
class StreamKey:
    """Bidirectional stream identifier (5-tuple, direction-normalized)."""

    ip_a: str
    ip_b: str
    port_a: int
    port_b: int

    def __hash__(self) -> int:
        return hash((self.ip_a, self.ip_b, self.port_a, self.port_b))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, StreamKey):
            return NotImplemented
        return (
            self.ip_a == other.ip_a
            and self.ip_b == other.ip_b
            and self.port_a == other.port_a
            and self.port_b == other.port_b
        )

    @classmethod
    def from_packet(cls, pkt: RawPacket) -> StreamKey:
        """Create a normalized stream key from a packet.

        Normalizes direction so that (A→B) and (B→A) map to the same key.
        """
        if (pkt.src_ip, pkt.src_port) < (pkt.dst_ip, pkt.dst_port):
            return cls(pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port)
        return cls(pkt.dst_ip, pkt.src_ip, pkt.dst_port, pkt.src_port)


@dataclass
class PacketStream:
    """All packets belonging to a single TCP stream."""

    key: StreamKey
    packets: list[RawPacket] = field(default_factory=list)

    @property
    def client_ip(self) -> str:
        """The client is the side that initiated the connection (first SYN)."""
        for pkt in self.packets:
            if "S" in pkt.flags and "A" not in pkt.flags:
                return pkt.src_ip
        # Fallback: first packet sender
        return self.packets[0].src_ip if self.packets else ""

    @property
    def server_ip(self) -> str:
        """The server is the other side of the connection."""
        client = self.client_ip
        if not self.packets:
            return ""
        first = self.packets[0]
        return first.dst_ip if first.src_ip == client else first.src_ip

    @property
    def client_port(self) -> int:
        client = self.client_ip
        for pkt in self.packets:
            if pkt.src_ip == client:
                return pkt.src_port
        return 0

    @property
    def server_port(self) -> int:
        client = self.client_ip
        for pkt in self.packets:
            if pkt.src_ip == client:
                return pkt.dst_port
        return 0


def _extract_packet(pkt, timestamp: float) -> RawPacket | None:
    """Extract a RawPacket from a scapy packet if it contains TCP."""
    if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
        return None

    ip_layer = pkt[IP]
    tcp_layer = pkt[TCP]
    payload = bytes(tcp_layer.payload) if tcp_layer.payload else b""

    # Build flags string
    flags = ""
    flag_map = {
        0x02: "S",  # SYN
        0x10: "A",  # ACK
        0x01: "F",  # FIN
        0x04: "R",  # RST
        0x08: "P",  # PSH
        0x20: "U",  # URG
    }
    tcp_flags = tcp_layer.flags
    for bit, char in flag_map.items():
        if int(tcp_flags) & bit:
            flags += char

    return RawPacket(
        src_ip=ip_layer.src,
        dst_ip=ip_layer.dst,
        src_port=tcp_layer.sport,
        dst_port=tcp_layer.dport,
        seq=tcp_layer.seq,
        ack=tcp_layer.ack,
        flags=flags,
        payload=payload,
        timestamp=timestamp,
    )


def read_pcap(filepath: str | Path) -> list[PacketStream]:
    """
    Read a PCAP/PCAPNG file and group TCP packets into bidirectional streams.

    Args:
        filepath: Path to the .pcap or .pcapng file.

    Returns:
        List of PacketStream objects, each containing all packets for a TCP connection.
    """
    filepath = Path(filepath)
    if not filepath.exists():
        raise FileNotFoundError(f"PCAP file not found: {filepath}")

    logger.info("Reading PCAP: %s", filepath)

    streams: dict[StreamKey, PacketStream] = {}
    packet_count = 0

    from secure_smtp.config import get_settings
    from secure_smtp.ingest.validation import validate_capture
    limits = get_settings()
    validate_capture(filepath, limits.max_capture_packets)
    try:
        packets = PcapReader(str(filepath))
    except Exception as e:
        logger.error("Failed to read PCAP %s: %s", filepath, e)
        raise

    for index, pkt in enumerate(packets):
        if index >= limits.max_capture_packets:
            packets.close()
            raise ValueError("Capture packet limit exceeded")
        timestamp = float(pkt.time) if hasattr(pkt, "time") else 0.0
        raw = _extract_packet(pkt, timestamp)
        if raw is None:
            continue

        packet_count += 1
        key = StreamKey.from_packet(raw)
        if key not in streams:
            if len(streams) >= limits.max_capture_streams:
                packets.close()
                raise ValueError("Capture stream limit exceeded")
            streams[key] = PacketStream(key=key)
        streams[key].packets.append(raw)

    packets.close()
    stream_list = list(streams.values())
    logger.info(
        "Extracted %d TCP packets across %d streams from %s",
        packet_count,
        len(stream_list),
        filepath,
    )

    return stream_list


def read_pcap_streaming(filepath: str | Path) -> Iterator[PacketStream]:
    """
    Read a large PCAP file in streaming mode (lower memory usage).

    Yields streams one at a time after the full file is read.
    For truly huge PCAPs, a two-pass approach would be needed —
    this is sufficient for hackathon-scale files.
    """
    # For now, delegate to the batch reader — streaming optimization
    # is a Phase 5 concern per NFR-4
    yield from read_pcap(filepath)
