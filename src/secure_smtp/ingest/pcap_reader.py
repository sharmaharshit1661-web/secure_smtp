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

from scapy.all import IP, TCP, IPv6, PcapReader

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
    if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)) or not pkt.haslayer(TCP):
        return None

    ip_layer = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
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

    payload_bytes = 0
    # Decode incrementally; bound objects, streams and retained payload independently
    # of upload size. Reject oversized captures rather than return partial evidence.
    with PcapReader(str(filepath)) as packets:
        for count, pkt in enumerate(packets, 1):
            if count > 100_000:
                raise ValueError("Capture exceeds the 100000 packet analysis limit")
            timestamp = float(pkt.time) if hasattr(pkt, "time") else 0.0
            raw = _extract_packet(pkt, timestamp)
            if raw is None:
                continue
            payload_bytes += len(raw.payload)
            if payload_bytes > 128 * 1024 * 1024:
                raise ValueError("Capture exceeds the retained payload limit")
            packet_count += 1
            key = StreamKey.from_packet(raw)
            if key not in streams:
                if len(streams) >= 10_000:
                    raise ValueError("Capture exceeds the 10000 stream analysis limit")
                streams[key] = PacketStream(key=key)
            if len(streams[key].packets) >= 5_000:
                raise ValueError("A connection exceeds the 5000 packet analysis limit")
            streams[key].packets.append(raw)

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
