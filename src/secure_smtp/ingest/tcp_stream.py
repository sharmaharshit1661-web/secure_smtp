"""
TCP stream reassembly — Stage 1.

Takes raw packets grouped by stream and reassembles them into ordered
byte sequences, handling retransmissions and out-of-order delivery.
Produces separate client→server and server→client byte streams.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from secure_smtp.ingest.pcap_reader import PacketStream, RawPacket

logger = logging.getLogger(__name__)


@dataclass
class ReassembledSegment:
    """A contiguous chunk of reassembled data with its byte offset in the stream."""

    offset: int  # Byte offset from the start of this direction's data
    data: bytes
    timestamp: float = 0.0


@dataclass
class DirectionalStream:
    """Ordered byte stream from one side of a connection."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    data: bytes = b""
    segments: list[ReassembledSegment] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return len(self.data) == 0


@dataclass
class ReassembledStream:
    """
    Fully reassembled TCP stream with separate client→server
    and server→client byte sequences.
    """

    client_to_server: DirectionalStream
    server_to_client: DirectionalStream
    client_ip: str
    server_ip: str
    client_port: int
    server_port: int

    @property
    def full_payload(self) -> bytes:
        """Interleaved full payload — all data in timestamp order."""
        all_segments = []
        for seg in self.client_to_server.segments:
            all_segments.append((seg.timestamp, "c2s", seg.data))
        for seg in self.server_to_client.segments:
            all_segments.append((seg.timestamp, "s2c", seg.data))
        all_segments.sort(key=lambda x: x[0])
        return b"".join(s[2] for s in all_segments)


def _identify_client(stream: PacketStream) -> tuple[str, int]:
    """Identify the client by finding the SYN packet initiator."""
    for pkt in stream.packets:
        if "S" in pkt.flags and "A" not in pkt.flags:
            return pkt.src_ip, pkt.src_port
    # Fallback: first packet sender is client
    if stream.packets:
        return stream.packets[0].src_ip, stream.packets[0].src_port
    return "", 0


def _reassemble_direction(
    packets: list[RawPacket],
) -> tuple[bytes, list[ReassembledSegment]]:
    """
    Reassemble one direction of a TCP stream.

    Uses sequence numbers to handle out-of-order and retransmitted packets.
    Returns the full reassembled data and the list of segments.
    """
    if not packets:
        return b"", []

    # Filter to packets with payload
    data_packets = [p for p in packets if len(p.payload) > 0]
    if not data_packets:
        return b"", []

    # Sort by sequence number for ordered reassembly
    data_packets.sort(key=lambda p: p.seq)

    # Track seen sequence ranges to skip retransmissions
    segments: list[ReassembledSegment] = []
    seen_ranges: list[tuple[int, int]] = []  # (start_seq, end_seq)
    base_seq = data_packets[0].seq
    total_data = bytearray()

    for pkt in data_packets:
        pkt_start = pkt.seq
        pkt_end = pkt_start + len(pkt.payload)

        # Check if this is a retransmission (overlaps with already-seen data)
        is_retransmit = False
        for seen_start, seen_end in seen_ranges:
            if pkt_start >= seen_start and pkt_end <= seen_end:
                is_retransmit = True
                break

        if is_retransmit:
            continue

        # Handle partial overlaps by trimming
        effective_payload = pkt.payload
        for seen_start, seen_end in seen_ranges:
            if pkt_start < seen_end and pkt_end > seen_start:
                # Partial overlap — trim the overlapping part
                if pkt_start < seen_start:
                    effective_payload = pkt.payload[: seen_start - pkt_start]
                    pkt_end = seen_start
                else:
                    trim = seen_end - pkt_start
                    effective_payload = pkt.payload[trim:]
                    pkt_start = seen_end

        if effective_payload:
            offset = pkt_start - base_seq
            segments.append(
                ReassembledSegment(
                    offset=max(0, offset),
                    data=effective_payload,
                    timestamp=pkt.timestamp,
                )
            )
            seen_ranges.append((pkt_start, pkt_start + len(effective_payload)))

    # Sort segments by offset and concatenate
    segments.sort(key=lambda s: s.offset)

    # Build the final byte stream, filling gaps with empty bytes if needed
    for seg in segments:
        if seg.offset + len(seg.data) > 16 * 1024 * 1024:
            raise ValueError("TCP sequence span exceeds the 16 MiB per-direction limit")
        current_len = len(total_data)
        if seg.offset > current_len:
            # Gap in the data — fill with zeros (indicates missing packets)
            total_data.extend(b"\x00" * (seg.offset - current_len))
        elif seg.offset < current_len:
            # Overlap — skip already-covered bytes
            skip = current_len - seg.offset
            if skip < len(seg.data):
                total_data.extend(seg.data[skip:])
            continue
        total_data.extend(seg.data)

    return bytes(total_data), segments


def reassemble_stream(stream: PacketStream) -> ReassembledStream:
    """
    Reassemble a PacketStream into ordered byte sequences.

    Args:
        stream: A PacketStream from pcap_reader containing all packets
                for a single TCP connection.

    Returns:
        A ReassembledStream with separate client→server and server→client data.
    """
    client_ip, client_port = _identify_client(stream)
    server_ip = ""
    server_port = 0

    client_packets: list[RawPacket] = []
    server_packets: list[RawPacket] = []

    for pkt in stream.packets:
        if pkt.src_ip == client_ip and pkt.src_port == client_port:
            client_packets.append(pkt)
            if not server_ip:
                server_ip = pkt.dst_ip
                server_port = pkt.dst_port
        else:
            server_packets.append(pkt)
            if not server_ip:
                server_ip = pkt.src_ip
                server_port = pkt.src_port

    c2s_data, c2s_segments = _reassemble_direction(client_packets)
    s2c_data, s2c_segments = _reassemble_direction(server_packets)

    logger.debug(
        "Reassembled stream %s:%d → %s:%d: C2S=%d bytes, S2C=%d bytes",
        client_ip,
        client_port,
        server_ip,
        server_port,
        len(c2s_data),
        len(s2c_data),
    )

    return ReassembledStream(
        client_to_server=DirectionalStream(
            src_ip=client_ip,
            dst_ip=server_ip,
            src_port=client_port,
            dst_port=server_port,
            data=c2s_data,
            segments=c2s_segments,
        ),
        server_to_client=DirectionalStream(
            src_ip=server_ip,
            dst_ip=client_ip,
            src_port=server_port,
            dst_port=client_port,
            data=s2c_data,
            segments=s2c_segments,
        ),
        client_ip=client_ip,
        server_ip=server_ip,
        client_port=client_port,
        server_port=server_port,
    )
