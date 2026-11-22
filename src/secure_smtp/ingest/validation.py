"""Strict container framing validation before a capture reaches Scapy."""

import struct
from pathlib import Path


def validate_capture(path: str | Path, max_packets: int = 100000) -> None:
    data = Path(path).read_bytes()
    count = 0
    magic = data[:4]
    if magic in (
        b"\xd4\xc3\xb2\xa1",
        b"\xa1\xb2\xc3\xd4",
        b"\x4d\x3c\xb2\xa1",
        b"\xa1\xb2\x3c\x4d",
    ):
        endian = "<" if magic[0] in (0xD4, 0x4D) else ">"
        if len(data) < 24:
            raise ValueError("Truncated PCAP header")
        major, minor, _, _, snaplen, _ = struct.unpack(endian + "HHIIII", data[4:24])
        if (major, minor) != (2, 4) or not 0 < snaplen <= 16 * 1024 * 1024:
            raise ValueError("Unsupported PCAP header")
        pos = 24
        while pos < len(data):
            if len(data) - pos < 16:
                raise ValueError("Truncated packet header")
            _, _, size, original = struct.unpack_from(endian + "IIII", data, pos)
            if size > snaplen or size > original or pos + 16 + size > len(data):
                raise ValueError("Invalid or truncated packet data")
            pos += 16 + size
            count += 1
            if count > max_packets:
                raise ValueError("Capture packet limit exceeded")
    elif magic == b"\x0a\x0d\x0d\x0a":
        pos, endian, blocks = 0, None, 0
        interfaces = []
        while pos < len(data):
            if len(data) - pos < 12:
                raise ValueError("Truncated PCAPNG block")
            if data[pos : pos + 4] == magic:
                bom = data[pos + 8 : pos + 12]
                endian = (
                    "<"
                    if bom == b"\x4d\x3c\x2b\x1a"
                    else ">"
                    if bom == b"\x1a\x2b\x3c\x4d"
                    else None
                )
            if endian is None:
                raise ValueError("Invalid PCAPNG byte order")
            kind, size = struct.unpack_from(endian + "II", data, pos)
            if (
                size < 12
                or size % 4
                or pos + size > len(data)
                or struct.unpack_from(endian + "I", data, pos + size - 4)[0] != size
            ):
                raise ValueError("Invalid or truncated PCAPNG block")
            if kind == 0x0A0D0D0A:
                if size < 28:
                    raise ValueError("Truncated PCAPNG section")
                major, minor = struct.unpack_from(endian + "HH", data, pos + 12)
                if (major, minor) != (1, 0):
                    raise ValueError("Unsupported PCAPNG section")
                interfaces = []
            if kind == 1:
                if size < 20:
                    raise ValueError("Truncated PCAPNG interface")
                snaplen = struct.unpack_from(endian + "I", data, pos + 12)[0]
                if snaplen > 16 * 1024 * 1024:
                    raise ValueError("PCAPNG interface snapshot limit exceeded")
                interfaces.append(snaplen)
            if kind in (2, 3, 6):
                minimum = 16 if kind == 3 else 32
                if size < minimum:
                    raise ValueError("Truncated PCAPNG packet")
                if kind == 3:
                    interface = 0
                    original = struct.unpack_from(endian + "I", data, pos + 8)[0]
                    if not interfaces:
                        raise ValueError("Packet references a missing interface")
                    captured = min(original, interfaces[0] or original)
                    header = 12
                else:
                    interface = struct.unpack_from(
                        endian + ("H" if kind == 2 else "I"), data, pos + 8
                    )[0]
                    captured, original = struct.unpack_from(endian + "II", data, pos + 20)
                    header = 28
                if interface >= len(interfaces):
                    raise ValueError("Packet references a missing interface")
                padded = (captured + 3) & ~3
                if (
                    captured > original
                    or (interfaces[interface] and captured > interfaces[interface])
                    or header + padded + 4 > size
                ):
                    raise ValueError("Invalid PCAPNG packet length")
                if kind == 3 and header + padded + 4 != size:
                    raise ValueError("Invalid PCAPNG simple packet padding")
                count += 1
            blocks += 1
            if count > max_packets or blocks > max_packets * 4:
                raise ValueError("Capture block limit exceeded")
            pos += size
    else:
        raise ValueError("File is not a PCAP or PCAPNG capture")
    if not count:
        raise ValueError("Capture contains no packets")
