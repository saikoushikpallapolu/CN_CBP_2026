"""Versioned packet parsing and flow representation shared by training and serving.

No protocol objects or image codecs are used in the inference path. Unsupported
link types and malformed records fail closed. Partial trailing records are allowed
only for explicitly marked historical slices.
"""
from __future__ import annotations

import io
import os
import mmap
import socket
import struct
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path

import numpy as np
try:
    import traffic_native as _native
except ImportError:
    _native = None

REPRESENTATION = "sanitized-flow-v1"
PACKETS_PER_FLOW = 16
BYTES_PER_PACKET = 32


@dataclass
class Packet:
    timestamp: float
    raw: bytes
    source: str
    destination: str
    sport: int
    dport: int
    protocol: int
    network_offset: int
    transport_offset: int
    version: int

    @property
    def key(self):
        return (self.protocol, *sorted(((self.source, self.sport), (self.destination, self.dport))))


def parse_packet(raw: bytes, timestamp: float, linktype: int = 1) -> Packet | None:
    if linktype == 1:
        if len(raw) < 14:
            return None
        offset, ethertype = 14, int.from_bytes(raw[12:14], "big")
        while ethertype in (0x8100, 0x88a8):
            if len(raw) < offset + 4:
                return None
            ethertype = int.from_bytes(raw[offset + 2:offset + 4], "big")
            offset += 4
        if ethertype not in (0x800, 0x86dd):
            return None
    elif linktype in (113, 276):
        offset = 16 if linktype == 113 else 20
        if len(raw) < offset:
            return None
        ethertype = int.from_bytes(raw[14:16] if linktype == 113 else raw[:2], "big")
        if ethertype not in (0x800, 0x86dd):
            return None
    elif linktype in (101, 228, 229):
        offset = 0
    else:
        raise ValueError(f"Unsupported capture link type: {linktype}")
    if len(raw) <= offset:
        return None
    version = raw[offset] >> 4
    if version == 4:
        if len(raw) < offset + 20:
            return None
        ihl = (raw[offset] & 15) * 4
        if ihl < 20 or len(raw) < offset + ihl:
            return None
        # Non-initial fragments do not contain transport ports.
        if int.from_bytes(raw[offset + 6:offset + 8], "big") & 0x1fff:
            return None
        source = socket.inet_ntop(socket.AF_INET, raw[offset + 12:offset + 16])
        destination = socket.inet_ntop(socket.AF_INET, raw[offset + 16:offset + 20])
        protocol, transport = raw[offset + 9], offset + ihl
    elif version == 6:
        if len(raw) < offset + 40:
            return None
        source = socket.inet_ntop(socket.AF_INET6, raw[offset + 8:offset + 24])
        destination = socket.inet_ntop(socket.AF_INET6, raw[offset + 24:offset + 40])
        protocol, transport = raw[offset + 6], offset + 40
        # Fail closed for extension headers until they are explicitly supported.
        if protocol not in (6, 17, 58):
            return None
    else:
        return None
    sport = dport = 0
    if protocol in (6, 17):
        if len(raw) < transport + (20 if protocol == 6 else 8):
            return None
        sport, dport = struct.unpack_from("!HH", raw, transport)
    return Packet(timestamp, raw, source, destination, sport, dport, protocol, offset, transport, version)


def sanitize(packet: Packet) -> bytes:
    data = bytearray(packet.raw)
    n, t = packet.network_offset, packet.transport_offset
    if n == 16:
        data[6:14] = bytes(8)  # Linux cooked v1 hardware address
    elif n == 20:
        data[4:8] = bytes(4)  # Linux cooked v2 interface index
        data[12:20] = bytes(8)
    elif n:
        data[:12] = bytes(12)
    if packet.version == 4:
        data[n + 4:n + 6] = bytes(2)  # IP identifier can identify capture hosts.
        data[n + 10:n + 20] = bytes(10)  # checksum and addresses
    else:
        data[n + 1:n + 4] = bytes(3)  # flow identifier
        data[n + 8:n + 40] = bytes(32)
    if packet.protocol in (6, 17):
        for offset in (t, t + 2):
            if int.from_bytes(data[offset:offset + 2], "big") > 1024:
                data[offset:offset + 2] = bytes(2)
        if packet.protocol == 6:
            data[t + 4:t + 12] = bytes(8)  # sequence and acknowledgement identities
            data[t + 16:t + 18] = bytes(2)
            # TCP timestamps also encode host uptime; remove option values.
            header_end = min(len(data), t + ((data[t + 12] >> 4) * 4))
            cursor = t + 20
            while cursor < header_end:
                kind = data[cursor]
                if kind == 0:
                    break
                if kind == 1:
                    cursor += 1
                    continue
                if cursor + 1 >= header_end:
                    break
                length = data[cursor + 1]
                if length < 2 or cursor + length > header_end:
                    break
                if kind == 8:
                    data[cursor + 2:cursor + length] = bytes(length - 2)
                cursor += length
        else:
            data[t + 6:t + 8] = bytes(2)
    return bytes(data)


def packet_features(packet: Packet) -> bytes:
    """32 invariant bytes: network framing, transport flags/window and payload.

    Taking only the first 32 Ethernet bytes would mostly preserve masked zeros
    and never reach TCP flags. This protocol-aware layout avoids that defect.
    """
    data = sanitize(packet)
    n, t = packet.network_offset, packet.transport_offset
    network = data[n:n + 12] if packet.version == 4 else data[n:n + 8].ljust(12, b"\0")
    if packet.protocol == 6:
        transport = data[t:t + 4] + data[t + 12:t + 16]
        payload = t + max(20, (data[t + 12] >> 4) * 4)
    elif packet.protocol == 17:
        transport, payload = data[t:t + 8], t + 8
    else:
        transport, payload = data[t:t + 8], t + 8
    return (network + transport.ljust(8, b"\0") + data[payload:payload + 12]).ljust(32, b"\0")[:32]


def read_capture(source, max_packets=200000, allow_truncated=False):
    """Stream classic PCAP and PCAPNG (section/interface/enhanced/simple blocks)."""
    owned = isinstance(source, (str, Path))
    stream = open(source, "rb") if owned else source
    try:
        magic = stream.read(4)
        formats = {b"\xd4\xc3\xb2\xa1": ("<", 1e6), b"\xa1\xb2\xc3\xd4": (">", 1e6),
                   b"\x4d\x3c\xb2\xa1": ("<", 1e9), b"\xa1\xb2\x3c\x4d": (">", 1e9)}
        count = 0
        if magic in formats:
            if _native is not None and hasattr(_native, "read_pcap"):
                try:
                    descriptor = stream.fileno()
                    size = os.fstat(descriptor).st_size
                except (OSError, io.UnsupportedOperation, AttributeError):
                    size = 0
                # Bound copied Python records; large training archives stream.
                if 24 <= size <= 64 * 1024 ** 2 and max_packets <= 200001:
                    with mmap.mmap(descriptor, 0, access=mmap.ACCESS_READ) as mapped:
                        rows = _native.read_pcap(mapped, max_packets, allow_truncated)
                    yield from rows
                    return
            endian, scale = formats[magic]
            header = stream.read(20)
            if len(header) != 20:
                raise ValueError("Truncated PCAP header")
            linktype = struct.unpack(endian + "HHIIII", header)[-1] & 0xffff
            while count < max_packets:
                header = stream.read(16)
                if not header:
                    return
                if len(header) != 16:
                    if allow_truncated:
                        return
                    raise ValueError("Truncated PCAP record")
                seconds, fraction, length, original = struct.unpack(endian + "IIII", header)
                if length > 16 * 1024 * 1024 or length > original:
                    raise ValueError("Invalid PCAP record length")
                raw = stream.read(length)
                if len(raw) != length:
                    if allow_truncated:
                        return
                    raise ValueError("Truncated packet payload")
                count += 1
                yield seconds + fraction / scale, raw, linktype
        elif magic == b"\x0a\x0d\x0d\x0a":
            stream.seek(-4, io.SEEK_CUR)
            endian, interfaces = "<", []
            while count < max_packets:
                header = stream.read(8)
                if not header:
                    return
                if len(header) != 8:
                    if allow_truncated:
                        return
                    raise ValueError("Truncated PCAPNG block")
                if header[:4] == b"\x0a\x0d\x0d\x0a":
                    bom = stream.read(4)
                    if bom not in (b"\x4d\x3c\x2b\x1a", b"\x1a\x2b\x3c\x4d"):
                        raise ValueError("Invalid PCAPNG byte order")
                    endian = "<" if bom[0] == 0x4d else ">"
                    length = struct.unpack(endian + "I", header[4:])[0]
                    prefix = bom
                    interfaces = []
                else:
                    length, prefix = struct.unpack(endian + "I", header[4:])[0], b""
                if length < 12 + len(prefix) or length > 16 * 1024 * 1024 or length % 4:
                    raise ValueError("Invalid PCAPNG block length")
                tail = stream.read(length - 8 - len(prefix))
                if len(tail) != length - 8 - len(prefix):
                    if allow_truncated:
                        return
                    raise ValueError("Truncated PCAPNG block")
                if struct.unpack(endian + "I", tail[-4:])[0] != length:
                    raise ValueError("Truncated or inconsistent PCAPNG block")
                body = prefix + tail[:-4]
                kind = struct.unpack(endian + "I", header[:4])[0]
                if kind == 1:
                    linktype = struct.unpack_from(endian + "H", body)[0]
                    resolution, offset = 1e-6, 0
                    cursor = 8
                    while cursor + 4 <= len(body):
                        code, size = struct.unpack_from(endian + "HH", body, cursor)
                        value = body[cursor + 4:cursor + 4 + size]
                        if code == 9 and size == 1:
                            resolution = (2 if value[0] & 128 else 10) ** -(value[0] & 127)
                        if code == 14 and size == 8:
                            offset = struct.unpack(endian + "q", value)[0]
                        cursor += 4 + ((size + 3) // 4) * 4
                    interfaces.append((linktype, resolution, offset))
                elif kind == 6:
                    if len(body) < 20:
                        raise ValueError("Invalid enhanced packet block")
                    interface, high, low, captured, original = struct.unpack_from(endian + "IIIII", body)
                    if interface >= len(interfaces) or captured > original or captured > len(body) - 20:
                        raise ValueError("Invalid PCAPNG packet")
                    linktype, resolution, offset = interfaces[interface]
                    count += 1
                    yield ((high << 32) | low) * resolution + offset, body[20:20 + captured], linktype
                elif kind == 3:
                    raise ValueError("PCAPNG simple packets lack timestamps; convert to enhanced blocks")
        else:
            raise ValueError("Invalid capture: expected PCAP or PCAPNG magic")
    finally:
        if owned:
            stream.close()


def flow_bursts(records, max_flows=2048, idle_seconds=30):
    """First 16 observed packets per session, bounded by idle time and table size.

    Completed sessions retain bounded tombstones so later packets do not become
    independent training samples from the same long-lived session.
    """
    active, completed = OrderedDict(), OrderedDict()
    for timestamp, raw, linktype in records:
        packet = parse_packet(raw, timestamp, linktype)
        if packet is None:
            continue
        key = packet.key
        if key in completed:
            previous = completed.pop(key)
            new_syn = packet.protocol == 6 and packet.raw[packet.transport_offset + 13] & 0x12 == 2
            if timestamp - previous <= idle_seconds and not new_syn:
                completed[key] = timestamp
                continue
        if key in active and timestamp - active[key][-1].timestamp > idle_seconds:
            yield active.pop(key)
        packets = active.pop(key, [])
        packets.append(packet)
        active[key] = packets
        if len(packets) == PACKETS_PER_FLOW:
            yield active.pop(key)
            completed[key] = timestamp
            if len(completed) > max_flows * 4:
                completed.popitem(last=False)
        if len(active) > max_flows:
            yield active.popitem(last=False)[1]
    yield from active.values()


def burst_array(packets):
    raw = b"".join(packet_features(p) for p in packets[:16]).ljust(512, b"\0")
    return np.frombuffer(raw, dtype=np.uint8).copy().reshape(16, 32)
