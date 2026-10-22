"""Packet parser for PacketLens.

Decodes Ethernet, IPv4/IPv6, TCP, UDP, ICMP, and DNS layers.

Design principles:
- Never assume every packet contains every layer.
- Never assume the payload is readable (encrypted / truncated traffic).
- Return a plain dataclass so consumers (console, CSV, tests) stay decoupled.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Packet


@dataclass
class ParsedPacket:
    """Flat record of decoded packet metadata."""

    timestamp: str = ""
    src_mac: str = ""
    dst_mac: str = ""
    ethertype: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    protocol: str = "Other"
    src_port: str = ""
    dst_port: str = ""
    flags: str = ""
    length: int = 0
    payload_preview: str = ""
    dns_query: str = ""


def _format_timestamp(pkt: Packet) -> str:
    """Best-effort timestamp from a Scapy packet (float epoch or datetime)."""
    try:
        t = pkt.time
        if isinstance(t, datetime):
            return t.strftime("%H:%M:%S.%f")[:-3]
        return datetime.fromtimestamp(float(t)).strftime("%H:%M:%S.%f")[:-3]
    except (AttributeError, TypeError, ValueError):
        return ""


def _safe_payload(pkt: Packet, max_bytes: int = 96) -> str:
    """Return a bounded, safe preview of a payload.

    Encrypted or binary traffic is shown as hex; non-printable bytes become dots.
    """
    try:
        raw = bytes(pkt.payload) if pkt.payload else b""
    except Exception:
        return ""
    if not raw:
        return ""
    preview = raw[:max_bytes]
    hex_part = " ".join(f"{b:02x}" for b in preview)
    ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in preview)
    truncated = "..." if len(raw) > max_bytes else ""
    return f"{hex_part}  |{ascii_part}|{truncated}"


def _protocol_name(proto_num) -> str:
    """Map an IP protocol number to a readable name."""
    mapping = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
        47: "GRE",
        58: "ICMPv6",
        89: "OSPF",
    }
    try:
        return mapping.get(int(proto_num), str(proto_num))
    except (TypeError, ValueError):
        return str(proto_num)


def parse_packet(pkt: Packet) -> ParsedPacket:
    """Parse a Scapy packet into a :class:`ParsedPacket` record."""
    record = ParsedPacket()
    record.timestamp = _format_timestamp(pkt)

    # Link layer: Ethernet
    if pkt.haslayer(Ether):
        eth = pkt.getlayer(Ether)
        record.src_mac = eth.src
        record.dst_mac = eth.dst
        record.ethertype = hex(eth.type)

    # Network layer: IPv4 or IPv6 (whichever is present)
    ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
    if ip_layer:
        record.src_ip = ip_layer.src
        record.dst_ip = ip_layer.dst
        record.length = len(pkt)

        if isinstance(ip_layer, IP):
            record.protocol = _protocol_name(ip_layer.proto)
        elif isinstance(ip_layer, IPv6):
            record.protocol = _protocol_name(ip_layer.nh)

    # Transport / application layers (only one transport layer is expected)
    if pkt.haslayer(TCP):
        tcp = pkt.getlayer(TCP)
        record.src_port = str(tcp.sport)
        record.dst_port = str(tcp.dport)
        record.flags = tcp.sprintf("%TCP.flags%")
        record.protocol = "TCP"
        record.payload_preview = _safe_payload(tcp.payload)

    elif pkt.haslayer(UDP):
        udp = pkt.getlayer(UDP)
        record.src_port = str(udp.sport)
        record.dst_port = str(udp.dport)
        record.protocol = "UDP"
        record.payload_preview = _safe_payload(udp.payload)

        # DNS decode where present
        if pkt.haslayer(DNS):
            dns = pkt.getlayer(DNS)
            record.protocol = "DNS"
            try:
                if dns.qr == 0 and dns.qd:
                    record.dns_query = dns.qd.qname.decode(errors="replace")
            except AttributeError:
                pass

    elif pkt.haslayer(ICMP):
        icmp = pkt.getlayer(ICMP)
        record.protocol = "ICMP"
        record.flags = f"type={icmp.type} code={icmp.code}"
        record.payload_preview = _safe_payload(icmp.payload)

    return record
