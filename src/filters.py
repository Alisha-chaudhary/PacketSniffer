"""Capture and display filters for PacketLens.

Provides:
- BPF capture-filter name -> string resolution
- TCP-flag decoding into human-readable labels
- DNS-query detection
- Safe payload-preview bounding for console / CSV output
"""

from __future__ import annotations

from typing import Optional

# Common BPF capture filters for authorised traffic inspection.
# Empty string means "no filter" (capture everything).
BPF_FILTERS: dict[str, str] = {
    "none": "",
    "tcp": "tcp",
    "udp": "udp",
    "icmp": "icmp",
    "dns": "udp port 53",
    "http": "tcp port 80",
    "https": "tcp port 443",
    "icmpv6": "icmp6",
}


def build_bpf_filter(name: str) -> Optional[str]:
    """Return a BPF filter string by name.

    Returns ``None`` for unknown names so callers can fall back to "none".
    Returns ``""`` for "none", meaning no capture filter.
    """
    return BPF_FILTERS.get(name.lower())


def decode_tcp_flags(flags_str: str) -> str:
    """Decode a Scapy TCP flags string into human-readable labels.

    Example: "SA" -> "SYN, ACK"
    """
    label_map = {
        "F": "FIN",
        "S": "SYN",
        "R": "RST",
        "P": "PSH",
        "A": "ACK",
        "U": "URG",
        "E": "ECE",
        "C": "CWR",
    }
    decoded = [label_map.get(ch, ch) for ch in flags_str]
    return ", ".join(decoded) if decoded else "None"


def is_dns_query(dns_layer) -> bool:
    """Return True when a DNS layer represents a query (not a response)."""
    try:
        return dns_layer.qr == 0
    except AttributeError:
        return False


def bound_payload(preview: str, max_chars: int = 120) -> str:
    """Bound a payload-preview string for safe console / CSV output."""
    if not preview:
        return ""
    return (preview[:max_chars] + "\u2026") if len(preview) > max_chars else preview
