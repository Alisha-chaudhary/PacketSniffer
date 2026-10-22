"""Unit tests for the PacketLens packet parser.

Run with:  python tests/test_parser.py   (from the PacketLens root)
           python -m tests.test_parser   (from the PacketLens root)
"""

from __future__ import annotations

import os
import sys
from datetime import datetime

# Ensure the PacketLens root is importable whether run as a script or module.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.parser import ParsedPacket, _protocol_name, parse_packet


class MinimalPkt:
    """A minimal fake Scapy-like packet with no decoded layers."""

    def __init__(self) -> None:
        self.time = datetime.now()
        self.payload = None

    def haslayer(self, cls):  # noqa: ARG002
        return False

    def getlayer(self, cls):  # noqa: ARG002
        return None


def test_parsed_packet_defaults():
    rec = ParsedPacket()
    assert rec.protocol == "Other"
    assert rec.src_ip == ""
    assert rec.length == 0


def test_protocol_name_mapping():
    assert _protocol_name(6) == "TCP"
    assert _protocol_name(17) == "UDP"
    assert _protocol_name(1) == "ICMP"
    assert _protocol_name(58) == "ICMPv6"
    assert _protocol_name(99) == "99"


def test_parse_packet_no_layers_does_not_crash():
    rec = parse_packet(MinimalPkt())
    assert isinstance(rec, ParsedPacket)
    assert rec.protocol == "Other"
    assert rec.timestamp  # timestamp should be populated


def test_bound_payload_truncation():
    try:  # package execution
        from src.filters import bound_payload
    except ImportError:
        from filters import bound_payload

    short = "48 65 6c 6c 6f"
    assert bound_payload(short) == short
    long_str = "a " * 200
    result = bound_payload(long_str, max_chars=10)
    assert len(result) == 11  # 10 chars + ellipsis
    assert result.endswith("\u2026")


FAILURES = []


def _check(name, condition):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {name}")
    if not condition:
        FAILURES.append(name)


if __name__ == "__main__":
    _check("defaults", ParsedPacket().protocol == "Other")
    _check("protocol mapping", _protocol_name(6) == "TCP")
    _check("no layers", parse_packet(MinimalPkt()).protocol == "Other")

    try:
        from scapy.all import IP, TCP, UDP, Raw  # type: ignore

        pkt = (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=44331, dport=443, flags="SA")
            / Raw(load=b"GET / HTTP/1.1")
        )
        rec = parse_packet(pkt)
        _check("real tcp parse", rec.protocol == "TCP")
        _check("real tcp src ip", rec.src_ip == "10.0.0.1")
        _check("real tcp dst port", rec.dst_port == "443")
        _check("real tcp flags", "S" in rec.flags)
        _check("real tcp length", rec.length > 0)

        dns_pkt = (
            IP(src="10.0.0.1", dst="1.1.1.1")
            / UDP(sport=51235, dport=53)
        )
        _check("real udp parse", parse_packet(dns_pkt).protocol == "UDP")

    except ImportError:
        print("[i] scapy not installed; skipping live-packet integration tests")

    if FAILURES:
        print(f"\n{len(FAILURES)} test(s) failed: {FAILURES}")
        raise SystemExit(1)
    print("\nAll parser tests passed.")
