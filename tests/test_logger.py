"""Unit tests for the PacketLens CSV logger.

Run with:  python tests/test_logger.py   (from the PacketLens root)
           python -m tests.test_logger   (from the PacketLens root)
"""

from __future__ import annotations

import os
import sys
import tempfile

# Ensure the PacketLens root is importable whether run as a script or module.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.logger import PacketLogger
from src.parser import ParsedPacket


def _sample_packet(protocol="TCP", src_ip="10.0.0.1", dst_ip="10.0.0.2"):
    return ParsedPacket(
        timestamp="12:00:00.000",
        src_mac="aa:bb:cc:dd:ee:ff",
        dst_mac="11:22:33:44:55:66",
        ethertype="0x800",
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        src_port="12345",
        dst_port="80",
        flags="SA",
        length=66,
        dns_query="",
        payload_preview="48 65 6c 6c 6f  |Hello|",
    )


FAILURES = []


def _check(name, condition):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {name}")
    if not condition:
        FAILURES.append(name)


def test_logger_writes_header_and_rows():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "capture_log.csv")
        logger = PacketLogger(path=path)
        logger.log(_sample_packet("TCP"))
        logger.log(_sample_packet("DNS", src_ip="10.0.0.1", dst_ip="1.1.1.1"))
        logger.close()

        with open(path, encoding="utf-8") as fh:
            content = fh.read()

        _check("header present", "timestamp" in content and "src_ip" in content and "protocol" in content)
        _check("tcp row present", "10.0.0.1,10.0.0.2,TCP" in content)
        _check("dns row present", "10.0.0.1,1.1.1.1,DNS" in content)
        _check("two data rows", content.count("\n") >= 2)


def test_logger_statistics():
    logger = PacketLogger()
    logger.log(_sample_packet("TCP"))
    logger.log(_sample_packet("TCP"))
    logger.log(_sample_packet("UDP"))
    logger.close()

    _check("packet count", logger.packet_count == 3)
    _check("tcp count", logger.protocol_counts["TCP"] == 2)
    _check("udp count", logger.protocol_counts["UDP"] == 1)
    summary = logger.summary()
    _check("summary has total", "Total packets:  3" in summary)
    _check("summary has tcp", "- TCP: 2" in summary)


if __name__ == "__main__":
    test_logger_writes_header_and_rows()
    test_logger_statistics()

    if FAILURES:
        print(f"\n{len(FAILURES)} test(s) failed: {FAILURES}")
        raise SystemExit(1)
    print("\nAll logger tests passed.")
