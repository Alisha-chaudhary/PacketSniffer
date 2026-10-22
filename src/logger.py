"""CSV logging and statistics for PacketLens.

Writes packet metadata to CSV and tracks protocol counts and traffic summary.
"""

from __future__ import annotations

import csv
import os
from collections import Counter
from typing import Iterable, Optional

try:  # package execution (python -m src.main or src/main.py from root)
    from src.parser import ParsedPacket
except ImportError:  # direct execution (python src/main.py)
    from parser import ParsedPacket


class PacketLogger:
    """Logs parsed packets to CSV and maintains capture statistics."""

    FIELDNAMES = [
        "timestamp",
        "src_mac",
        "dst_mac",
        "ethertype",
        "src_ip",
        "dst_ip",
        "protocol",
        "src_port",
        "dst_port",
        "flags",
        "length",
        "dns_query",
        "payload_preview",
    ]

    def __init__(self, path: str = "capture_log.csv") -> None:
        self.path = path
        self.protocol_counts: Counter[str] = Counter()
        self.total_bytes: int = 0
        self.packet_count: int = 0
        self._file: Optional[csv.DictWriter] = None  # type: ignore[assignment]
        self._writer: Optional[csv.DictWriter] = None
        self._opened = False

    def open(self) -> None:
        """Open the CSV file and write the header row if needed."""
        if self._opened:
            return
        new_file = (
            not os.path.exists(self.path)
            or os.path.getsize(self.path) == 0
        )
        self._file = open(self.path, mode="a", newline="", encoding="utf-8")
        self._writer = csv.DictWriter(self._file, fieldnames=self.FIELDNAMES)
        if new_file:
            self._writer.writeheader()
        self._opened = True

    def log(self, packet: ParsedPacket) -> None:
        """Write one parsed packet to the CSV and update statistics."""
        self.open()
        assert self._writer is not None
        row = {
            "timestamp": packet.timestamp,
            "src_mac": packet.src_mac,
            "dst_mac": packet.dst_mac,
            "ethertype": packet.ethertype,
            "src_ip": packet.src_ip,
            "dst_ip": packet.dst_ip,
            "protocol": packet.protocol,
            "src_port": packet.src_port,
            "dst_port": packet.dst_port,
            "flags": packet.flags,
            "length": packet.length,
            "dns_query": packet.dns_query,
            "payload_preview": packet.payload_preview,
        }
        self._writer.writerow(row)
        self.protocol_counts[packet.protocol] += 1
        self.total_bytes += packet.length or 0
        self.packet_count += 1

    def log_batch(self, packets: Iterable[ParsedPacket]) -> None:
        """Log multiple packets efficiently."""
        for pkt in packets:
            self.log(pkt)

    def summary(self) -> str:
        """Return a human-readable traffic summary."""
        lines = [
            "=== Capture Statistics ===",
            f"Total packets:  {self.packet_count}",
            f"Total bytes:    {self.total_bytes}",
            "Protocol breakdown:",
        ]
        if self.protocol_counts:
            for proto, count in self.protocol_counts.most_common():
                lines.append(f"  - {proto}: {count}")
        else:
            lines.append("  (none)")
        lines.append(f"Log file: {self.path}")
        return "\n".join(lines)

    def close(self) -> None:
        """Close the CSV file if open."""
        if self._file is not None and not self._file.closed:
            self._file.close()
        self._opened = False

    def __enter__(self) -> "PacketLogger":
        self.open()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
