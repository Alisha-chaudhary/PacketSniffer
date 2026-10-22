"""PacketLens - authorised network packet capture & analysis.

CLI entry point for live capture using Scapy (Npcap on Windows).

Usage:
    python src/main.py
    python src/main.py -c 50 -f tcp -o capture_log.csv
"""

from __future__ import annotations

import argparse
import sys

try:  # package execution
    from src.capture import CaptureEngine
    from src.filters import build_bpf_filter, decode_tcp_flags, bound_payload
    from src.logger import PacketLogger
    from src.parser import ParsedPacket, parse_packet
except ImportError:  # direct execution: python src/main.py
    from capture import CaptureEngine
    from filters import build_bpf_filter, decode_tcp_flags, bound_payload
    from logger import PacketLogger
    from parser import ParsedPacket, parse_packet


def display_packet(record: ParsedPacket) -> None:
    """Print a single decoded packet to the console."""
    if record.protocol == "TCP" and record.flags:
        flags = decode_tcp_flags(record.flags)
    else:
        flags = record.flags or ""
    print(
        f"{record.timestamp} | {record.protocol:<5} | "
        f"{record.src_ip:<15}:{record.src_port:>5} -> "
        f"{record.dst_ip:<15}:{record.dst_port:>5} | "
        f"len={record.length} | flags={flags}"
    )
    if record.dns_query:
        print(f"    DNS query: {record.dns_query}")
    if record.payload_preview:
        print(f"    payload: {bound_payload(record.payload_preview)}")


def run() -> int:
    parser = argparse.ArgumentParser(
        description="PacketLens: authorised network packet capture and analysis"
    )
    parser.add_argument(
        "-i",
        "--interface",
        help="Capture interface (default: Scapy default)",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=0,
        help="Max packets to capture (0 = unlimited)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=None,
        help="Stop capturing after N seconds",
    )
    parser.add_argument(
        "-f",
        "--filter",
        default="none",
        help=(
            "BPF capture-filter name: tcp, udp, icmp, dns, http, https, "
            "icmpv6, none (default: none)"
        ),
    )
    parser.add_argument(
        "-o",
        "--output",
        default="capture_log.csv",
        help="CSV output path (default: capture_log.csv)",
    )
    args = parser.parse_args()

    engine = CaptureEngine()
    engine.list_interfaces()
    engine.select_interface(args.interface)

    bpf = build_bpf_filter(args.filter)
    if bpf is None:
        print(f"[!] Unknown filter '{args.filter}', using 'none'")
        bpf = ""

    logger = PacketLogger(path=args.output)

    def on_packet(pkt) -> None:
        record = parse_packet(pkt)
        logger.log(record)
        display_packet(record)

    try:
        with logger:
            engine.capture(
                callback=on_packet,
                count=args.count,
                timeout=args.timeout,
                bpf_filter=bpf,
            )
    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")
    except PermissionError:
        print(
            "[!] Run as Administrator (Npcap requires elevated privileges "
            "on Windows)."
        )
        return 1
    except OSError as exc:
        print(f"[!] Capture failed: {exc}")
        return 1
    finally:
        print("\n" + logger.summary())

    return 0


if __name__ == "__main__":
    sys.exit(run())
