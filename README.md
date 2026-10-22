# PacketSniffer 📡

## Authorised Network Packet Capture & Analysis

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)](https://www.microsoft.com/windows)
[![Scapy](https://img.shields.io/badge/Scapy-packet%20capture-green)](https://scapy.net/)
[![Npcap](https://img.shields.io/badge/Npcap-Windows%20capture-purple)](https://npcap.com/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-success)](https://github.com/Alisha-chaudhary/PacketLens)

PacketSniffer is a lightweight, educational network-sniffing tool built in Python with **Scapy** (Npcap on Windows). It captures authorised traffic, decodes packet structure across the link, network, transport, and application layers, and logs metadata to CSV for defensive analysis and troubleshooting.

> **Engineering goal:** learn how packets move through a network - Ethernet → IPv4/IPv6 → TCP/UDP/ICMP → DNS — and understand what metadata is visible (and what stays hidden, such as encrypted HTTPS payloads).

---

## 🛡️ What PacketSniffer Does

| Phase | Capability |
|-------|------------|
| **Capture** | Live packet capture on a selected interface; graceful shutdown on Ctrl+C |
| **Parse** | Decodes Ethernet, IPv4/IPv6, TCP, UDP, ICMP, and DNS layers |
| **Inspect** | TCP flags, DNS queries, bounded safe payload previews |
| **Filter** | BPF capture filters (tcp, udp, dns, http, https, icmp, none) |
| **Log** | CSV export of every packet + protocol counts and traffic summary |
| **Validate** | Unit tests for parser and logger |

---

## 🚀 Quick Start

### 1. Clone and install

```bash
git clone https://github.com/Alisha-chaudhary/PacketSniffer.git
cd PacketSniffer

python -m venv .venv
.venv\Scripts\activate

pip install -r requirements.txt
```

### 2. Install Npcap (Windows)

Scapy on Windows requires [Npcap](https://npcap.com/) in **WinPcap API-compatible mode**. Install it and run your terminal / VS Code as **Administrator**.

### 3. Run the capture

```bash
# List interfaces, then capture on the default interface
python src/main.py

# Capture 50 TCP packets only
python src/main.py -c 50 -f tcp

# Capture DNS traffic for 30 seconds
python src/main.py -f dns -t 30

# Write to a custom CSV
python src/main.py -o my_capture.csv
```

Press **Ctrl+C** at any time to stop gracefully and view the traffic summary.

---

## 🧩 Project Structure

```
PacketSniffers/
├── .github/workflows/          # CI workflow (runs tests)
├── screenshots/                # Demo screenshots (add your own)
├── samples/                    # Sanitised sample capture output
├── src/
│   ├── main.py                 # CLI entry point
│   ├── capture.py              # Live capture engine (Scapy)
│   ├── parser.py               # Packet header / payload decoder
│   ├── filters.py              # BPF filters, TCP flags, DNS detection
│   └── logger.py               # CSV logging + statistics
├── tests/
│   ├── test_parser.py
│   └── test_logger.py
├── .gitignore
├── Ethics.md                   # Authorised-use policy
├── Security.md                 # Security policy
├── requirements.txt
└── README.md
```

---

## 🏗️ Architecture

```
Network interface (Wi-Fi / Ethernet)
        │
        ▼
Npcap driver (Windows)
        │
        ▼
Scapy sniff()  ──►  capture.py  ──►  parser.py
        │                          │
        ▼                          ▼
   filters.py                  ParsedPacket
        │                          │
        ▼                          ▼
   logger.py  ──►  capture_log.csv
        │
        ▼
   Console (live packet details)
```

Scapy parses whichever layers are present in each packet. PacketSniffer does **not** assume every packet contains every layer, and does **not** assume the payload is readable. Encrypted traffic, capture filters, interface choice, and packet truncation all affect what is observed.

---

## 🔎 Core Modules

| Module | Purpose |
|--------|---------|
| `capture.py` | Interface selection, live capture, BPF filters, graceful shutdown, error handling |
| `parser.py` | Ethernet, IPv4/IPv6, TCP, UDP, ICMP, DNS decoding; bounded payload preview |
| `filters.py` | BPF filter names, TCP-flag labels, DNS-query detection, payload bounding |
| `logger.py` | CSV logging, protocol counts, traffic summary, context-manager support |

---

## 📊 Sample Output

Sanitised sample capture (`samples/sample_output.csv`):

```csv
timestamp,src_ip,dst_ip,protocol,src_port,dst_port,flags,length,dns_query
14:22:01.104,192.168.1.45,93.184.216.34,TCP,51234,443,SA,66,
14:22:01.105,192.168.1.45,1.1.1.1,UDP,51235,53,,78,example.com
14:22:01.106,192.168.1.1,192.168.1.45,ICMP,,,type=8 code=0,56,
```

Console view:

```text
14:22:01.104 | TCP   | 192.168.1.45:51234  -> 93.184.216.34:443   | len=66 | flags=SYN, ACK
14:22:01.105 | DNS   | 192.168.1.45:51235  -> 1.1.1.1:53        | len=78 | DNS query: example.com
14:22:01.106 | ICMP  | 192.168.1.1:        -> 192.168.1.45:      | len=56 | flags=type=8 code=0
```

---

## 🛠️ Built With

- **Python** — core language
- **Scapy** — packet capture and dissection
- **Npcap** — Windows packet-capture driver
- **csv** — metadata export
- **argparse** — CLI

---

## ⚖️ Authorised Testing Only

PacketSniffer is intended for **authorised security testing, network troubleshooting, and educational use**.

- Only capture traffic on networks you own or have explicit written permission to monitor.
- Do not capture credentials, personal data, or third-party traffic without authorisation.
- Payload previews are intentionally bounded; encrypted traffic (TLS/HTTPS) exposes metadata only.
- The author is not responsible for misuse of this project.

See [`Ethics.md`](Ethics.md) and [`Security.md`](Security.md) for full policies.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## 🗺️ Roadmap

- [x] MVP: live capture, IP/port/protocol, payload preview, CSV logging
- [x] Interface selection, BPF filters, TCP flags, DNS decoding
- [ ] Unit tests + CI
- [ ] Configuration file (YAML/JSON)
- [ ] PCAP file analysis (offline mode)
- [ ] HTML/text report generation
- [ ] Windows installer / portable distribution

---

**Built by Alisha-chaudhary** · Cybersecurity Analyst · Threat Intelligence · Detection Engineering
