# Security Policy

## Supported versions

The current release of PacketLens is the only supported version. Security updates are issued as needed on the `main` branch.

## Reporting a vulnerability

If you discover a security issue in PacketLens, please:

1. Do **not** create a public issue.
2. Email alisha.cybersec@gmail.com with details, steps to reproduce, and suggested remediation.
3. Allow a reasonable investigation window before public disclosure.

## Safe-by-design notes

- PacketLens performs **read-only** packet capture. It does not inject, modify, or spoof traffic.
- No network calls are made by the tool itself (except the traffic you choose to capture).
- Sample output in `samples/` contains **sanitised, synthetic** data only — no real IPs, hostnames, or credentials.
- The tool does not log or transmit any captured data to the author or any third party.

## Dependency policy

`requirements.txt` pins only `scapy`. Review and pin transitive dependencies before using PacketLens in a regulated environment.
