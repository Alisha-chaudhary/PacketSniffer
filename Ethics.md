# Ethics - Authorised Use Policy

## Purpose

PacketLens is a defensive, educational network-analysis tool. It is designed to help learners and security practitioners understand packet anatomy, protocols, and communication flows on networks they are authorised to monitor.

## Authorised capture only

You may use PacketLens only on:

- Networks you own or administer, **or**
- Networks where you have **explicit written permission** to capture and analyse traffic

You must **not** use PacketLens to:

- Intercept or record credentials, session cookies, or personal communications
- Monitor third-party, corporate, or public networks without authorisation
- Capture traffic belonging to individuals who have not consented

## Privacy and data handling

- Captured metadata (IPs, ports, protocol, length, timestamps) is written to a local CSV file only.
- Payload previews are intentionally small (default 96 bytes) and are never transmitted anywhere.
- Encrypted application content (for example TLS/HTTPS) is not decrypted or exposed.
- Delete sample and capture files before sharing or publishing any evidence.

## Legal notice

Packet capture may be regulated by law in your jurisdiction. The author and contributors are not responsible for misuse, legal violations, or any damage resulting from unauthorised use of this tool.

If you are unsure whether your use case is authorised, consult your organisation's security policy or legal counsel before running PacketLens.

## Reporting concerns

If you believe this project could be misused, or if you have questions about responsible use, open an issue in this repository rather than deploying it in an unauthorised context.
