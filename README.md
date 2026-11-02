# NSHARK

[![CI](https://github.com/ixbm5/nshark/actions/workflows/ci.yml/badge.svg)](https://github.com/ixbm5/nshark/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

```text
 ███╗   ██╗███████╗██╗  ██╗ █████╗ ██████╗ ██╗  ██╗  v1.0.0 // APEX PCAP ENGINE
 ████╗  ██║██╔════╝██║  ██║██╔══██╗██╔══██╗██║ ██╔╝  Fast PCAP Analysis & Threat Intel
 ██╔██╗ ██║███████╗███████║███████║██████╔╝█████╔╝   ─────────────────────────────────
 ██║╚██╗██║╚════██║██╔══██║██╔══██║██╔══██╗██╔═██╗   [DET] Recon · Auth · C2 · Exfil · AD
 ██║ ╚████║███████║██║  ██║██║  ██║██║  ██║██║  ██╗  [EXT] IOC · DNS · HTTP · Carve
 ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝  [CTI] VT·AbuseIPDB·Shodan·OTX
```

CLI packet analyzer for threat hunting, CTF triage, and incident response. Pass a `.pcap` or `.pcapng` to surface behavioral detections, crackable authentication hashes, cleartext credentials, carved files, and IOCs directly in the terminal (~3,000 packets/sec).

Detections cover network reconnaissance, brute force and cleartext credentials, web exploits and reverse shells, C2 beaconing and TLS anomalies, DNS and data exfiltration, Layer-2 poisoning, and Active Directory lateral movement.

## Install

### Recommended (`pipx`)

Works on **Linux, macOS, and Windows** in an isolated environment:

```bash
pipx install git+https://github.com/ixbm5/nshark.git
```

### From Source (`venv`)

```bash
git clone https://github.com/ixbm5/nshark.git && cd nshark
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

## Quick Start

```bash
# Try it right away on the included multi-stage sample capture:
nshark samples/demo_attack.pcap
nshark hashes samples/demo_attack.pcap

# 1. Analyze any PCAP (detects attacks, maps to MITRE ATT&CK, builds timeline)
nshark capture.pcap

# 2. Extract crackable Hashcat hashes (NetNTLMv2, Kerberos, HTTP Digest, DBs)
nshark hashes capture.pcap -o hashes.txt

# 3. Passive host discovery (IP, MAC vendor, OS, hostname, open ports)
nshark hosts capture.pcap

# 4. Carve transferred files from network traffic
nshark carve capture.pcap -o ./carved
```

## Threat Intel Enrichment & Privacy (Optional)

`nshark` is **100% offline by default** and makes zero network requests unless `--enrich` or `nshark enrich` is explicitly used.

When enriching a file or PCAP, **files and packet captures are never uploaded**—`nshark` computes SHA-256 hashes locally and only queries public IP addresses, domain names, and hash digests (see **[SECURITY.md](SECURITY.md)**).

Configure API keys via hidden prompt (stored in `~/.nshark/.env` with `0600` permissions, never exposed in shell history) or environment variables (`VT_API_KEY`, `ABUSEIPDB_KEY`, `SHODAN_API_KEY`, `OTX_API_KEY`):

```bash
nshark config --vt
```

Then enrich a PCAP, IP, domain, URL, file hash, or local binary:

```bash
nshark capture.pcap --enrich
nshark enrich 8.8.8.8
nshark enrich 275a021bbfb341410736c63c7fac0f00fac5f80953f5a499282dd3599260e27f
nshark enrich suspicious_file.exe
```

## Commands

| Command | What it does |
|---|---|
| `nshark <pcap>` (`nshark analyze <pcap>`) | Run full attack triage (`-f "<bpf>"`, `--enrich`, `--report [console\|json\|html]`, `--fp-tolerance [strict\|balanced\|lenient]`) |
| `nshark hashes <pcap>` | Extract Hashcat-ready authentication hashes (`-m 5600`, `13100`, `18200`, `11400`, `11100`, `11200`) |
| `nshark hosts <pcap>` | Passive host, OS, MAC vendor, and service inventory |
| `nshark iocs <pcap>` | Extract public IPs, domains, URLs, and file hashes |
| `nshark carve <pcap>` | Extract files transferred over HTTP, SMB2, FTP, SMTP, TFTP |
| `nshark dns <pcap>` | Inspect DNS queries and flag tunneling / DGA |
| `nshark http <pcap>` | Inspect HTTP requests and decoded payloads |
| `nshark enrich <target>` | Check IP, domain, hash, binary, or PCAP on VirusTotal/OTX/AbuseIPDB/Shodan |
| `nshark export <pcap>` | Export IOCs or alerts to STIX 2.1, MISP, or CSV |
| `nshark config` | View or save Threat Intel API keys (`--vt`, `--abuseipdb`, `--shodan`, `--otx`, `--reset`) |

## Documentation

- **[Detection Reference](docs/DETECTIONS.md)** — Every `DetectionType` in `models.py`, which file and class produces it, heuristics, MITRE ATT&CK mappings, and known false positives.
- **[How Hash Extraction Works](docs/HASH_EXTRACTION.md)** — How NetNTLMv2, Kerberos RC4/AES, HTTP Digest, and DB hashes are reassembled from raw packet bytes.
- **[Use Cases & Sample Outputs](USE_CASES.md)** — Real examples and terminal outputs across CTF, SOC, and Active Directory scenarios.
- **[Security & Privacy Policy](SECURITY.md)** — Offline guarantees, what `--enrich` transmits, secret hygiene, and vulnerability reporting.

## Why nshark? (Comparison)

`nshark` is built for **fast first-look triage** when someone hands you a `.pcap` during an incident, lab, or CTF and you want to see the attack story and extract hashes right away.

| Feature | `nshark` | `tshark` | `Zeek` | `NetworkMiner` |
|---|---|---|---|---|
| **Primary Goal** | Single-command attack summary & hashes | Packet filtering & field extraction | High-speed network sensor & structured logs | GUI host, file & credential extractor |
| **Out-of-the-Box Attack Alerts** | Yes (Behavioral & protocol alerts + MITRE ATT&CK IDs) | No (requires manual display filters) | Partial (requires custom Zeek scripts) | No (commercial edition only) |
| **Crackable Hash Extraction** | Built-in (`NetNTLMv2`, `Kerberos`, `Digest`, `DBs`) | Manual field slicing required | Requires external plugins | Partial |
| **File Carving** | Built-in (`HTTP`, `SMB2`, `FTP`, `SMTP`, `TFTP`) | Manual (`--export-objects`) | Built-in (file analysis framework) | Built-in (GUI) |
| **Throughput on Multi-GB Captures** | Moderate (~3,000 pkts/s, pure Python) | Fast (C-based) | Very Fast (C++, line-rate 10GbE+) | Slow on large files (GUI memory bound) |

**Where `nshark` is better:**
- Summarizes multi-stage attacks (port scan -> directory brute force -> login brute force -> command injection -> reverse shell -> persistence, or Active Directory Kerberoasting/DCSync/PsExec) in a single terminal command without writing 15 separate Wireshark filters.
- Outputs ready-to-crack Hashcat lines (`-m 5600`, `-m 13100`, `-m 18200`, `-m 11400`) directly to a file.

**Where `Zeek` or `tshark` is better:**
- For monitoring a live 10 Gbps enterprise tap or parsing a 20 GB capture, use `Zeek` or `tshark` (written in C/C++).
- For deep protocol dissection of specialized industrial, telecom, or proprietary protocols (3,000+ dissectors), use `tshark` / Wireshark.

## Benchmarks (Speed & Memory)

Measured on Apple Silicon (M-series, Python 3.9) using `tracemalloc` across the full detection pipeline:

| Capture Type | File Size | Packets | Reconstructed Flows | Wall-Clock Time | Peak Heap Memory |
|---|---|---|---|---|---|
| **Real Multi-Stage Attack PCAP** | 0.61 MB | 3,342 | 1,115 | **0.93 s** | **3.5 MB** |
| **Medium Capture** | 4.43 MB | 10,000 | 500 | **4.08 s** | **10.5 MB** |
| **Large Capture** | 22.13 MB | 50,000 | 500 | **19.73 s** | **50.7 MB** |

## Known Limitations

- **Saved capture files only (no live capture):** `nshark` analyzes saved `.pcap` and `.pcapng` files; it does not sniff live network interfaces directly.
- **Pure Python speed (~2,500–3,500 packets/sec) & in-memory flow state:** While `PcapReader` streams packets from disk during parsing, parsed packets and reconstructed flows are held in memory for cross-flow correlation. Captures under 100 MB run in seconds; for multi-gigabyte captures, pre-filter with `nshark -f "<bpf>"` or `tcpdump`.
- **No TLS decryption:** On encrypted TLS flows, `nshark` analyzes X.509 certificates, SNI, JA3/JA3S fingerprints, TLS downgrades, and Heartbleed, but cannot decrypt application payloads.
- **Lightweight TCP reassembly:** Out-of-order TCP segments are reordered per flow for file carving and HTTP decoding, but deliberately overlapping TCP segmentation evasion is not reassembled.
- **IPv4 focus:** Most behavioral detectors and GeoIP lookups are tuned primarily for IPv4 traffic; IPv6 tunnel and extension-header attacks have not been tested.

## License

[MIT](LICENSE)
