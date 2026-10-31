# NSHARK

```text
 ███╗   ██╗███████╗██╗  ██╗ █████╗ ██████╗ ██╗  ██╗  v1.0.0 // APEX PCAP ENGINE
 ████╗  ██║██╔════╝██║  ██║██╔══██╗██╔══██╗██║ ██╔╝  Fast PCAP Analysis & Threat Intel
 ██╔██╗ ██║███████╗███████║███████║██████╔╝█████╔╝   ─────────────────────────────────
 ██║╚██╗██║╚════██║██╔══██║██╔══██║██╔══██╗██╔═██╗   [DET] 12 Behavioral Modules
 ██║ ╚████║███████║██║  ██║██║  ██║██║  ██║██║  ██╗  [EXT] IOC · DNS · HTTP · Carve
 ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝  [CTI] VT·AbuseIPDB·Shodan·OTX
```

Fast CLI packet analyzer for threat hunting, CTF triage, and incident response. Pass any `.pcap` or `.pcapng` to surface attacks, crackable hashes, cleartext credentials, carved files, and IOCs in seconds.

## Install

### 1-Line Install (macOS & Linux)

```bash
curl -sSL https://raw.githubusercontent.com/ixbm5/nshark/main/install.sh | bash
```

---

### From Source

```bash
git clone https://github.com/ixbm5/nshark.git && cd nshark
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

---

### Using pipx

```bash
# If pipx is not installed on your system:
# macOS:   brew install pipx && pipx ensurepath
# Linux:   sudo apt install pipx && pipx ensurepath

pipx install git+https://github.com/ixbm5/nshark.git
```


## Quick Start

```bash
# 1. Analyze a PCAP (detects attacks, maps to MITRE ATT&CK, builds timeline)
nshark capture.pcap

# 2. Extract crackable Hashcat hashes (NetNTLMv2, Kerberos, HTTP Digest, DBs)
nshark hashes capture.pcap -o hashes.txt

# 3. Passive host discovery (IP, MAC vendor, OS, hostname, open ports)
nshark hosts capture.pcap

# 4. Carve transferred files from network traffic
nshark carve capture.pcap -o ./carved
```

## Threat Intel Enrichment (Optional)

Save your API key once (stored in `~/.nshark/.env`, works from any folder):

```bash
nshark config --vt <YOUR_VIRUSTOTAL_KEY>
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
| `nshark <pcap>` | Run full attack triage and protocol diagnostics |
| `nshark hashes <pcap>` | Extract Hashcat-ready authentication hashes |
| `nshark hosts <pcap>` | Passive host, OS, and service inventory |
| `nshark iocs <pcap>` | Extract public IPs, domains, URLs, and file hashes |
| `nshark carve <pcap>` | Extract files transferred over HTTP, SMB, FTP, SMTP, TFTP |
| `nshark dns <pcap>` | Inspect DNS queries and flag tunneling / DGA |
| `nshark http <pcap>` | Inspect HTTP requests and decoded payloads |
| `nshark enrich <target>` | Check IP, domain, hash, binary, or PCAP on VirusTotal/OTX/AbuseIPDB/Shodan |
| `nshark export <pcap>` | Export IOCs to STIX 2.1, MISP, or CSV |
| `nshark config` | View or save Threat Intel API keys (`--vt`, `--abuseipdb`, `--shodan`, `--otx`) |

See **[USE_CASES.md](USE_CASES.md)** for full examples and sample terminal outputs.

## License

[MIT](LICENSE)

