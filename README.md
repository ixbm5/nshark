# NSHARK

```text
                               ▄▄
                             ▄███
                           ▄█████               ▄▄▄▄▄▄
                         ▄███████         ▄▄▄████████████▄▄▄
                       ▄█████████    ▄▄▄███████████████████████▄▄
    ▄▄▄              ▄███████████▄▄█████████████████████████████████▄▄
     ▀███▄▄        ▄██████████████████████████████████████▀▀▀▀██████████▄
       ▀█████▄▄  ▄███████████████████████████████████████  ▄▄  ▀█████████▌
         ▀███████████████████████████████████████████████  ▀▀ ▄████████▀
 ~^~^~^~   ▄████████████████████████████████████████████████████████▀  ~^~^~
 01001110 ▄███▀▀      ▀▀███████████████████████▀▀▀▀████████████▀▀▀  01010011
         ██▀              ▀▀█████████████▀▀▀         ▀██████▀
                              ▀▀██████▀▀               ▀███
                                  ▀▀                     ▀

 ███╗   ██╗███████╗██╗  ██╗ █████╗ ██████╗ ██╗  ██╗  v1.0.0 // APEX PCAP ENGINE
 ████╗  ██║██╔════╝██║  ██║██╔══██╗██╔══██╗██║ ██╔╝  Fast PCAP Analysis & Threat Intel
 ██╔██╗ ██║███████╗███████║███████║██████╔╝█████╔╝   ─────────────────────────────────
 ██║╚██╗██║╚════██║██╔══██║██╔══██║██╔══██╗██╔═██╗   [DET] 12 Behavioral Modules
 ██║ ╚████║███████║██║  ██║██║  ██║██║  ██║██║  ██╗  [EXT] IOC · DNS · HTTP · Carve
 ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝  [CTI] VT·AbuseIPDB·Shodan·OTX
```

Fast CLI packet analyzer for threat hunting, CTF triage, and incident response. Drop in a `.pcap` or `.pcapng` and get attacks, JA3 fingerprints, cleartext credentials, carved files, and IOCs in seconds.

```text
$ nshark analyze capture.pcap

╭──────────────────────────────────────────────────────────────────────────────╮
│ NSHARK v1.0.0 // Fast PCAP Analysis & Threat Intel                           │
│ File: capture.pcap  |  Packets: 3,980  |  Flows: 62  |  Duration: 735.5s     │
╰──────────────────────────────────────────────────────────────────────────────╯

[!] ALERTS (4 found, min confidence 70%)
┏━━━━━━━━━━┳━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Sev      ┃ Conf ┃ Detection  ┃ Source -> Dst ┃ MITRE     ┃ Details                   ┃
┡━━━━━━━━━━╇━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ CRITICAL │  99% │ Tls        │ 192.168.1.158 │ T1573     │ Malicious JA3 fingerprint │
│          │      │ Anomaly    │ -> 95.211.193 │           │ TrickBot C2 Channel       │
├──────────┼──────┼────────────┼───────────────┼───────────┼───────────────────────────┤
│ CRITICAL │  98% │ Dns        │ 192.168.1.20  │ T1048.001 │ DNS Tunneling via         │
│          │      │ Tunneling  │ -> biillpi.com│           │ TXT (entropy=3.63)        │
├──────────┼──────┼────────────┼───────────────┼───────────┼───────────────────────────┤
│ HIGH     │  90% │ Arp        │ 172.16.0.1    │ T1557.002 │ ARP MITM Relay: MAC       │
│          │      │ Spoofing   │ -> 172.16.0.5 │           │ 00:25:b3:bf:91:ee         │
├──────────┼──────┼────────────┼───────────────┼───────────┼───────────────────────────┤
│ HIGH     │  90% │ Cleartext  │ 192.168.1.50  │ T1040     │ FTP login exposed:        │
│          │      │ Creds      │ -> 10.0.0.12  │           │ USER='admin', PASS='mi***'│
└──────────┴──────┴────────────┴───────────────┴───────────┴───────────────────────────┘
```

## Install

```bash
git clone https://github.com/ixbm5/nshark.git
cd nshark
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

**Docker:**
```bash
docker build -t nshark .
docker run --rm -v "$PWD:/data" nshark analyze /data/capture.pcap
```

## Usage

```bash
# 1. Full attack triage & threat detection (live HUD + MITRE ATT&CK + timeline)
nshark analyze capture.pcap

# Filter captures with Berkeley Packet Filter (BPF) for near-instant triage
nshark analyze capture.pcap -f "tcp port 80 or port 445"

# 2. Extract crackable Hashcat hashes (NetNTLMv2 -m 5600, Kerberos -m 13100/18200)
nshark hashes capture.pcap -o hashes.txt

# 3. Passive host & asset inventory (IP, MAC vendor, hostname, OS, active services)
nshark hosts capture.pcap
```

Run `nshark -h` or `nshark <command> -h` for all options.

## Use Cases

Click any scenario below to view detailed commands and walkthroughs in [**USE_CASES.md**](USE_CASES.md):

| Use Case | Description | Quick Link |
|---|---|---|
| 🚨 **Full Attack Triage** | Run all 12 behavioral detectors (including over VXLAN/GRE/VLAN tunnels) with live HUD & MITRE mapping | [View Guide →](USE_CASES.md#1-full-attack-triage) |
| 🔑 **Hash Extraction** | Dump NetNTLMv2/v1, Kerberos RC4/AES, HTTP/SIP Digest, and Postgres/MySQL (`-m 11100/11200`) | [View Guide →](USE_CASES.md#2-crackable-hash-extraction) |
| 🖥️ **Host & Asset Inventory** | Passive OS (`p0f` TTL/Window + banners), hostname, AD domain, MAC vendor & services | [View Guide →](USE_CASES.md#3-host--asset-discovery) |
| 🛡️ **Active Directory Attacks** | Detect PsExec, Impacket, Pass-the-Hash, Kerberoasting, and Responder | [View Guide →](USE_CASES.md#4-active-directory--lateral-movement) |
| 💾 **File Carving & Hashing** | TCP sequence-ordered carving across HTTP, SMB2, FTP, SMTP MIME, and TFTP with MD5/SHA-256 | [View Guide →](USE_CASES.md#5-file-carving--payload-hashing) |
| 🌐 **DNS & HTTP Deep Dive** | Detect DNS tunneling (`iodine`, `dnscat2`), DGA, SQLi, LFI, and RCE | [View Guide →](USE_CASES.md#6-dns-tunneling--http-inspection) |
| ⚡ **Threat Intel & SIEM Export** | Query VT/AbuseIPDB/Shodan/OTX, export STIX 2.1, MISP, CSV | [View Guide →](USE_CASES.md#7-threat-intel-lookups--siem-export) |

👉 **[Browse all use cases and step-by-step examples →](USE_CASES.md)**

## What It Detects

| Module | Coverage | ATT&CK |
|---|---|---|
| **ARP / LLMNR / DHCP Spoofing** | ARP MITM relays, LLMNR & NBT-NS poisoning (Responder), Rogue DHCP & Starvation | `T1557.002` / `.001` / `.003` |
| **Port Scan** | SYN, connect, and UDP vertical scans & horizontal sweeps | `T1046` |
| **Web Enumeration** | Directory brute-forcing (Gobuster, Dirb, Feroxbuster, Nikto) | `T1595.003` |
| **Brute Force** | SSH, FTP, and HTTP rapid auth bursts | `T1110.001` |
| **Cleartext Creds** | HTTP Basic/POST/Bearer/JWT, FTP, Telnet, SMTP, POP3, IMAP, LDAP, SNMP, Redis, PostgreSQL | `T1040` |
| **Command Injection** | SQLi, LFI, RCE metacharacters, and path traversal in HTTP | `T1190` |
| **Reverse Shell** | Interactive shell prompts and `uid=` output over TCP/HTTP | `T1059.004` |
| **Lateral Movement** | SMB Pass-the-Hash/PsExec (`T1021.002`), Kerberoasting/AS-REP (`T1558.003`), RDP (`T1021.001`), WinRM (`T1021.006`) | `T1021.002` |
| **TLS (JA3/JA3S) & SSH (HASSH)** | Malicious JA3/JA3S hashes, C2 X.509 certificates, bare-IP TLS, SSH HASSH & C2 tunnels | `T1573` |
| **C2 Beaconing** | Jitter-aware periodic callbacks & direct-IP HTTP check-ins | `T1071.001` |
| **DNS Tunneling** | High-entropy subdomains, long labels, and TXT/NULL abuse (`iodine`, `dnscat2`) | `T1048.001` |
| **Exfiltration** | Outbound byte spikes, asymmetric uploads, and ICMP tunneling (`T1048.003`) | `T1041` |

## Threat Intel Keys (Optional)

NSHARK works offline by default. To enable `--enrich`, copy `.env.example` to `.env` and add any keys you have:

```ini
VT_API_KEY=your_virustotal_key
ABUSEIPDB_KEY=your_abuseipdb_key
SHODAN_API_KEY=your_shodan_key
OTX_API_KEY=your_alienvault_key
```

Results are cached locally in `~/.nshark/cache.db` (24h TTL).

## License

[MIT](LICENSE)
