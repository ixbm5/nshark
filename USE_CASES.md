# NSHARK — Everyday Use Cases & Expected Outputs

Quick navigation:
- [1. Instant PCAP Triage (`nshark <pcap>`)](#1-instant-pcap-triage)
- [2. Threat Intel Setup & Enrichment (`nshark config` & `nshark enrich`)](#2-threat-intel-setup--enrichment)
- [3. Crackable Hash Extraction (`nshark hashes`)](#3-crackable-hash-extraction)
- [4. Host & Asset Discovery (`nshark hosts`)](#4-host--asset-discovery)
- [5. Active Directory & Lateral Movement](#5-active-directory--lateral-movement)
- [6. File Carving & VirusTotal Hash Checks (`nshark carve`)](#6-file-carving--virustotal-hash-checks)
- [7. DNS Tunneling, HTTP Inspection & SIEM Export (`nshark dns` / `http` / `export`)](#7-dns-tunneling-http-inspection--siem-export)

---

## 1. Instant PCAP Triage

Just pass a `.pcap` or `.pcapng` file directly (or use `nshark analyze`):

```bash
# Instant triage (runs behavioral and protocol detectors across the capture)
nshark capture.pcap

# Same command with Threat Intel reputation checks enabled
nshark analyze capture.pcap --enrich

# Filter large captures with BPF before analysis (drops irrelevant traffic early)
nshark analyze capture.pcap -f "tcp port 80 or port 445"

# CTF / Threat Hunting mode (surface lower-confidence leads)
nshark analyze capture.pcap --fp-tolerance lenient --min-confidence 50

# Save full report as JSON
nshark analyze capture.pcap --report json -o report.json
```

**What You Expect to See:**
```text
╭───────────────────────────────────────────────────────────────────────────────────╮
│ NSHARK v1.0.0 // CRITICAL THREAT                                                  │
│ File: LM_psexec.pcapng  |  Packets: 94  |  Flows: 3  |  Duration: 1.5s            │
╰───────────────────────────────────────────────────────────────────────────────────╯

[!] ALERTS (1 found, min confidence 70%)
┏━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Sev      ┃     Conf ┃ Detection        ┃ Source -> Target          ┃ MITRE    ┃ Details                            ┃
┡━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ CRITICAL │ █████ 98%┃ Lateral Movement ┃ 172.16.66.1 ──▶ .66.36    ┃ T1021.002┃ SMB/DCE-RPC Lateral Movement (PsEx…┃
│          │          ┃                  ┃                           ┃          ┃ Account='3B\backdoor' [Hashcat     ┃
│          │          ┃                  ┃                           ┃          ┃ NetNTLMv2 (-m 5600) -> run `nshark ┃
│          │          ┃                  ┃                           ┃          ┃ hashes`]                           ┃
└──────────┴──────────┴──────────────────┴───────────────────────────┴──────────┴────────────────────────────────────┘
```

---

## 2. Threat Intel Setup & Enrichment

### Step 1: Save Your API Key Securely (Works From Any Folder)
Configure your keys once via an interactive hidden prompt (or environment variables) so secrets never appear in your shell history (`~/.zsh_history`) or process table (`ps aux`). NSHARK stores them in `~/.nshark/.env` with strict `0600` permissions:

```bash
# Prompt securely for your VirusTotal API key (input hidden)
nshark config --vt

# Optionally prompt for AbuseIPDB, Shodan, or AlienVault OTX
nshark config --abuseipdb --shodan --otx

# Check which Threat Intel feeds are active
nshark config
```

**Expected Output (`nshark config`):**
```text
                   [*] NSHARK Threat Intelligence Feeds (Global ~/.nshark/.env · mode 0600)                   
┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Provider        ┃ Status   ┃ Configured Key ┃ Supported Indicators              ┃ Setup Command            ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ VirusTotal v3   │ ● ACTIVE │ ****9f2a       │ IPs, Domains, File SHA-256/MD5    │ nshark config --vt       │
├─────────────────┼──────────┼────────────────┼───────────────────────────────────┼──────────────────────────┤
│ AbuseIPDB v2    │ ○ NOT SET│ -              │ Public IPv4/IPv6 Reputation       │ nshark config --abuseip… │
├─────────────────┼──────────┼────────────────┼───────────────────────────────────┼──────────────────────────┤
│ Shodan          │ ○ NOT SET│ -              │ Open Ports, Banners, CVEs         │ nshark config --shodan   │
├─────────────────┼──────────┼────────────────┼───────────────────────────────────┼──────────────────────────┤
│ AlienVault OTX  │ ● ACTIVE │ ****3c10       │ IPs, Domains, File Hashes, Pulses │ nshark config --otx      │
└─────────────────┴──────────┴────────────────┴───────────────────────────────────┴──────────────────────────┘
```

### Step 2: Enrich Anything with `nshark enrich`
`nshark enrich` automatically detects what you give it — an **IP**, **domain**, **URL**, **SHA-256/MD5 hash**, **local binary file (`.exe`/`.elf`/`.pdf`)**, **PCAP file**, or **text list of IOCs**:

```bash
# Check a public IP or domain
nshark enrich 8.8.8.8
nshark enrich evil-domain.com

# Check a full URL (automatically extracts the host/domain)
nshark enrich "https://evil-domain.com/payload.exe"

# Check a SHA-256 or MD5 file hash on VirusTotal & OTX
nshark enrich 275a021bbfb341410736c63c7fac0f00fac5f80953f5a499282dd3599260e27f

# Check a suspicious binary on disk (automatically computes SHA-256 and queries VT)
nshark enrich ./suspicious_binary.exe

# Pass a PCAP directly to extract and enrich all public IPs, domains, and carved files
nshark enrich capture.pcapng
```

**Expected Output (`nshark enrich`):**
```text
                                            [*] Reputation Results (3)                                            
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Indicator                            ┃ Provider   ┃ Verdict   ┃ Score ┃ Details                                ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 275a021bbfb341410736c63c7fac0f00fac… │ VirusTotal │ MALICIOUS │  100% │ 68/72 engines | family=eicar.test |    │
│                                      │            │           │       │ file=eicar.com.txt | type=Text         │
├──────────────────────────────────────┼────────────┼───────────┼───────┼────────────────────────────────────────┤
│ 185.220.101.34                       │ VirusTotal │ MALICIOUS │   90% │ 14/94 engines | org=AS205100 F3 Netze  │
│                                      │            │           │       │ | country=DE [Outbound to :443]        │
├──────────────────────────────────────┼────────────┼───────────┼───────┼────────────────────────────────────────┤
│ 8.8.8.8                              │ VirusTotal │ CLEAN     │    0% │ 0/94 engines | org=AS15169 Google LLC  │
│                                      │            │           │       │ | country=US | rep=540                 │
└──────────────────────────────────────┴────────────┴───────────┴───────┴────────────────────────────────────────┘
```

---

## 3. Crackable Hash Extraction

Pull **NetNTLMv2 (`-m 5600`)**, **NetNTLMv1 (`-m 5500`)**, **Kerberos 5 TGS-REP RC4/AES (`-m 13100` / `19600` / `19700`)**, **Kerberos 5 AS-REP (`-m 18200`)**, **HTTP/SIP Digest (`-m 11400`)**, **PostgreSQL MD5 (`-m 11100`)**, and **MySQL SHA1 (`-m 11200`)** challenge-response hashes straight out of a PCAP in Hashcat format:

```bash
# View captured hashes in terminal
nshark hashes capture.pcap

# Save raw Hashcat strings directly to a file and crack with Hashcat
nshark hashes capture.pcap -o hashes.txt
hashcat -m 5600 hashes.txt rockyou.txt
```

**Expected Output:**
```text
┏━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Type       ┃ Mode     ┃ Account            ┃ Source -> Target        ┃ Hash Preview           ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━┩
│ NetNTLMv2  │ -m 5600  │ 3B\backdoor        │ 172.16.66.1 -> .66.36   │ backdoor::3B:47ddce77… │
├────────────┼──────────┼────────────────────┼─────────────────────────┼────────────────────────┤
│ KRB5-TGS   │ -m 13100 │ THREEBEESCO\backd… │ 172.16.66.1 -> .66.10   │ $krb5tgs$23$*backdoor… │
└────────────┴──────────┴────────────────────┴─────────────────────────┴────────────────────────┘
```

---

## 4. Host & Asset Discovery

Passively map every machine in the capture (IPv4/IPv6, Ethernet/ARP MAC hardware/VM vendor, hostname, Active Directory domain, `p0f`-style TTL/TCP window OS fingerprint, and service banners) without sending a single packet:

```bash
nshark hosts capture.pcap
```

**Expected Output:**
```text
┏━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┓
┃ IP Address   ┃ MAC / Vendor       ┃ Hostname / Domain  ┃ OS Fingerprint     ┃ Active Services ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━┩
│ 10.0.0.5     │ 00:50:56:aa:11:22  │ DC01 (CORP.LOCAL)  │ Windows Server     │ 53/dns, 88/krb, │
│              │ (VMware)           │                    │ (Domain Controller)│ 389/ldap, 445   │
├──────────────┼────────────────────┼────────────────────┼────────────────────┼─────────────────┤
│ 10.0.0.50    │ 00:0c:29:44:55:66  │ WIN10-DEV (CORP)   │ Windows            │ 135/msrpc,      │
│              │ (VMware)           │                    │                    │ 445/smb         │
└──────────────┴────────────────────┴────────────────────┴────────────────────┴─────────────────┘
```

---

## 5. Active Directory & Lateral Movement

`nshark analyze` automatically inspects SMB (`445`/`139`), DCE/RPC (`135`), Kerberos (`88`), RDP (`3389`), WinRM (`5985`), LLMNR/NBT-NS (`5355`/`137`), and DHCP (`67`/`68`):

- **PsExec / Impacket (`smbexec`, `wmiexec`, `atexec`, `secretsdump`)**: Detects `ADMIN$`, `C$`, `svcctl`, `atsvc`, `drsuapi` (DCSync), and `PSEXESVC` (`T1021.002`).
- **Pass-the-Hash & NTLM Spraying**: Flags `STATUS_LOGON_FAILURE` bursts and single-host NTLMSSP sweeps across multiple targets (`T1021.002`).
- **Kerberoasting & AS-REP Roasting**: Flags RC4-HMAC (`etype 23`) encryption downgrades on `TGS-REQ`/`TGS-REP`/`AS-REP` and `kerbrute` `KRB-ERROR` user enumeration (`T1558.003`).
- **Responder (`LLMNR` / `NBT-NS` Poisoning) & Rogue DHCP**: Flags rogue unicast responses spoofing `WPAD`/hostnames (`T1557.001`) and competing DHCP servers (`T1557.003`).

---

## 6. File Carving & VirusTotal Hash Checks

Reconstruct and extract files transferred across **HTTP (`GET` responses & `POST` multipart uploads)**, **SMB2 (`CREATE` + `WRITE`/`READ`)**, **FTP (`RETR`/`STOR` data channels)**, **SMTP/IMAP MIME (`base64` attachments)**, and **TFTP (`UDP 69`)**, detect 20+ file types by magic bytes, and compute MD5 + SHA-256 hashes:

```bash
# Carve all transferred files into ./carved
nshark carve capture.pcap -o ./carved

# Carve files and check their SHA-256 hashes against VirusTotal
nshark carve capture.pcap -o ./carved --hash-check
```

---

## 7. DNS Tunneling, HTTP Inspection & SIEM Export

```bash
# Show only suspicious / DGA / DNS tunneling queries (iodine, dnscat2, dns2tcp)
nshark dns capture.pcap --suspicious-only

# Reconstruct HTTP requests, decode URL/Base64 bodies, and flag SQLi/LFI/RCE
nshark http capture.pcap

# Extract all public IPs, domains (DNS + TLS SNI), URLs, emails, and file hashes with VT verdicts
nshark iocs capture.pcap --enrich

# Export IOCs to STIX 2.1, MISP, or CSV
nshark export capture.pcap --format stix -o iocs.stix.json
nshark export capture.pcap --format misp -o event.misp.json
nshark export capture.pcap --format csv -o iocs.csv
```

