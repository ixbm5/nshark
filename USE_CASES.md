# NSHARK — Use Cases & Command Guide

Quick navigation:
- [1. Full Attack Triage (`nshark analyze`)](#1-full-attack-triage)
- [2. Crackable Hash Extraction (`nshark hashes`)](#2-crackable-hash-extraction)
- [3. Host & Asset Discovery (`nshark hosts`)](#3-host--asset-discovery)
- [4. Active Directory & Lateral Movement](#4-active-directory--lateral-movement)
- [5. File Carving & Payload Hashing (`nshark carve`)](#5-file-carving--payload-hashing)
- [6. DNS Tunneling & HTTP Inspection (`nshark dns` / `http`)](#6-dns-tunneling--http-inspection)
- [7. Threat Intel Lookups & SIEM Export (`nshark iocs` / `enrich` / `export`)](#7-threat-intel-lookups--siem-export)

---

## 1. Full Attack Triage

Run all 12 behavioral detectors (L2 ARP/LLMNR through L7 HTTP/DNS/SMB/Kerberos/TLS) with a single command:

```bash
# Default balanced mode (shows alerts >= 70% confidence)
nshark analyze capture.pcap

# Target specific protocols or subnets with BPF filter expressions (drops irrelevant packets early)
nshark analyze capture.pcap -f "tcp port 80 or port 445"

# CTF / Threat Hunting mode (surface lower-confidence leads)
nshark analyze capture.pcap --fp-tolerance lenient --min-confidence 50

# Noisy production network (strict mode >= 85% confidence)
nshark analyze capture.pcap --fp-tolerance strict

# Save full report as JSON (includes auto-generated Wireshark filters per alert)
nshark analyze capture.pcap --report json -o report.json
```

---

## 2. Crackable Hash Extraction

Pull **NetNTLMv2 (`-m 5600`)**, **NetNTLMv1 (`-m 5500`)**, **Kerberos 5 TGS-REP RC4/AES (`-m 13100` / `19600` / `19700`)**, **Kerberos 5 AS-REP (`-m 18200`)**, **HTTP/SIP Digest (`-m 11400`)**, **PostgreSQL MD5 (`-m 11100`)**, and **MySQL SHA1 (`-m 11200`)** challenge-response hashes straight out of a PCAP in Hashcat format:

```bash
# View captured hashes in terminal
nshark hashes capture.pcap

# Save raw Hashcat strings directly to a file and crack with Hashcat
nshark hashes capture.pcap -o hashes.txt
hashcat -m 5600 hashes.txt rockyou.txt
```

**Example Output:**
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

## 3. Host & Asset Discovery

Passively map every machine in the capture (IPv4/IPv6, Ethernet/ARP MAC hardware/VM vendor, hostname, Active Directory domain, `p0f`-style TTL/TCP window OS fingerprint, and service banners) without sending a single packet:

```bash
nshark hosts capture.pcap
```

**Example Output:**
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

## 4. Active Directory & Lateral Movement

`nshark analyze` automatically inspects SMB (`445`/`139`), DCE/RPC (`135`), Kerberos (`88`), RDP (`3389`), WinRM (`5985`), LLMNR/NBT-NS (`5355`/`137`), and DHCP (`67`/`68`):

- **PsExec / Impacket (`smbexec`, `wmiexec`, `atexec`, `secretsdump`)**: Detects `ADMIN$`, `C$`, `svcctl`, `atsvc`, `drsuapi` (DCSync), and `PSEXESVC` (`T1021.002`).
- **Pass-the-Hash & NTLM Spraying**: Flags `STATUS_LOGON_FAILURE` bursts and single-host NTLMSSP sweeps across multiple targets (`T1021.002`).
- **Kerberoasting & AS-REP Roasting**: Flags RC4-HMAC (`etype 23`) encryption downgrades on `TGS-REQ`/`TGS-REP`/`AS-REP` and `kerbrute` `KRB-ERROR` user enumeration (`T1558.003`).
- **Responder (`LLMNR` / `NBT-NS` Poisoning) & Rogue DHCP**: Flags rogue unicast responses spoofing `WPAD`/hostnames (`T1557.001`) and competing DHCP servers (`T1557.003`).

---

## 5. File Carving & Payload Hashing

Reconstruct and extract files transferred across **HTTP (`GET` responses & `POST` multipart uploads)**, **SMB2 (`CREATE` + `WRITE`/`READ`)**, **FTP (`RETR`/`STOR` data channels)**, **SMTP/IMAP MIME (`base64` attachments)**, and **TFTP (`UDP 69`)**, detect 20+ file types by magic bytes, and compute MD5 + SHA-256 hashes:

```bash
# Carve all transferred files into ./carved
nshark carve capture.pcap -o ./carved

# Carve files and check their SHA-256 hashes against VirusTotal
nshark carve capture.pcap -o ./carved --hash-check
```

---

## 6. DNS Tunneling & HTTP Inspection

```bash
# Show only suspicious / DGA / DNS tunneling queries (iodine, dnscat2, dns2tcp)
nshark dns capture.pcap --suspicious-only

# Reconstruct HTTP requests, decode URL/Base64 bodies, and flag SQLi/LFI/RCE
nshark http capture.pcap
```

---

## 7. Threat Intel Lookups & SIEM Export

```bash
# Extract all public IPs, domains (DNS + TLS SNI), URLs, emails, and User-Agents
nshark iocs capture.pcap

# Filter by IOC type and enrich with VirusTotal, AbuseIPDB, Shodan, and OTX
nshark iocs capture.pcap --type ip,domain --enrich

# Standalone IP / domain / file list lookup (no PCAP needed)
nshark enrich 45.33.32.156
nshark enrich iocs.txt --providers vt,abuseipdb,shodan,otx
cat ips.txt | nshark enrich --stdin

# Export IOCs to STIX 2.1, MISP, or CSV
nshark export capture.pcap --format stix -o iocs.stix.json
nshark export capture.pcap --format misp -o event.misp.json
nshark export capture.pcap --format csv -o iocs.csv
```
