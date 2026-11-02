# Changelog

All notable changes to `nshark` are documented in this file.

## [1.0.0] - 2026-11-01

### Added
- **Streaming PCAP & PCAPNG Engine (`nshark/core/parser.py`, `nshark/core/flow.py`):**
  - Memory-efficient packet iteration via `PcapReader` with VXLAN (UDP 4789) decapsulation, BPF pre-filtering (`-f`), and bidirectional flow reconstruction.
- **Behavioral & Protocol Detections (`nshark/detectors/`) — covering recon, credential access, web & post-exploitation, C2, exfiltration, Layer-2 poisoning, and Active Directory lateral movement:**
  - `PortScanDetector` (`T1046`): SYN, Connect, UDP, Xmas/Null/FIN stealth scans, and horizontal sweeps.
  - `BruteForceDetector` (`T1110.001`): SSH, FTP, HTTP POST/Basic, SMB, RDP, Telnet, and MySQL login brute-forcing with failure-count tracking.
  - `BeaconingDetector` (`T1071.001`): Jitter-tolerant C2 callback interval analysis via Coefficient of Variation ($\sigma/\mu$).
  - `DNSTunnelDetector` (`T1048.001`): `dnscat2`, `iodine`, `dns2tcp`, Base32/64/Hex DNS exfiltration, DGA domains, and `AXFR` zone transfers.
  - `ExfiltrationDetector` (`T1041`, `T1048.003`): Outbound byte-ratio anomaly detection and covert ICMP Echo tunneling.
  - `CleartextCredsDetector` (`T1040`, `T1552.001`): HTTP Basic/POST/Bearer, FTP, SMTP, POP3, IMAP, LDAP, Redis, Telnet, and SNMP credential extraction with login success correlation.
  - `PostExploitationDetector` (`T1190`, `T1059.004`, `T1595.003`): Command injection (RCE), SQLi, LFI, Log4Shell, interactive reverse shells, SSH `authorized_keys` persistence, and web directory enumeration.
  - `TLSAnalysisDetector` (`T1573`, `T1587.003`): JA3/JA3S TLS fingerprinting, SSH HASSH, self-signed/expired certificates, TLS 1.0/1.1 downgrades, and Heartbleed (`CVE-2014-0160`).
  - `ARPSpoofDetector` (`T1557.002`, `T1557.001`): ARP cache poisoning, gratuitous ARP floods, LLMNR/NBT-NS/mDNS poisoning, and rogue DHCP servers.
  - `LateralMovementDetector` (`T1021.002`, `T1003.006`, `T1558.003`, `T1210`): PsExec/SMBExec, DCSync, Zerologon (`CVE-2020-1472`), PetitPotam, PrintNightmare, Kerberoasting, AS-REP Roasting, Pass-the-Hash, WMI/DCOM, and SMBGhost (`CVE-2020-0796`).
- **Offline Hash Extractor (`nshark hashes`):**
  - Extracts Hashcat-ready `NetNTLMv2` (`-m 5600`), `NetNTLMv1` (`-m 5500`), `Kerberos 5 TGS-REP` (`-m 13100`/`19600`/`19700`), `AS-REP` (`-m 18200`), `HTTP/SIP Digest` (`-m 11400`), `PostgreSQL MD5` (`-m 11100`), and `MySQL SHA1` (`-m 11200`).
- **Multi-Protocol File Carver (`nshark carve`):**
  - Reassembles and carves payloads across HTTP (including chunked & gzip), SMB2, FTP-DATA, SMTP MIME, and TFTP with strict path-traversal sanitization and SHA-256/MD5 hashing.
- **Privacy-Preserving Threat Intel Enrichment (`nshark enrich` & `nshark config`):**
  - VirusTotal v3, AbuseIPDB v2, Shodan, and AlienVault OTX integrations with local SQLite caching (`~/.nshark/cache.db`) and hidden API key prompts (`0600` permissions on `~/.nshark/.env`).
- **SIEM Exporters (`nshark export`):**
  - STIX 2.1 bundles, MISP events, and CSV indicator exports.

### Changed
- Removed `install.sh` (`curl | bash` installer) because piping a remote shell script is a trust risk for a security tool.
- `nshark config` now prompts for API keys with hidden input instead of taking keys as plain CLI arguments that leak into shell history.

