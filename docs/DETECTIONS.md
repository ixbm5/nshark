# Detection Modules & How They Work

`nshark` runs a set of behavioral and protocol-level detectors over the parsed packets and reconstructed flows. Every alert is mapped to a MITRE ATT&CK technique and passed through the scoring engine (`nshark/scoring/engine.py`), which boosts confidence when multiple stages of an attack come from the same host.

Below is what each module looks for, how the detection logic works in code, and what legitimate traffic can trigger false positives.

---

### Detection Types (`DetectionType` in `nshark/core/models.py`)

| Detection Type (`DetectionType`) | File & Class | MITRE Technique | What & How It Detects | Known False Positive |
|---|---|---|---|---|
| `PORT_SCAN` (`port_scan`) | `nshark/detectors/port_scan.py` (`PortScanDetector`) | `T1046` | Vertical/horizontal TCP SYN, Connect, UDP, and Xmas/FIN/Null stealth scans (`>=20` unique ports or `>=15` hosts in 60s, port entropy, and `RST` ratios). | Authorized vulnerability scanners (Nessus/Qualys) or P2P clients. |
| `WEB_ENUMERATION` (`web_enumeration`) | `nshark/detectors/post_exploitation.py` (`PostExploitationDetector`) | `T1595.003` | Forced browsing and directory brute-forcing (`>=20` HTTP `404` responses per source IP and scanner `User-Agent` headers like `gobuster`/`ffuf`). | Broken web scrapers or frontend apps requesting missing static assets in bulk. |
| `BRUTE_FORCE` (`brute_force`) | `nshark/detectors/brute_force.py` (`BruteForceDetector`) | `T1110.001` | Rapid login guessing (`>=10` attempts in 60s) and explicit auth failure replies across SSH, FTP, HTTP, SMB, RDP, Telnet, and MySQL. | Automated scripts or services stuck in a retry loop with an expired password. |
| `CLEARTEXT_CREDENTIALS` (`cleartext_credentials`) | `nshark/detectors/cleartext_creds.py` (`CleartextCredsDetector`), `nshark/detectors/post_exploitation.py` (`PostExploitationDetector`) | `T1040` | Plaintext logins in HTTP Basic/POST/Bearer, FTP, SMTP, POP3, IMAP, Telnet, LDAP, Redis, PostgreSQL, and SNMP, plus replayed HTTP session cookies. | Anonymous FTP (`USER anonymous`) or local lab web apps over plain HTTP. |
| `COMMAND_INJECTION` (`command_injection`) | `nshark/detectors/post_exploitation.py` (`PostExploitationDetector`) | `T1190` | URL-decoded HTTP requests with shell chaining (`; nc`, `\| bash`), SQLi (`UNION SELECT`, `' OR 1=1`), path traversal (`../etc/passwd`), or Log4Shell JNDI strings. | Authorized web app vulnerability scanners (Nikto/OWASP ZAP). |
| `REVERSE_SHELL` (`reverse_shell`) | `nshark/detectors/post_exploitation.py` (`PostExploitationDetector`) | `T1059.004` | Interactive shell output (`uid=0(root)`, `Microsoft Windows [Version`) and SSH `authorized_keys` persistence over raw TCP streams. | Legacy unencrypted Telnet or `rsh` administrative sessions. |
| `C2_BEACONING` (`c2_beaconing`) | `nshark/detectors/beaconing.py` (`BeaconingDetector`), `nshark/detectors/post_exploitation.py` (`PostExploitationDetector`) | `T1071.001` | Periodic outbound callbacks (`>=10` connections with interval $\text{CoV} \le 0.15$), plus HTTP malware check-ins, Meterpreter TLV streams, and RAT heartbeats. | Cloud monitoring agents (Datadog/Zabbix) or NTP polling on a fixed timer. |
| `DNS_TUNNELING` (`dns_tunneling`) | `nshark/detectors/dns_tunnel.py` (`DNSTunnelDetector`) | `T1048.001` | `dnscat2`, `iodine`, `dns2tcp`, high-entropy (`>3.5`) or long (`>30` char) subdomains, high `TXT`/`NULL`/`SRV` ratios, DGA domains, and `AXFR` zone transfers. | Anti-spam DNSBL lookups or DKIM/SPF/DMARC `TXT` verification queries. |
| `DATA_EXFILTRATION` (`data_exfiltration`) | `nshark/detectors/exfiltration.py` (`ExfiltrationDetector`) | `T1041` (`T1048.003` for ICMP) | Outbound transfers `>=1 MB` with upload/download ratio `>=3.0x` (or `>2\sigma` above host baseline), plus oversized or high-entropy ICMP Echo payloads. | Uploading large backups to cloud storage or running `ping -s 1400` MTU tests. |
| `TLS_ANOMALY` (`tls_anomaly`) | `nshark/detectors/tls_analysis.py` (`TLSAnalysisDetector`) | `T1573` | Known malicious JA3/JA3S TLS fingerprints, SSH HASSH, self-signed/expired X.509 certificates, TLS 1.0/1.1 downgrades, and Heartbleed (`CVE-2014-0160`). | Internal lab services using self-signed certificates. |
| `ARP_SPOOFING` (`arp_spoofing`) | `nshark/detectors/arp_spoof.py` (`ARPSpoofDetector`) | `T1557.002` (`T1557.001` / `T1557.003`) | Multiple MAC addresses claiming the same IP (especially gateway `.1`/`.254`), gratuitous ARP floods, unsolicited LLMNR/NBT-NS replies, and rogue DHCP offers. | Router redundancy protocols (VRRP/HSRP) or secondary failover DHCP servers. |
| `LATERAL_MOVEMENT` (`lateral_movement`) | `nshark/detectors/lateral_movement.py` (`LateralMovementDetector`) | `T1021.002` (`T1558.003` / `T1021.001` / `T1021.006`) | SMB `ADMIN$`/`IPC$` shares, DCE-RPC binds (`svcctl` PsExec, `drsuapi` DCSync, `netlogon` Zerologon, `lsarpc` PetitPotam), Kerberoasting RC4 `TGS-REQ`, Pass-the-Hash, RDP, WinRM, and SMBGhost. | Enterprise admin deployment tools (SCCM/PDQ Deploy) or Domain Controller replication. |

---

## Tuning False Positives

If a capture from a noisy environment triggers false positives, you can adjust sensitivity without editing code:

1. **Strict Mode (`--fp-tolerance strict`):** Raises the minimum confidence threshold to `85%`, suppressing low-confidence single-indicator alerts.
2. **Custom Confidence Cutoff (`--min-confidence 80`):** Filters out alerts below your chosen score.
3. **Custom Thresholds (`config.yaml`):** Run `nshark config --reset` to generate a local `config.yaml` where you can raise `port_scan.min_ports`, `beaconing.min_beacons`, `dns_tunnel.entropy_threshold`, or `exfiltration.min_bytes`.
