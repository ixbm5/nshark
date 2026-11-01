# Security Policy & Privacy Guarantees

## 1. Offline-by-Default & Zero Telemetry

`nshark` is an **offline-first** network forensics and packet analysis tool:

- **No Telemetry:** `nshark` never collects analytics, usage metrics, crash reports, or telemetry of any kind.
- **Zero Outbound Connections by Default:** Running `nshark <capture.pcap>`, `nshark analyze`, `nshark hashes`, `nshark hosts`, `nshark carve`, `nshark dns`, `nshark http`, `nshark iocs`, or `nshark export` performs **100% local packet parsing** and makes **zero outbound network requests**.

---

## 2. What `--enrich` and `nshark enrich` Send Over the Network

Outbound HTTPS requests are made **only** when you explicitly pass the `--enrich` flag (or `--hash-check` on `carve`) or run the `nshark enrich` subcommand, and **only** to the Threat Intelligence providers for which you have configured an API key.

### Files and PCAPs Are Never Uploaded

When you run `nshark enrich <file.exe>` or `nshark <capture.pcap> --enrich`:

1. **Local Hashing Only:** Binary files and carved payloads are hashed **locally on your machine** using SHA-256 and MD5 (`hashlib`). **Raw files, packet payloads, and PCAP captures are never uploaded to VirusTotal or any third party.**
2. **RFC 1918 & Internal Traffic Filtering:** Private/internal IP addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, link-local, and multicast) are filtered out locally before enrichment.
3. **Exact Data Transmitted per Provider:**

| Provider | Endpoint Queried | Data Sent | What is NEVER Sent |
|---|---|---|---|
| **VirusTotal v3** | `GET https://www.virustotal.com/api/v3/{ip_addresses,domains,files}/{id}` | Public IPv4/IPv6 string, domain name, or 64-char SHA-256 / 32-char MD5 hex string | Raw files, carved payloads, PCAPs, private IPs, URLs with query strings |
| **AbuseIPDB v2** | `GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}` | Public IPv4/IPv6 string | Domains, file hashes, files, private IPs |
| **Shodan** | `GET https://api.shodan.io/shodan/host/{ip}` | Public IPv4/IPv6 string | Domains, file hashes, files, private IPs |
| **AlienVault OTX** | `GET https://otx.alienvault.com/api/v1/indicators/{type}/{id}/general` | Public IPv4 string, domain name, or file hash hex string | Raw files, carved payloads, PCAPs, private IPs |

---

## 3. API Key Storage & Secret Hygiene

- **No Secrets in CLI Arguments:** `nshark config --vt` (and `--abuseipdb`, `--shodan`, `--otx`) uses an interactive hidden prompt (`hide_input=True`) or reads from `stdin` / environment variables (`VT_API_KEY`, `ABUSEIPDB_KEY`, `SHODAN_API_KEY`, `OTX_API_KEY`). API keys are **never** accepted as command-line arguments so they cannot leak into shell history (`~/.zsh_history`, `~/.bash_history`) or the system process table (`ps aux`).
- **Strict File Permissions (`0600`):** When saving keys via `nshark config`, the directory `~/.nshark` is created with mode `0700` (`drwx------`) and `~/.nshark/.env` is created atomically via `os.open(..., 0o600)` (`-rw-------`), readable only by the current OS user.
- **Log Masking:** All terminal tables and debug logs mask configured API keys (showing only the final 4 characters, e.g., `****9f2a`).

---

## 4. Malformed Traffic & File Carving Safety

Analyzing untrusted or adversarial packet captures requires strict defensive parsing:

- **Path Traversal Prevention:** When carving files from HTTP, SMB, FTP, SMTP, or TFTP streams (`nshark carve`), attacker-controlled filenames in `Content-Disposition` headers, URLs, or SMB tree paths are stripped of directory components (`os.path.basename`), sanitized via strict allowlist regex (`[^A-Za-z0-9._-]`), stripped of leading dots, and verified with `os.path.realpath` to ensure every written file stays strictly inside the target output directory.
- **Decompression & Memory Bounds:** Gzip/deflate payloads and reassembled flows are bounded during carving and inspection to prevent zip-bomb or memory-exhaustion denial of service.
- **Streaming PCAP Parser:** Packet reading uses streaming iteration (`PcapReader`) rather than loading entire multi-gigabyte captures into memory at once, and gracefully skips truncated or malformed frames without crashing.

---

## 5. Reporting a Vulnerability

If you discover a security vulnerability in `nshark` (such as a parser crash, path traversal bypass, or credential leak):

1. **Do not open a public GitHub issue.**
2. Please report it privately via **[GitHub Security Advisories](https://github.com/ixbm5/nshark/security/advisories/new)** on the repository.
3. Include a minimal reproduction (such as a synthetic Scapy snippet or anonymized `.pcap`) and expected vs. actual behavior. We aim to acknowledge reports within 48 hours and release a patch promptly.
