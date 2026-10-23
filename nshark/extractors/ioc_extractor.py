"""Automated Indicator of Compromise (IOC) extraction from network packets."""

from __future__ import annotations

import ipaddress
import logging
import re
from datetime import datetime
from typing import Optional

from nshark.core.flow import reconstruct_flows
from nshark.core.models import Flow, IOC, IOCType, ParsedPacket
from nshark.detectors.dns_tunnel import extract_dns_query_info
from nshark.detectors.tls_analysis import (
    KNOWN_MALICIOUS_HASSH,
    KNOWN_MALICIOUS_JA3,
    KNOWN_MALICIOUS_JA3S,
    parse_ssh_kexinit,
    parse_tls_client_hello,
    parse_tls_server_hello,
)
from nshark.extractors.file_carver import carve_files

logger = logging.getLogger(__name__)

HTTP_HOST_RE = re.compile(r"^Host:\s*([^\r\n:]+)", re.IGNORECASE | re.MULTILINE)
HTTP_REQ_RE = re.compile(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)\s+HTTP/1\.[01]", re.IGNORECASE)
HTTP_UA_RE = re.compile(r"^User-Agent:\s*([^\r\n]+)", re.IGNORECASE | re.MULTILINE)
SMTP_EMAIL_RE = re.compile(
    r"(?:MAIL\s+FROM|RCPT\s+TO):\s*<?([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})>?",
    re.IGNORECASE,
)

SUSPICIOUS_UA_KEYWORDS: tuple[str, ...] = (
    "curl",
    "wget",
    "python-requests",
    "go-http-client",
    "powershell",
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "gobuster",
    "dirbuster",
    "hydra",
    "mozilla/4.0",
)


def is_public_ip(ip_str: str) -> bool:
    """Return True if `ip_str` is a routable public IPv4/IPv6 address."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return not (
            addr.is_private
            or addr.is_loopback
            or addr.is_multicast
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_unspecified
            or ip_str == "255.255.255.255"
        )
    except ValueError:
        return False


def extract_domain_from_dns(pkt: ParsedPacket) -> Optional[str]:
    """Extract queried domain name from a DNS packet if present."""
    info = extract_dns_query_info(pkt)
    if info:
        qname, _ = info
        if "." in qname and not qname.endswith(".arpa"):
            return qname.lower()
    return None


def extract_sni(pkt: ParsedPacket) -> Optional[str]:
    """Extract Server Name Indication (SNI) hostname from a TLS ClientHello payload."""
    data = pkt.payload
    if len(data) < 43:
        return None
    # TLS Handshake record: ContentType 0x16 (22), HandshakeType 0x01 (ClientHello)
    if data[0] != 0x16 or data[5] != 0x01:
        return None

    try:
        pos = 43  # Skip fixed TLS header + ClientHello random
        if pos >= len(data):
            return None
        session_id_len = data[pos]
        pos += 1 + session_id_len

        if pos + 2 > len(data):
            return None
        cipher_suites_len = int.from_bytes(data[pos : pos + 2], "big")
        pos += 2 + cipher_suites_len

        if pos + 1 > len(data):
            return None
        comp_methods_len = data[pos]
        pos += 1 + comp_methods_len

        if pos + 2 > len(data):
            return None
        extensions_len = int.from_bytes(data[pos : pos + 2], "big")
        pos += 2
        end_ext = min(len(data), pos + extensions_len)

        while pos + 4 <= end_ext:
            ext_type = int.from_bytes(data[pos : pos + 2], "big")
            ext_len = int.from_bytes(data[pos + 2 : pos + 4], "big")
            pos += 4
            if ext_type == 0x0000 and pos + 5 <= end_ext:  # server_name extension
                name_type = data[pos + 2]
                name_len = int.from_bytes(data[pos + 3 : pos + 5], "big")
                if name_type == 0 and pos + 5 + name_len <= end_ext:
                    sni = data[pos + 5 : pos + 5 + name_len].decode("ascii", errors="ignore")
                    if "." in sni:
                        return sni.lower()
            pos += ext_len
    except Exception:
        pass
    return None


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def extract_iocs(
    packets: list[ParsedPacket],
    flows: Optional[list[Flow]] = None,
) -> list[IOC]:
    """Extract and deduplicate all IOCs (public IPs, domains, URLs, emails, User-Agents, file & JA3 hashes)."""
    ioc_map: dict[tuple[IOCType, str], IOC] = {}
    context_sets: dict[tuple[IOCType, str], list[str]] = {}

    def _record(ioc_type: IOCType, value: str, ts: Optional[datetime], context: str) -> None:
        val = value.strip()
        if not val:
            return
        key = (ioc_type, val)
        if key not in ioc_map:
            ioc_map[key] = IOC(
                type=ioc_type,
                value=val,
                first_seen=ts,
                last_seen=ts,
                context=context,
            )
            context_sets[key] = [context] if context else []
        else:
            existing = ioc_map[key]
            if ts is not None:
                if existing.first_seen is None or ts < existing.first_seen:
                    existing.first_seen = ts
                if existing.last_seen is None or ts > existing.last_seen:
                    existing.last_seen = ts
            if context and context not in context_sets[key]:
                context_sets[key].append(context)
                shown = context_sets[key][:3]
                extra = len(context_sets[key]) - 3
                existing.context = "; ".join(shown) + (f" (+{extra} more)" if extra > 0 else "")

    for pkt in packets:
        ts = pkt.timestamp

        # 1. Public IP addresses
        if is_public_ip(pkt.src_ip):
            _record(IOCType.IP, pkt.src_ip, ts, f"Inbound from {pkt.src_ip}:{pkt.src_port}")
        if is_public_ip(pkt.dst_ip):
            _record(IOCType.IP, pkt.dst_ip, ts, f"Outbound to {pkt.dst_ip}:{pkt.dst_port}")

        # 2. DNS domains
        dns_domain = extract_domain_from_dns(pkt)
        if dns_domain:
            _record(IOCType.DOMAIN, dns_domain, ts, "DNS Query")

        # 3. TLS SNI domains + JA3/JA3S fingerprints
        sni = extract_sni(pkt)
        if sni:
            _record(IOCType.DOMAIN, sni, ts, f"TLS SNI ({pkt.dst_ip}:{pkt.dst_port})")

        if not pkt.payload:
            continue

        if pkt.protocol == "TCP":
            ch = parse_tls_client_hello(pkt.payload)
            if ch and ch["ja3_hash"] in KNOWN_MALICIOUS_JA3:
                fam = KNOWN_MALICIOUS_JA3[ch["ja3_hash"]]
                _record(IOCType.HASH_MD5, ch["ja3_hash"], ts, f"JA3 Client Fingerprint ({fam})")
            sh = parse_tls_server_hello(pkt.payload)
            if sh and sh["ja3s_hash"] in KNOWN_MALICIOUS_JA3S:
                srv = KNOWN_MALICIOUS_JA3S[sh["ja3s_hash"]]
                _record(IOCType.HASH_MD5, sh["ja3s_hash"], ts, f"JA3S Server Fingerprint ({srv})")
            kex = parse_ssh_kexinit(pkt.payload)
            if kex and kex["hassh"] in KNOWN_MALICIOUS_HASSH:
                htool = KNOWN_MALICIOUS_HASSH[kex["hassh"]]
                _record(IOCType.HASH_MD5, kex["hassh"], ts, f"SSH HASSH Fingerprint ({htool})")

        text = pkt.payload.decode("utf-8", errors="ignore")

        # 4. HTTP Host, URLs, and User-Agents
        req_match = HTTP_REQ_RE.search(text)
        host_match = HTTP_HOST_RE.search(text)
        if host_match:
            host = host_match.group(1).strip().lower()
            if not _is_ip_literal(host) and "." in host:
                _record(IOCType.DOMAIN, host, ts, "HTTP Host Header")
            if req_match:
                method, path = req_match.group(1).upper(), req_match.group(2)
                url = f"http://{host}{path}"
                _record(IOCType.URL, url, ts, f"HTTP {method} from {pkt.src_ip}")

        ua_match = HTTP_UA_RE.search(text)
        if ua_match:
            ua = ua_match.group(1).strip()
            is_susp = any(k in ua.lower() for k in SUSPICIOUS_UA_KEYWORDS) or len(ua.split()) <= 1
            ctx = "Suspicious User-Agent" if is_susp else "HTTP User-Agent"
            _record(IOCType.USER_AGENT, ua, ts, ctx)

        # 5. SMTP email addresses
        for email_match in SMTP_EMAIL_RE.finditer(text):
            email = email_match.group(1).lower()
            _record(IOCType.EMAIL, email, ts, f"SMTP envelope ({pkt.src_ip} -> {pkt.dst_ip})")

    # 6. Carved File Payload Hashes (SHA-256 & MD5)
    try:
        active_flows = flows if flows is not None else reconstruct_flows(packets)
        carved = carve_files(packets, active_flows, output_dir=None)
        default_ts = packets[0].timestamp if packets else None
        for cf in carved:
            _record(IOCType.HASH_SHA256, cf.sha256, default_ts, f"Carved {cf.file_type}: {cf.filename} ({cf.size} B)")
            _record(IOCType.HASH_MD5, cf.md5, default_ts, f"Carved {cf.file_type}: {cf.filename}")
    except Exception:
        pass

    results = list(ioc_map.values())
    logger.info("Extracted %d unique IOCs from %d packets", len(results), len(packets))
    return results
