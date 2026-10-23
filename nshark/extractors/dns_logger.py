"""DNS query timeline extractor with DGA, tunneling, and legitimacy categorization."""

from __future__ import annotations

import logging
from typing import Optional

from nshark.core.models import DNSQuery, ParsedPacket
from nshark.detectors.dns_tunnel import (
    DNS_QTYPE_NAMES,
    extract_dns_query_info,
    shannon_entropy,
    split_subdomain_and_base,
)

logger = logging.getLogger(__name__)

SAFE_BASE_DOMAINS: set[str] = {
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "youtube.com",
    "microsoft.com",
    "windows.com",
    "live.com",
    "office.com",
    "azure.com",
    "apple.com",
    "icloud.com",
    "cloudflare.com",
    "cloudflare-dns.com",
    "amazonaws.com",
    "amazon.com",
    "cloudfront.net",
    "akamai.net",
    "akamaiedge.net",
    "github.com",
    "githubusercontent.com",
    "ubuntu.com",
    "debian.org",
    "mozilla.org",
    "firefox.com",
    "digicert.com",
    "letsencrypt.org",
    "fastly.net",
    "slack.com",
    "zoom.us",
    "linkedin.com",
    "googlesyndication.com",
    "doubleclick.net",
    "google-analytics.com",
    "facebook.com",
    "fbcdn.net",
    "twimg.com",
    "twitter.com",
}

VOWELS = set("aeiou")


def calculate_entropy(s: str) -> float:
    """Compute character-level Shannon entropy."""
    return shannon_entropy(s)


def is_dga_like(domain: str) -> bool:
    """Check if the main domain label exhibits Domain Generation Algorithm (DGA) heuristics."""
    _, base = split_subdomain_and_base(domain.lower())
    parts = base.split(".")
    if not parts:
        return False
    sld = parts[0]  # second-level domain label
    if len(sld) < 10:
        return False

    entropy = calculate_entropy(sld)
    alpha_chars = [c for c in sld if c.isalpha()]
    digit_chars = [c for c in sld if c.isdigit()]
    vowel_count = sum(1 for c in alpha_chars if c in VOWELS)
    vowel_ratio = vowel_count / len(alpha_chars) if alpha_chars else 0.0
    digit_ratio = len(digit_chars) / len(sld)

    if entropy >= 3.4 and (vowel_ratio < 0.25 or digit_ratio > 0.20 or entropy >= 3.95):
        return True
    return False


def categorize_query(query_name: str, query_type: str) -> str:
    """Categorize a DNS query into legit | tunneling | dga | suspicious | unknown."""
    qname_clean = query_name.lower().strip(".")
    sub, base = split_subdomain_and_base(qname_clean)

    if base in SAFE_BASE_DOMAINS:
        return "legit"

    # Standard Active Directory / service discovery SRV lookups
    if qname_clean.startswith(("_ldap.", "_kerberos.", "_gc.", "_msdcs.", "_VLMCS.")):
        return "legit"

    sub_clean = sub.replace(".", "")
    if sub_clean and (
        (calculate_entropy(sub_clean) >= 3.6 and len(sub_clean) >= 20)
        or (query_type in ("TXT", "NULL") and len(qname_clean) >= 35)
    ):
        return "tunneling"

    if is_dga_like(qname_clean):
        return "dga"

    if query_type in ("TXT", "NULL") or len(qname_clean) > 45:
        return "suspicious"

    return "legit" if len(base) <= 18 else "unknown"


def _extract_dns_response(pkt: ParsedPacket) -> Optional[tuple[str, str, str]]:
    """Extract (qname, qtype, answer_summary) from a DNS response packet if available."""
    try:
        if pkt.raw is not None:
            from scapy.all import DNS, DNSQR, DNSRR  # type: ignore[import-untyped]

            if pkt.raw.haslayer(DNS) and pkt.raw[DNS].qr == 1 and pkt.raw.haslayer(DNSQR):
                qr = pkt.raw[DNSQR]
                qname = qr.qname.decode("utf-8", errors="ignore").rstrip(".")
                qtype = DNS_QTYPE_NAMES.get(int(qr.qtype), str(qr.qtype))
                answers: list[str] = []
                if pkt.raw.haslayer(DNSRR):
                    an = pkt.raw[DNS].an
                    while an:
                        rdata = getattr(an, "rdata", "")
                        if isinstance(rdata, bytes):
                            rdata = rdata.decode("utf-8", errors="ignore")
                        elif isinstance(rdata, list):
                            rdata = b"".join(
                                x if isinstance(x, bytes) else str(x).encode() for x in rdata
                            ).decode("utf-8", errors="ignore")
                        if rdata:
                            answers.append(str(rdata).rstrip("."))
                        an = an.payload
                return qname, qtype, ", ".join(answers[:3])
    except Exception:
        pass
    return None


def extract_dns_timeline(packets: list[ParsedPacket]) -> list[DNSQuery]:
    """Build a chronological DNS query timeline with response correlation and categorization."""
    queries: list[DNSQuery] = []
    # Map (qname, qtype) -> most recent DNSQuery waiting for response
    pending: dict[tuple[str, str], DNSQuery] = {}

    for pkt in packets:
        if pkt.dst_port != 53 and pkt.src_port != 53:
            continue

        q_info = extract_dns_query_info(pkt)
        if q_info:
            qname, qtype = q_info
            cat = categorize_query(qname, qtype)
            entry = DNSQuery(
                timestamp=pkt.timestamp,
                query_name=qname,
                query_type=qtype,
                response="",
                source_ip=pkt.src_ip,
                category=cat,
            )
            queries.append(entry)
            pending[(qname.lower(), qtype)] = entry
            continue

        r_info = _extract_dns_response(pkt)
        if r_info:
            qname, qtype, ans = r_info
            matched = pending.get((qname.lower(), qtype))
            if matched and not matched.response:
                matched.response = ans

    queries.sort(key=lambda q: q.timestamp)
    logger.info("Extracted %d DNS timeline queries", len(queries))
    return queries
