"""DNS Tunneling detector using Shannon entropy, query length, and TXT record ratios."""

from __future__ import annotations

import logging
import math
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Optional

from nshark.core.models import (
    Alert,
    DetectionType,
    Flow,
    IOC,
    IOCType,
    ParsedPacket,
    Severity,
)
from nshark.detectors.base import BaseDetector

logger = logging.getLogger(__name__)

DNS_QTYPE_NAMES: dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    10: "NULL",
    12: "PTR",
    15: "MX",
    16: "TXT",
    24: "SIG",
    28: "AAAA",
    251: "IXFR",
    252: "AXFR",
    255: "ANY",
}


def shannon_entropy(text: str) -> float:
    """Calculate character-level Shannon entropy of a string."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def extract_dns_query_info(pkt: ParsedPacket) -> Optional[tuple[str, str]]:
    """Extract (qname, qtype_str) from a DNS packet (UDP or TCP wire format)."""
    try:
        if pkt.raw is not None:
            from scapy.all import DNS, DNSQR  # type: ignore[import-untyped]

            if pkt.raw.haslayer(DNS) and pkt.raw[DNS].qr == 0 and pkt.raw.haslayer(DNSQR):
                qr = pkt.raw[DNSQR]
                qname = qr.qname.decode("utf-8", errors="ignore").rstrip(".")
                qtype = DNS_QTYPE_NAMES.get(int(qr.qtype), str(qr.qtype))
                if qname:
                    return qname, qtype
    except Exception:
        pass

    # Fallback: parse DNS wire format from UDP or TCP payload
    if pkt.dst_port == 53 and len(pkt.payload) > 12:
        try:
            data = pkt.payload
            if pkt.protocol == "TCP" and len(data) > 14:
                if int.from_bytes(data[4:6], "big") != 1 and int.from_bytes(data[6:8], "big") == 1:
                    data = data[2:]
            flags = int.from_bytes(data[2:4], "big")
            if (flags >> 15) & 1 != 0:
                return None
            pos = 12
            labels: list[str] = []
            while pos < len(data):
                length = data[pos]
                if length == 0:
                    pos += 1
                    break
                if (length & 0xC0) == 0xC0:
                    pos += 2
                    break
                pos += 1
                labels.append(data[pos : pos + length].decode("ascii", errors="ignore"))
                pos += length
            if labels and pos + 2 <= len(data):
                qtype_num = int.from_bytes(data[pos : pos + 2], "big")
                qtype_str = DNS_QTYPE_NAMES.get(qtype_num, str(qtype_num))
                return ".".join(labels), qtype_str
        except Exception:
            pass

    return None


def split_subdomain_and_base(fqdn: str) -> tuple[str, str]:
    """Split 'a.b.example.com' into ('a.b', 'example.com')."""
    parts = [p for p in fqdn.strip(".").split(".") if p]
    if len(parts) <= 2:
        return "", fqdn
    return ".".join(parts[:-2]), ".".join(parts[-2:])


class DNSTunnelDetector(BaseDetector):
    """Detects DNS tunneling, Zone Transfers (AXFR), SIGRed (CVE-2020-1350), DGA, and DNS TXT C2."""

    name = "DNS Tunneling Detector"
    detection_type = DetectionType.DNS_TUNNELING

    def analyze(
        self,
        packets: list[ParsedPacket],
        flows: list[Flow],
        config: dict[str, Any],
    ) -> list[Alert]:
        """Analyze DNS traffic for tunneling, AXFR, SIGRed (CVE-2020-1350), TXT C2, and DGA/hijacking."""
        import base64
        import re
        from nshark.extractors.dns_logger import is_dga_like

        dns_cfg = config.get("detection", {}).get("dns_tunneling", {})
        entropy_thresh: float = float(dns_cfg.get("entropy_threshold", 3.5))
        min_qlen: int = int(dns_cfg.get("min_query_length", 30))
        min_txt_ratio: float = float(dns_cfg.get("min_txt_ratio", 0.3))

        alerts: list[Alert] = []
        seen_axfr: set[tuple[str, str, str]] = set()
        dga_queries: dict[str, list[tuple[str, str, datetime]]] = defaultdict(list)
        all_queried_domains: set[str] = set()

        # Group queries by (src_ip, base_domain)
        domain_queries: dict[tuple[str, str], list[tuple[str, str, str, datetime]]] = defaultdict(list)
        # Track DNS TXT/NULL response payloads per base_domain
        domain_resp_blobs: dict[str, list[bytes]] = defaultdict(list)

        # SIGRed (CVE-2020-1350) tracking
        sig_queries: dict[tuple[str, str], str] = {}
        sigred_events: dict[tuple[str, str], dict[str, Any]] = {}

        for pkt in packets:
            if pkt.dst_port != 53 and pkt.src_port != 53:
                continue

            # Check DNS server -> client responses (src_port == 53) for SIGRed and TXT/NULL C2 payloads
            if pkt.src_port == 53 and pkt.payload:
                data = pkt.payload
                # Check TCP oversized DNS response (SIGRed CVE-2020-1350: 2-byte TCP length >= 0xF000 with SIG type 0x0018)
                if pkt.protocol == "TCP" and len(data) >= 24:
                    tcp_dns_len = int.from_bytes(data[:2], "big")
                    if tcp_dns_len >= 0xF000 and b"\x00\x18\x00\x01" in data[:64]:
                        pair = (pkt.src_ip, pkt.dst_ip)
                        qdom = sig_queries.get((pkt.dst_ip, pkt.src_ip), "unknown")
                        sigred_events[pair] = {
                            "domain": qdom,
                            "tcp_dns_length": tcp_dns_len,
                            "ts": pkt.timestamp,
                        }
                # Collect response bytes for base domains
                try:
                    if pkt.raw is not None:
                        from scapy.all import DNS, DNSQR  # type: ignore[import-untyped]
                        if pkt.raw.haslayer(DNS) and pkt.raw[DNS].qr == 1 and pkt.raw.haslayer(DNSQR):
                            qn = pkt.raw[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                            _, bdom = split_subdomain_and_base(qn)
                            if bdom:
                                domain_resp_blobs[bdom].append(data)
                except Exception:
                    pass

            info = extract_dns_query_info(pkt)
            if not info:
                continue
            qname, qtype = info
            all_queried_domains.add(qname.lower())

            if qtype == "SIG":
                sig_queries[(pkt.src_ip, pkt.dst_ip)] = qname

            # 1. Detect DNS Zone Transfer (AXFR / IXFR)
            if qtype in ("AXFR", "IXFR") and (pkt.src_ip, pkt.dst_ip, qname) not in seen_axfr:
                seen_axfr.add((pkt.src_ip, pkt.dst_ip, qname))
                alerts.append(
                    Alert(
                        detection_type=DetectionType.DNS_TUNNELING,
                        severity=Severity.HIGH,
                        confidence=95,
                        source_ip=pkt.src_ip,
                        destination_ip=pkt.dst_ip,
                        description=(
                            f"DNS Zone Transfer ({qtype}) requested for domain '{qname}' "
                            f"against DNS server {pkt.dst_ip}"
                        ),
                        details={
                            "query_type": qtype,
                            "domain": qname,
                            "dns_server": pkt.dst_ip,
                            "protocol": pkt.protocol,
                        },
                        timestamp=pkt.timestamp,
                        related_iocs=[
                            IOC(type=IOCType.DOMAIN, value=qname, first_seen=pkt.timestamp)
                        ],
                    )
                )

            # 2. Track DGA-like domains
            if is_dga_like(qname):
                dga_queries[pkt.src_ip].append((qname, pkt.dst_ip, pkt.timestamp))

            sub, base = split_subdomain_and_base(qname)
            if not sub:
                continue
            domain_queries[(pkt.src_ip, base)].append((qname, sub, qtype, pkt.timestamp))

        # Emit CVE-2020-1350 (SIGRed) alerts
        for (mal_dns_ip, victim_ip), sinfo in sigred_events.items():
            alerts.append(
                Alert(
                    detection_type=DetectionType.DNS_TUNNELING,
                    severity=Severity.CRITICAL,
                    confidence=99,
                    source_ip=mal_dns_ip,
                    destination_ip=victim_ip,
                    description=(
                        f"SIGRed Windows DNS Exploit (CVE-2020-1350): Malicious oversized TCP DNS SIG "
                        f"response ({sinfo['tcp_dns_length']:,}B > 64KB integer overflow) for '{sinfo['domain']}'"
                    ),
                    details={
                        "cve": "CVE-2020-1350",
                        "exploit": "SIGRed Windows DNS RCE/DoS",
                        **sinfo,
                    },
                    timestamp=sinfo["ts"],
                )
            )

        # Emit DGA / ISP NXDOMAIN Hijack alerts
        hijack_indicators = [
            d for d in all_queried_domains
            if any(h in d for h in ("searchguide.", "barefruit.", "paxfire.", "dnserror"))
        ]
        for src_ip, dga_list in dga_queries.items():
            # Filter out domains already part of a multi-query DNS tunnel
            tunnel_bases = {b for (_, b), ql in domain_queries.items() if len(ql) >= 5}
            filtered_dga = [
                (q, srv, ts) for q, srv, ts in dga_list
                if split_subdomain_and_base(q)[1] not in tunnel_bases
            ]
            if not filtered_dga:
                continue
            unique_dga = sorted({q for q, _, _ in filtered_dga})
            first_ts = min(ts for _, _, ts in filtered_dga)
            dns_srv = filtered_dga[0][1]
            if hijack_indicators:
                desc = (
                    f"DGA / Non-Existent Domain Query ('{unique_dga[0]}') intercepted by "
                    f"ISP NXDOMAIN Hijacking ('{hijack_indicators[0]}')"
                )
                conf = 88
            else:
                desc = (
                    f"Suspicious DGA / Non-Existent Domain lookup: "
                    f"{', '.join(unique_dga[:3])} ({len(unique_dga)} random domain(s))"
                )
                conf = 82 if len(unique_dga) == 1 else min(95, 80 + len(unique_dga) * 3)

            alerts.append(
                Alert(
                    detection_type=DetectionType.DNS_TUNNELING,
                    severity=Severity.HIGH if conf >= 85 else Severity.MEDIUM,
                    confidence=conf,
                    source_ip=src_ip,
                    destination_ip=dns_srv,
                    description=desc,
                    details={
                        "dga_domains": unique_dga[:10],
                        "isp_hijack_domains": hijack_indicators,
                    },
                    timestamp=first_ts,
                    related_iocs=[
                        IOC(type=IOCType.DOMAIN, value=d, first_seen=first_ts)
                        for d in unique_dga[:5]
                    ],
                )
            )

        for (src_ip, base_domain), qlist in domain_queries.items():
            if len(qlist) < 3:
                continue

            entropies = [shannon_entropy(sub.replace(".", "")) for _, sub, _, _ in qlist]
            lengths = [len(qname) for qname, _, _, _ in qlist]
            txt_or_null = sum(1 for _, _, qt, _ in qlist if qt in ("TXT", "NULL"))
            null_count = sum(1 for _, _, qt, _ in qlist if qt == "NULL")
            cname_count = sum(1 for _, _, qt, _ in qlist if qt == "CNAME")
            mx_count = sum(1 for _, _, qt, _ in qlist if qt == "MX")
            unique_subs = len({sub for _, sub, _, _ in qlist})
            long_high_ent_count = sum(
                1 for e, l in zip(entropies, lengths) if e >= entropy_thresh and l >= 40
            )

            avg_entropy = sum(entropies) / len(entropies)
            avg_length = sum(lengths) / len(lengths)
            txt_ratio = txt_or_null / len(qlist)

            # Check response payloads for TXT C2 commands or tool signatures
            resp_bytes = b"".join(domain_resp_blobs.get(base_domain, []))
            decoded_preview = ""
            # Check for @<base64>@ chunks used in DNS TXT command stagers
            b64_chunks = re.findall(rb"@([A-Za-z0-9+/=]{16,})@", resp_bytes)
            if b64_chunks:
                try:
                    joined_b64 = b"".join(b64_chunks[:4])
                    raw_dec = base64.b64decode(joined_b64 + b"===", validate=False).decode("utf-8", errors="ignore")
                    clean_lines = [ln.strip() for ln in raw_dec.splitlines() if ln.strip() and len(ln.strip()) >= 4]
                    if clean_lines:
                        decoded_preview = " | ".join(clean_lines[:2])[:80]
                except Exception:
                    pass

            # Fingerprint specific DNS tunneling tool
            tool_name = ""
            subs_sample = [sub for _, sub, _, _ in qlist[:25]]
            if any("=auth" in s or "=connect" in s for s in subs_sample):
                tool_name = "dns2tcp"
                for s in subs_sample:
                    b64_part = s.split(".")[0]
                    if len(b64_part) >= 16:
                        try:
                            dec_b = base64.b64decode(b64_part + "===", validate=False)
                            if b"SSH-" in dec_b or b"OpenSSH" in dec_b:
                                decoded_preview = "Tunneled SSHv2 (OpenSSH)"
                                break
                        except Exception:
                            pass
            elif null_count >= 3 or b"VACK" in resp_bytes or re.search(rb"\d+\.\d+\.\d+\.\d+-\d+\.\d+\.\d+\.\d+", resp_bytes):
                tool_name = "iodine"
                m_ip = re.search(rb"(\d+\.\d+\.\d+\.\d+-\d+\.\d+\.\d+\.\d+-\d+-\d+)", resp_bytes)
                if m_ip:
                    decoded_preview = f"Tunnel IP {m_ip.group(1).decode('ascii', errors='ignore')}"
            elif cname_count >= 20 and unique_subs >= 20:
                tool_name = "iodine (CNAME mode)"
            elif all(re.match(r"^[0-9a-f.]{18,}$", s) for s in subs_sample[:5]) and (txt_or_null + mx_count + cname_count) >= len(qlist) * 0.8:
                tool_name = "dnscat2"
            elif b64_chunks or (txt_ratio >= 0.8 and unique_subs >= 10 and len(resp_bytes) >= 1500):
                tool_name = "DNS TXT C2 Stager"

            # Multi-signal confidence scoring
            score = 0
            signals: list[str] = []
            if tool_name:
                score += 45
                signals.append(f"tool={tool_name}")

            if avg_entropy >= entropy_thresh:
                score += 40
                signals.append(f"entropy={avg_entropy:.2f}")
            elif avg_entropy >= entropy_thresh - 0.3:
                score += 20

            if avg_length >= min_qlen:
                score += 30
                signals.append(f"avg_len={avg_length:.0f}")

            if txt_ratio >= min_txt_ratio:
                score += 25
                signals.append(f"TXT/NULL_ratio={txt_ratio:.0%}")

            if long_high_ent_count >= 10:
                score += 45
                signals.append(f"long_high_entropy_queries={long_high_ent_count}")

            if unique_subs >= 100:
                score += 40
                signals.append(f"unique_subdomains={unique_subs}")
            elif unique_subs >= 10:
                score += 20
                signals.append(f"unique_subdomains={unique_subs}")
            elif unique_subs >= 5 and avg_entropy >= entropy_thresh:
                score += 10

            if cname_count >= 20 and unique_subs >= 20:
                score += 15
                signals.append(f"CNAME_queries={cname_count}")

            if decoded_preview:
                score += 25
                signals.append(f"decoded='{decoded_preview}'")

            if score < 55:
                continue

            confidence = min(99, score)
            severity = Severity.CRITICAL if confidence >= 85 else Severity.HIGH
            first_ts = min(ts for _, _, _, ts in qlist)
            label_prefix = f"DNS Tunneling ({tool_name})" if tool_name else "DNS Tunneling"

            alerts.append(
                Alert(
                    detection_type=DetectionType.DNS_TUNNELING,
                    severity=severity,
                    confidence=confidence,
                    source_ip=src_ip,
                    destination_ip=base_domain,
                    description=(
                        f"{label_prefix} suspected via {base_domain} "
                        f"({len(qlist)} queries, {', '.join(signals)})"
                    ),
                    details={
                        "base_domain": base_domain,
                        "tool": tool_name or "generic",
                        "decoded_preview": decoded_preview,
                        "total_queries": len(qlist),
                        "unique_subdomains": unique_subs,
                        "average_entropy": round(avg_entropy, 2),
                        "average_query_length": round(avg_length, 1),
                        "txt_null_ratio": round(txt_ratio, 2),
                        "sample_queries": [q[0] for q in qlist[:5]],
                    },
                    timestamp=first_ts,
                    related_iocs=[
                        IOC(type=IOCType.DOMAIN, value=base_domain, first_seen=first_ts)
                    ],
                )
            )

        logger.info("DNSTunnelDetector found %d alert(s)", len(alerts))
        return alerts

