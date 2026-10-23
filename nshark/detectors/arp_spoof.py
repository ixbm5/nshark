"""ARP Spoofing / Adversary-in-the-Middle (T1557.002) detector."""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime
from typing import Any, Optional

from nshark.core.models import (
    Alert,
    DetectionType,
    Flow,
    ParsedPacket,
    Severity,
)
from nshark.detectors.base import BaseDetector

logger = logging.getLogger(__name__)

BROADCAST_MACS: set[str] = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", ""}


def _parse_arp_flags(flags: str) -> tuple[int, str, str]:
    """Extract (op, hwsrc, hwdst) from ParsedPacket.flags on ARP packets."""
    op = 0
    hwsrc = ""
    hwdst = ""
    for part in flags.split(";"):
        if part.startswith("op="):
            try:
                op = int(part[3:])
            except ValueError:
                pass
        elif part.startswith("hwsrc="):
            hwsrc = part[6:].strip().lower()
        elif part.startswith("hwdst="):
            hwdst = part[6:].strip().lower()
    return op, hwsrc, hwdst


class ARPSpoofDetector(BaseDetector):
    """Detects ARP cache poisoning and Layer-2 MITM attacks."""

    name = "ARP Spoofing Detector"
    detection_type = DetectionType.ARP_SPOOFING

    def analyze(
        self,
        packets: list[ParsedPacket],
        flows: list[Flow],
        config: dict[str, Any],
    ) -> list[Alert]:
        """Analyze ARP frames for conflicting MAC-to-IP bindings and gratuitous ARP floods."""
        alerts: list[Alert] = []

        # Map IP -> set of MACs claiming that IP in ARP replies (op=2) or requests
        ip_to_macs: dict[str, set[str]] = defaultdict(set)
        # Map MAC -> set of IPs claimed by that MAC in ARP replies (op=2) vs ARP requests (op=1)
        mac_to_reply_ips: dict[str, set[str]] = defaultdict(set)
        mac_to_req_ips: dict[str, set[str]] = defaultdict(set)
        mac_req_counts: dict[str, int] = defaultdict(int)
        mac_req_targets: dict[str, set[str]] = defaultdict(set)
        # Count ARP replies per (hwsrc, psrc, pdst)
        reply_counts: dict[tuple[str, str, str], int] = defaultdict(int)
        first_seen_ip: dict[str, datetime] = {}
        first_seen_mac: dict[str, datetime] = {}

        for pkt in packets:
            if pkt.protocol != "ARP":
                continue

            op, hwsrc, _ = _parse_arp_flags(pkt.flags)
            psrc = pkt.src_ip
            pdst = pkt.dst_ip

            if hwsrc in BROADCAST_MACS or psrc in ("0.0.0.0", "255.255.255.255", ""):
                continue

            if psrc not in first_seen_ip:
                first_seen_ip[psrc] = pkt.timestamp
            if hwsrc not in first_seen_mac:
                first_seen_mac[hwsrc] = pkt.timestamp

            ip_to_macs[psrc].add(hwsrc)
            if op == 2:
                mac_to_reply_ips[hwsrc].add(psrc)
                reply_counts[(hwsrc, psrc, pdst)] += 1
            elif op == 1:
                mac_to_req_ips[hwsrc].add(psrc)
                mac_req_counts[hwsrc] += 1
                if pdst not in ("0.0.0.0", "255.255.255.255", ""):
                    mac_req_targets[hwsrc].add(pdst)

        alerted_ips: set[str] = set()
        alerted_macs: set[str] = set()

        # 1. Multiple MAC addresses claiming the same IP address (classic ARP poisoning)
        for ip_addr, macs in ip_to_macs.items():
            if len(macs) >= 2:
                alerted_ips.add(ip_addr)
                mac_list = sorted(macs)
                alerts.append(
                    Alert(
                        detection_type=DetectionType.ARP_SPOOFING,
                        severity=Severity.CRITICAL,
                        confidence=94,
                        source_ip=ip_addr,
                        destination_ip=None,
                        description=(
                            f"ARP Cache Poisoning: IP {ip_addr} claimed by {len(mac_list)} "
                            f"different MAC addresses ({', '.join(mac_list)})"
                        ),
                        details={
                            "spoofed_ip": ip_addr,
                            "mac_addresses": mac_list,
                        },
                        timestamp=first_seen_ip.get(ip_addr),
                    )
                )

        # 2. Single attacker MAC claiming multiple distinct IPs with ARP replies (MITM relay)
        all_macs = set(mac_to_reply_ips.keys()) | set(mac_to_req_ips.keys())
        for mac_addr in all_macs:
            reply_ips = mac_to_reply_ips.get(mac_addr, set())
            all_claimed_ips = reply_ips | mac_to_req_ips.get(mac_addr, set())
            if reply_ips and len(all_claimed_ips) >= 2:
                ip_list = sorted(all_claimed_ips)
                if not all(ip in alerted_ips for ip in ip_list):
                    alerted_macs.add(mac_addr)
                    alerts.append(
                        Alert(
                            detection_type=DetectionType.ARP_SPOOFING,
                            severity=Severity.HIGH,
                            confidence=90,
                            source_ip=ip_list[-1],
                            destination_ip=ip_list[0],
                            description=(
                                f"ARP MITM Relay: MAC {mac_addr} sent ARP replies impersonating "
                                f"{len(ip_list)} hosts ({', '.join(ip_list[:4])})"
                            ),
                            details={
                                "attacker_mac": mac_addr,
                                "impersonated_ips": ip_list,
                            },
                            timestamp=first_seen_mac.get(mac_addr),
                        )
                    )

        # 2b. ARP Broadcast Request Storm / Multi-Subnet Gateway Flood (op=1)
        for mac_addr, req_count in mac_req_counts.items():
            req_ips = sorted(mac_to_req_ips[mac_addr])
            target_ips = sorted(mac_req_targets[mac_addr])
            if mac_addr not in alerted_macs and (req_count >= 50 or len(req_ips) >= 3):
                alerts.append(
                    Alert(
                        detection_type=DetectionType.ARP_SPOOFING,
                        severity=Severity.HIGH,
                        confidence=91,
                        source_ip=req_ips[0] if req_ips else mac_addr,
                        destination_ip=target_ips[0] if target_ips else "255.255.255.255",
                        description=(
                            f"ARP Broadcast Request Storm: MAC {mac_addr} flooded {req_count} who-has "
                            f"requests claiming {len(req_ips)} source IP(s) ({', '.join(req_ips[:4])}) "
                            f"probing {len(target_ips)} target IP(s)"
                        ),
                        details={
                            "sender_mac": mac_addr,
                            "request_count": req_count,
                            "claimed_source_ips": req_ips,
                            "target_ips_count": len(target_ips),
                        },
                        timestamp=first_seen_mac.get(mac_addr),
                    )
                )

        # 3. High-rate unsolicited ARP reply flood (>= 15 replies for same binding)
        for (hwsrc, psrc, pdst), count in reply_counts.items():
            if count >= 15 and psrc not in alerted_ips:
                alerted_ips.add(psrc)
                alerts.append(
                    Alert(
                        detection_type=DetectionType.ARP_SPOOFING,
                        severity=Severity.HIGH,
                        confidence=85,
                        source_ip=psrc,
                        destination_ip=pdst,
                        description=(
                            f"Unsolicited ARP Reply Flood: {count} is-at replies from {hwsrc} "
                            f"claiming {psrc} -> {pdst}"
                        ),
                        details={
                            "sender_mac": hwsrc,
                            "claimed_ip": psrc,
                            "target_ip": pdst,
                            "reply_count": count,
                        },
                        timestamp=first_seen_ip.get(psrc),
                    )
                )

        # 4. LLMNR (UDP 5355) & NBT-NS (UDP 137) Name Poisoning (Responder / T1557.001)
        # Track responder_ip -> set of spoofed hostnames & victims
        poison_names_by_ip: dict[str, set[str]] = defaultdict(set)
        poison_victims_by_ip: dict[str, set[str]] = defaultdict(set)
        poison_proto_by_ip: dict[str, set[str]] = defaultdict(set)
        first_poison_ts: dict[str, datetime] = {}

        for pkt in packets:
            if pkt.protocol != "UDP" or pkt.src_port not in (5355, 137):
                continue
            payload = pkt.payload
            if not payload or len(payload) < 16:
                continue
            # Check DNS/NBNS Response flag (QR == 1 -> bit 7 of byte 2)
            if not (payload[2] & 0x80):
                continue

            responder_ip = pkt.src_ip
            victim_ip = pkt.dst_ip
            first_poison_ts.setdefault(responder_ip, pkt.timestamp)
            poison_victims_by_ip[responder_ip].add(victim_ip)

            if pkt.src_port == 5355:
                poison_proto_by_ip[responder_ip].add("LLMNR")
                # Extract LLMNR query name starting at byte 12
                idx = 12
                labels: list[str] = []
                while idx < len(payload):
                    ln = payload[idx]
                    if ln == 0 or ln > 63 or idx + 1 + ln > len(payload):
                        break
                    labels.append(payload[idx + 1 : idx + 1 + ln].decode("ascii", errors="ignore"))
                    idx += 1 + ln
                if labels:
                    poison_names_by_ip[responder_ip].add(".".join(labels).upper())
            elif pkt.src_port == 137 and len(payload) >= 46 and payload[12] == 0x20:
                poison_proto_by_ip[responder_ip].add("NBT-NS")
                # Decode 32-byte NetBIOS first-level encoded name
                encoded = payload[13:45]
                chars: list[int] = []
                for i in range(0, 30, 2):
                    hi = encoded[i] - ord("A")
                    lo = encoded[i + 1] - ord("A")
                    if 0 <= hi <= 15 and 0 <= lo <= 15:
                        chars.append((hi << 4) | lo)
                nb_name = bytes(chars).decode("ascii", errors="ignore").strip()
                if nb_name:
                    poison_names_by_ip[responder_ip].add(nb_name.upper())

        for responder_ip, names in poison_names_by_ip.items():
            has_wpad = any(n.startswith("WPAD") for n in names)
            if len(names) >= 2 or has_wpad:
                sorted_names = sorted(names)
                sorted_victims = sorted(poison_victims_by_ip[responder_ip])
                protos = "/".join(sorted(poison_proto_by_ip[responder_ip]))
                alerts.append(
                    Alert(
                        detection_type=DetectionType.ARP_SPOOFING,
                        severity=Severity.CRITICAL if has_wpad or len(names) >= 3 else Severity.HIGH,
                        confidence=min(96, 86 + len(names) * 3),
                        source_ip=responder_ip,
                        destination_ip=sorted_victims[0] if sorted_victims else "",
                        description=(
                            f"{protos} Poisoning (Responder): {responder_ip} answered name queries "
                            f"for {len(sorted_names)} host(s) ({', '.join(sorted_names[:4])})"
                        ),
                        details={
                            "protocol": "LLMNR/NBT-NS",
                            "port": 5355 if "LLMNR" in protos else 137,
                            "spoofed_names": sorted_names,
                            "victim_ips": sorted_victims,
                        },
                        timestamp=first_poison_ts.get(responder_ip),
                    )
                )

        # 5. DHCP Spoofing / Rogue DHCP Server (T1557.003) & DHCP Starvation (UDP 67/68)
        dhcp_servers: dict[str, dict[str, set[str]]] = defaultdict(lambda: {"routers": set(), "dns": set()})
        dhcp_discover_chaddrs: set[str] = set()
        dhcp_discover_src: str = "0.0.0.0"
        first_dhcp_ts: Optional[datetime] = None

        for pkt in packets:
            if pkt.protocol != "UDP" or (pkt.src_port not in (67, 68) and pkt.dst_port not in (67, 68)):
                continue
            pay = pkt.payload
            if not pay or len(pay) < 240:
                continue
            magic = pay.find(b"\x63\x82\x53\x63")
            if magic < 0:
                continue

            if first_dhcp_ts is None:
                first_dhcp_ts = pkt.timestamp

            chaddr = ":".join(f"{b:02x}" for b in pay[28:34])
            msg_type = 0
            router_ip = ""
            dns_ip = ""

            opt_idx = magic + 4
            while opt_idx + 2 <= len(pay):
                opt_code = pay[opt_idx]
                if opt_code == 255:
                    break
                if opt_code == 0:
                    opt_idx += 1
                    continue
                opt_len = pay[opt_idx + 1]
                opt_val = pay[opt_idx + 2 : opt_idx + 2 + opt_len]
                if opt_code == 53 and len(opt_val) >= 1:
                    msg_type = opt_val[0]
                elif opt_code == 3 and len(opt_val) >= 4:
                    router_ip = ".".join(str(b) for b in opt_val[:4])
                elif opt_code == 6 and len(opt_val) >= 4:
                    dns_ip = ".".join(str(b) for b in opt_val[:4])
                opt_idx += 2 + opt_len

            if msg_type == 1:  # DHCPDISCOVER
                dhcp_discover_chaddrs.add(chaddr)
                if pkt.src_ip not in ("0.0.0.0", "255.255.255.255"):
                    dhcp_discover_src = pkt.src_ip
            elif msg_type in (2, 5) and pkt.src_ip not in ("0.0.0.0", "255.255.255.255"):  # OFFER or ACK
                if router_ip:
                    dhcp_servers[pkt.src_ip]["routers"].add(router_ip)
                if dns_ip:
                    dhcp_servers[pkt.src_ip]["dns"].add(dns_ip)
                else:
                    _ = dhcp_servers[pkt.src_ip]

        if len(dhcp_servers) >= 2:
            srv_list = sorted(dhcp_servers.keys())
            alerts.append(
                Alert(
                    detection_type=DetectionType.ARP_SPOOFING,
                    severity=Severity.CRITICAL,
                    confidence=91,
                    source_ip=srv_list[-1],
                    destination_ip=srv_list[0],
                    description=(
                        f"Rogue DHCP Server / DHCP Spoofing: {len(srv_list)} competing DHCP servers "
                        f"offering leases on LAN ({', '.join(srv_list)})"
                    ),
                    details={
                        "protocol": "DHCP",
                        "port": 67,
                        "dhcp_servers": srv_list,
                    },
                    timestamp=first_dhcp_ts,
                )
            )

        if len(dhcp_discover_chaddrs) >= 15:
            alerts.append(
                Alert(
                    detection_type=DetectionType.ARP_SPOOFING,
                    severity=Severity.HIGH,
                    confidence=92,
                    source_ip=dhcp_discover_src,
                    destination_ip="255.255.255.255",
                    description=(
                        f"DHCP Starvation Attack: {len(dhcp_discover_chaddrs)} DHCPDISCOVER requests "
                        f"with distinct spoofed client MACs"
                    ),
                    details={
                        "protocol": "DHCP",
                        "port": 67,
                        "unique_client_macs": len(dhcp_discover_chaddrs),
                    },
                    timestamp=first_dhcp_ts,
                )
            )

        logger.info("ARPSpoofDetector produced %d alerts", len(alerts))
        return alerts
