"""Port scan detection module (SYN scan, Connect scan, UDP scan, Horizontal scan)."""

from __future__ import annotations

import logging
import math
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

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


def _port_entropy(ports: list[int]) -> float:
    """Compute Shannon entropy over destination ports to distinguish scans from single-service traffic."""
    if not ports:
        return 0.0
    total = len(ports)
    counts = Counter(ports)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


class PortScanDetector(BaseDetector):
    """Detects vertical (many ports on one host) and horizontal (one port across many hosts) scans."""

    name = "Port Scan Detector"
    detection_type = DetectionType.PORT_SCAN

    def analyze(
        self,
        packets: list[ParsedPacket],
        flows: list[Flow],
        config: dict[str, Any],
    ) -> list[Alert]:
        """Analyze packets for port scanning patterns."""
        scan_cfg = config.get("detection", {}).get("port_scan", {})
        min_ports: int = int(scan_cfg.get("min_ports", 20))
        time_window: float = float(scan_cfg.get("time_window_seconds", 60))

        alerts: list[Alert] = []

        # Group connection attempts by (src_ip, dst_ip) for vertical scans
        # and by (src_ip, dst_port) for horizontal scans
        pair_packets: dict[tuple[str, str], list[ParsedPacket]] = defaultdict(list)
        horiz_targets: dict[tuple[str, int], set[str]] = defaultdict(set)
        horiz_times: dict[tuple[str, int], list[datetime]] = defaultdict(list)

        # Track client-initiated UDP requests so server replies are not treated as scans
        udp_client_requests: set[tuple[str, int, str, int]] = set()
        WELL_KNOWN_UDP_SERVER_PORTS = {53, 67, 68, 123, 137, 161, 443, 500, 1900, 5353}

        for pkt in packets:
            if pkt.protocol == "TCP":
                # Look at SYN-only packets
                if "S" in pkt.flags and "A" not in pkt.flags:
                    pair_packets[(pkt.src_ip, pkt.dst_ip)].append(pkt)
                    horiz_targets[(pkt.src_ip, pkt.dst_port)].add(pkt.dst_ip)
                    horiz_times[(pkt.src_ip, pkt.dst_port)].append(pkt.timestamp)
            elif pkt.protocol == "UDP" and pkt.dst_port > 0:
                if pkt.src_port in WELL_KNOWN_UDP_SERVER_PORTS:
                    continue
                if (pkt.dst_ip, pkt.dst_port, pkt.src_ip, pkt.src_port) in udp_client_requests:
                    continue
                udp_client_requests.add((pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port))
                pair_packets[(pkt.src_ip, pkt.dst_ip)].append(pkt)

        # 1. Vertical scan check (sliding window of `time_window` seconds)
        for (src_ip, dst_ip), pkts in pair_packets.items():
            if len(pkts) < min_ports:
                continue

            pkts.sort(key=lambda p: p.timestamp)
            all_ports = [p.dst_port for p in pkts]
            unique_ports = set(all_ports)

            if len(unique_ports) < min_ports:
                continue

            # Find maximum unique ports within time_window
            max_unique_in_window = 0
            best_window_duration = 0.0
            best_start_time = pkts[0].timestamp
            left = 0
            port_counts: Counter[int] = Counter()

            for right in range(len(pkts)):
                port_counts[pkts[right].dst_port] += 1
                while (
                    pkts[right].timestamp - pkts[left].timestamp
                ).total_seconds() > time_window:
                    left_port = pkts[left].dst_port
                    port_counts[left_port] -= 1
                    if port_counts[left_port] <= 0:
                        del port_counts[left_port]
                    left += 1

                cur_unique = len(port_counts)
                if cur_unique > max_unique_in_window:
                    max_unique_in_window = cur_unique
                    best_start_time = pkts[left].timestamp
                    best_window_duration = max(
                        0.1,
                        (pkts[right].timestamp - pkts[left].timestamp).total_seconds(),
                    )

            if max_unique_in_window < min_ports:
                continue

            entropy = _port_entropy(all_ports)
            if entropy < 2.5:
                # Low entropy means repeated hits to very few ports, not a port scan
                continue

            # Determine scan type & confidence
            tcp_count = sum(1 for p in pkts if p.protocol == "TCP")
            scan_subtype = "SYN Port Scan" if tcp_count >= len(pkts) // 2 else "UDP Port Scan"

            if max_unique_in_window >= 500:
                confidence = 95
                severity = Severity.HIGH
            elif max_unique_in_window >= 100:
                confidence = 88
                severity = Severity.HIGH
            elif max_unique_in_window >= 50:
                confidence = 80
                severity = Severity.MEDIUM
            else:
                confidence = 68 + min(15, int((max_unique_in_window - min_ports) * 0.4))
                severity = Severity.MEDIUM

            # Boost confidence if port entropy is very high (> 4.5)
            if entropy >= 4.5:
                confidence = min(98, confidence + 5)

            sample_ports = sorted(unique_ports)[:15]
            alerts.append(
                Alert(
                    detection_type=DetectionType.PORT_SCAN,
                    severity=severity,
                    confidence=confidence,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    description=(
                        f"{scan_subtype}: {max_unique_in_window} unique ports scanned "
                        f"in {best_window_duration:.1f}s (entropy {entropy:.2f})"
                    ),
                    details={
                        "scan_type": scan_subtype,
                        "unique_ports_scanned": len(unique_ports),
                        "max_ports_in_window": max_unique_in_window,
                        "window_duration_seconds": round(best_window_duration, 2),
                        "port_entropy": round(entropy, 2),
                        "sample_ports": sample_ports,
                        "total_probe_packets": len(pkts),
                    },
                    timestamp=best_start_time,
                    related_iocs=[IOC(type=IOCType.IP, value=src_ip, first_seen=best_start_time)],
                )
            )

        # 2. Horizontal scan check (1 port across many target hosts - only count unanswered/SYN probe flows)
        horiz_probe_targets: dict[tuple[str, int], set[str]] = defaultdict(set)
        horiz_probe_times: dict[tuple[str, int], list[datetime]] = defaultdict(list)
        for flow in flows:
            if flow.protocol == "TCP" and flow.dst_port > 0:
                # A real horizontal scan probe has no application payload exchanged
                if flow.bytes_sent == 0 and flow.bytes_received == 0 and flow.packet_count <= 4:
                    horiz_probe_targets[(flow.src_ip, flow.dst_port)].add(flow.dst_ip)
                    if flow.start_time:
                        horiz_probe_times[(flow.src_ip, flow.dst_port)].append(flow.start_time)

        for (src_ip, dst_port), target_ips in horiz_probe_targets.items():
            if len(target_ips) >= max(10, min_ports // 2):
                times = sorted(horiz_probe_times[(src_ip, dst_port)])
                duration = (times[-1] - times[0]).total_seconds() if len(times) > 1 else 0.1
                confidence = min(95, 70 + len(target_ips))
                alerts.append(
                    Alert(
                        detection_type=DetectionType.PORT_SCAN,
                        severity=Severity.HIGH if len(target_ips) >= 25 else Severity.MEDIUM,
                        confidence=confidence,
                        source_ip=src_ip,
                        destination_ip=f"{len(target_ips)} hosts (port {dst_port})",
                        description=(
                            f"Horizontal Sweep on port {dst_port}: "
                            f"{len(target_ips)} unique hosts probed in {duration:.1f}s"
                        ),
                        details={
                            "scan_type": "Horizontal Port Sweep",
                            "target_port": dst_port,
                            "hosts_probed": len(target_ips),
                            "sample_targets": sorted(target_ips)[:10],
                            "duration_seconds": round(duration, 2),
                        },
                        timestamp=times[0] if times else None,
                        related_iocs=[
                            IOC(type=IOCType.IP, value=src_ip, first_seen=times[0] if times else None)
                        ],
                    )
                )

        # 3. Active OS Fingerprinting (nmap -O U1 UDP probe 'C'*300 & Xmas/Null/SYN-FIN TCP probes)
        os_probe_Evidence: dict[tuple[str, str], list[tuple[str, datetime]]] = defaultdict(list)
        for pkt in packets:
            if pkt.protocol == "UDP" and len(pkt.payload) >= 100 and b"C" * 100 in pkt.payload:
                os_probe_Evidence[(pkt.src_ip, pkt.dst_ip)].append(("Nmap U1 UDP probe ('C'*300)", pkt.timestamp))
            elif pkt.protocol == "TCP":
                fl = pkt.flags
                if "F" in fl and "P" in fl and "U" in fl:
                    os_probe_Evidence[(pkt.src_ip, pkt.dst_ip)].append(("TCP Xmas probe (FPU)", pkt.timestamp))
                elif "S" in fl and "F" in fl:
                    os_probe_Evidence[(pkt.src_ip, pkt.dst_ip)].append(("TCP SYN+FIN OS probe", pkt.timestamp))
                elif fl == "":
                    os_probe_Evidence[(pkt.src_ip, pkt.dst_ip)].append(("TCP Null probe", pkt.timestamp))

        for (src_ip, dst_ip), ev_list in os_probe_Evidence.items():
            probe_types = sorted({e[0] for e in ev_list})
            first_ts = min(e[1] for e in ev_list)
            alerts.append(
                Alert(
                    detection_type=DetectionType.PORT_SCAN,
                    severity=Severity.MEDIUM,
                    confidence=90,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    description=(
                        f"Active OS Fingerprinting (nmap -O / Stealth Scan): "
                        f"{', '.join(probe_types)} ({len(ev_list)} probe packets)"
                    ),
                    details={
                        "scan_type": "Active OS Fingerprinting",
                        "probe_signatures": probe_types,
                        "probe_count": len(ev_list),
                    },
                    timestamp=first_ts,
                    related_iocs=[IOC(type=IOCType.IP, value=src_ip, first_seen=first_ts)],
                )
            )

        logger.info("PortScanDetector found %d alert(s)", len(alerts))
        return alerts
