"""Data Exfiltration detector using upload/download asymmetry and statistical baseline anomalies."""

from __future__ import annotations

import logging
import math
from collections import defaultdict
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


class ExfiltrationDetector(BaseDetector):
    """Detects abnormal outbound data transfers per flow and per host against session baselines."""

    name = "Data Exfiltration Detector"
    detection_type = DetectionType.DATA_EXFILTRATION

    def analyze(
        self,
        packets: list[ParsedPacket],
        flows: list[Flow],
        config: dict[str, Any],
    ) -> list[Alert]:
        """Analyze flows for asymmetric outbound transfers and volume spikes."""
        exfil_cfg = config.get("detection", {}).get("exfiltration", {})
        ratio_thresh: float = float(exfil_cfg.get("upload_ratio_threshold", 3.0))
        min_bytes: int = int(exfil_cfg.get("min_bytes", 1048576))  # default 1 MB

        alerts: list[Alert] = []
        if not flows:
            return alerts

        # Aggregate outbound/inbound bytes per (src_ip, dst_ip) pair across all flows
        pair_sent: dict[tuple[str, str], int] = defaultdict(int)
        pair_recv: dict[tuple[str, str], int] = defaultdict(int)
        pair_first_ts: dict[tuple[str, str], Optional[datetime]] = {}
        pair_ports: dict[tuple[str, str], set[int]] = defaultdict(set)

        for flow in flows:
            key = (flow.src_ip, flow.dst_ip)
            pair_sent[key] += flow.bytes_sent
            pair_recv[key] += flow.bytes_received
            pair_ports[key].add(flow.dst_port)
            if key not in pair_first_ts or (
                flow.start_time and pair_first_ts[key] and flow.start_time < pair_first_ts[key]
            ):
                pair_first_ts[key] = flow.start_time

        # Compute session-wide baseline of outbound volume per pair
        sent_values = list(pair_sent.values())
        mean_sent = sum(sent_values) / len(sent_values) if sent_values else 0.0
        variance = (
            sum((x - mean_sent) ** 2 for x in sent_values) / len(sent_values)
            if len(sent_values) > 1
            else 0.0
        )
        std_sent = math.sqrt(variance)
        anomaly_cutoff = mean_sent + 2 * std_sent if len(sent_values) >= 3 else min_bytes

        for (src_ip, dst_ip), bytes_out in pair_sent.items():
            bytes_in = max(1, pair_recv[(src_ip, dst_ip)])
            upload_ratio = bytes_out / bytes_in

            is_standard_exfil = bytes_out >= min_bytes and upload_ratio >= ratio_thresh
            is_extreme_asymmetry = bytes_out >= 300_000 and upload_ratio >= 15.0

            if not (is_standard_exfil or is_extreme_asymmetry):
                continue

            mb_out = bytes_out / (1024 * 1024)
            above_baseline = bytes_out > anomaly_cutoff

            confidence = 72
            if mb_out >= 10:
                confidence += 15
            elif mb_out >= 5:
                confidence += 10
            elif mb_out >= 2:
                confidence += 5

            if upload_ratio >= 10.0:
                confidence += 8
            if above_baseline:
                confidence += 5

            confidence = min(97, confidence)
            severity = Severity.CRITICAL if mb_out >= 10 or confidence >= 90 else Severity.HIGH

            alerts.append(
                Alert(
                    detection_type=DetectionType.DATA_EXFILTRATION,
                    severity=severity,
                    confidence=confidence,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    description=(
                        f"Abnormal outbound transfer: {mb_out:.2f} MB sent to {dst_ip} "
                        f"(upload/download ratio {upload_ratio:.1f}x)"
                    ),
                    details={
                        "bytes_sent": bytes_out,
                        "megabytes_sent": round(mb_out, 2),
                        "bytes_received": pair_recv[(src_ip, dst_ip)],
                        "upload_download_ratio": round(upload_ratio, 2),
                        "destination_ports": sorted(pair_ports[(src_ip, dst_ip)]),
                        "exceeds_session_baseline": above_baseline,
                    },
                    timestamp=pair_first_ts.get((src_ip, dst_ip)),
                    related_iocs=[
                        IOC(
                            type=IOCType.IP,
                            value=dst_ip,
                            first_seen=pair_first_ts.get((src_ip, dst_ip)),
                        )
                    ],
                )
            )

        # 2. ICMP Tunneling / Covert Data Smuggling (icmpsh, ptunnel, ping exfil)
        icmp_bytes_by_pair: dict[tuple[str, str], int] = defaultdict(int)
        icmp_pkts_by_pair: dict[tuple[str, str], int] = defaultdict(int)
        icmp_first_ts: dict[tuple[str, str], Optional[datetime]] = {}

        for pkt in packets:
            if pkt.protocol != "ICMP" or not pkt.payload:
                continue
            data = pkt.payload
            # Ignore standard Windows ("abcdefghijklmnop...") and Linux (\x10\x11\x12...) ping payloads <= 64 bytes
            if len(data) <= 64 and (b"abcdefghijklmnop" in data or b"\x10\x11\x12\x13\x14\x15" in data):
                continue
            if len(data) > 64:
                pair = (pkt.src_ip, pkt.dst_ip)
                icmp_bytes_by_pair[pair] += len(data)
                icmp_pkts_by_pair[pair] += 1
                icmp_first_ts.setdefault(pair, pkt.timestamp)

        for (src_ip, dst_ip), total_icmp_bytes in icmp_bytes_by_pair.items():
            pkt_cnt = icmp_pkts_by_pair[(src_ip, dst_ip)]
            if pkt_cnt >= 4 and total_icmp_bytes >= 512:
                alerts.append(
                    Alert(
                        detection_type=DetectionType.DATA_EXFILTRATION,
                        severity=Severity.HIGH,
                        confidence=min(95, 82 + pkt_cnt),
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        description=(
                            f"ICMP Tunneling / Exfiltration: {pkt_cnt} oversized ICMP packets "
                            f"({total_icmp_bytes:,} payload bytes) to {dst_ip}"
                        ),
                        details={
                            "protocol": "ICMP",
                            "icmp_packets": pkt_cnt,
                            "icmp_payload_bytes": total_icmp_bytes,
                            "wireshark_filter": f"icmp && ip.src == {src_ip} && ip.dst == {dst_ip}",
                        },
                        timestamp=icmp_first_ts.get((src_ip, dst_ip)),
                    )
                )

        logger.info("ExfiltrationDetector found %d alert(s)", len(alerts))
        return alerts
