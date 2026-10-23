"""C2 Beaconing detector using jitter-aware interval statistics (Coefficient of Variation)."""

from __future__ import annotations

import logging
import math
from collections import defaultdict
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


class BeaconingDetector(BaseDetector):
    """Detects periodic Command-and-Control (C2) callbacks, including jittered beacons."""

    name = "C2 Beaconing Detector"
    detection_type = DetectionType.C2_BEACONING

    def analyze(
        self,
        packets: list[ParsedPacket],
        flows: list[Flow],
        config: dict[str, Any],
    ) -> list[Alert]:
        """Analyze outbound connection timestamps for periodic callback intervals."""
        beacon_cfg = config.get("detection", {}).get("beaconing", {})
        min_beacons: int = int(beacon_cfg.get("min_beacons", 10))
        jitter_tolerance: float = float(beacon_cfg.get("jitter_tolerance", 0.15))

        alerts: list[Alert] = []

        # Collect connection initiation timestamps per (src_ip, dst_ip, dst_port)
        conn_times: dict[tuple[str, str, int], list[datetime]] = defaultdict(list)
        DISCOVERY_UDP_PORTS = {53, 67, 68, 123, 137, 138, 161, 500, 1900, 5353, 5355}

        for pkt in packets:
            if pkt.dst_ip.endswith(".255") or pkt.dst_ip.startswith(("224.", "239.", "169.254.", "127.")):
                continue
            if pkt.protocol == "TCP":
                # SYN packet (start of TCP connection) or PSH/ACK in persistent beacon socket
                if ("S" in pkt.flags and "A" not in pkt.flags) or (
                    "P" in pkt.flags and len(pkt.payload) > 0
                ):
                    conn_times[(pkt.src_ip, pkt.dst_ip, pkt.dst_port)].append(pkt.timestamp)
            elif pkt.protocol == "UDP" and pkt.dst_port not in DISCOVERY_UDP_PORTS and pkt.src_port not in DISCOVERY_UDP_PORTS:
                conn_times[(pkt.src_ip, pkt.dst_ip, pkt.dst_port)].append(pkt.timestamp)

        for (src_ip, dst_ip, dst_port), timestamps in conn_times.items():
            if len(timestamps) < min_beacons:
                continue

            timestamps.sort()
            # Deduplicate bursts within 0.2s (retransmissions or multi-packet requests)
            filtered_ts: list[datetime] = [timestamps[0]]
            for ts in timestamps[1:]:
                if (ts - filtered_ts[-1]).total_seconds() >= 0.5:
                    filtered_ts.append(ts)

            if len(filtered_ts) < min_beacons:
                continue

            intervals = [
                (filtered_ts[i] - filtered_ts[i - 1]).total_seconds()
                for i in range(1, len(filtered_ts))
            ]

            mean_interval = sum(intervals) / len(intervals)
            if mean_interval < 1.0:
                # Sub-second floods are scans/DoS, not C2 beaconing
                continue

            variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
            std_dev = math.sqrt(variance)
            cov = std_dev / mean_interval if mean_interval > 0 else 999.0

            if cov > jitter_tolerance:
                continue

            if cov < 0.05:
                confidence = 95
                severity = Severity.CRITICAL
            elif cov < 0.10:
                confidence = 86
                severity = Severity.HIGH
            else:
                confidence = 76
                severity = Severity.HIGH

            alerts.append(
                Alert(
                    detection_type=DetectionType.C2_BEACONING,
                    severity=severity,
                    confidence=confidence,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    description=(
                        f"Periodic C2 Beaconing to {dst_ip}:{dst_port} - "
                        f"{len(filtered_ts)} callbacks, interval {mean_interval:.1f}s ±{std_dev:.1f}s "
                        f"(jitter CoV {cov:.3f})"
                    ),
                    details={
                        "destination_port": dst_port,
                        "beacon_count": len(filtered_ts),
                        "mean_interval_seconds": round(mean_interval, 2),
                        "std_dev_seconds": round(std_dev, 2),
                        "coefficient_of_variation": round(cov, 4),
                        "first_callback": filtered_ts[0].isoformat(),
                        "last_callback": filtered_ts[-1].isoformat(),
                    },
                    timestamp=filtered_ts[0],
                    related_iocs=[IOC(type=IOCType.IP, value=dst_ip, first_seen=filtered_ts[0])],
                )
            )

        logger.info("BeaconingDetector found %d alert(s)", len(alerts))
        return alerts
