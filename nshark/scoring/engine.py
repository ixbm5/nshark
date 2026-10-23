"""Scoring, multi-detector correlation, and timeline generation engine."""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime
from typing import Optional

from nshark.core.models import (
    Alert,
    DetectionType,
    FPTolerance,
    Severity,
    TimelineEvent,
)

logger = logging.getLogger(__name__)


class ScoringEngine:
    """Correlates alerts across detectors, adjusts confidence scores, and builds timelines."""

    def score_and_correlate(
        self,
        alerts: list[Alert],
        fp_tolerance: FPTolerance = FPTolerance.BALANCED,
        min_confidence_override: Optional[int] = None,
    ) -> list[Alert]:
        """Correlate alerts by source/target IP, apply attack-chain boosts, and filter by threshold.

        Args:
            alerts: Raw list of Alert objects from all detectors.
            fp_tolerance: False-positive tolerance preset (strict, balanced, lenient).
            min_confidence_override: Explicit minimum confidence (0-100) if provided.

        Returns:
            Filtered and confidence-sorted list of Alert objects.
        """
        if not alerts:
            return []

        # Group detection types by participating IPs
        ip_detections: dict[str, set[DetectionType]] = defaultdict(set)
        for alert in alerts:
            if alert.source_ip:
                ip_detections[alert.source_ip].add(alert.detection_type)
            if alert.destination_ip:
                ip_detections[alert.destination_ip].add(alert.detection_type)

        # Apply cross-detector correlation boosts
        for alert in alerts:
            src_types = ip_detections.get(alert.source_ip, set())
            dst_types = ip_detections.get(alert.destination_ip, set())
            combined_types = src_types | dst_types

            if len(combined_types) >= 2:
                boost = min(15, (len(combined_types) - 1) * 8)
                alert.confidence = min(99, alert.confidence + boost)
                alert.details["correlated_detections"] = sorted(t.value for t in combined_types)

            # Check for multi-stage attack chains (e.g., Recon/Brute Force -> C2/Exfil)
            has_initial_access = bool(
                combined_types
                & {
                    DetectionType.PORT_SCAN,
                    DetectionType.BRUTE_FORCE,
                    DetectionType.CLEARTEXT_CREDENTIALS,
                }
            )
            has_post_exploitation = bool(
                combined_types
                & {
                    DetectionType.C2_BEACONING,
                    DetectionType.DNS_TUNNELING,
                    DetectionType.DATA_EXFILTRATION,
                    DetectionType.LATERAL_MOVEMENT,
                    DetectionType.REVERSE_SHELL,
                }
            )
            if has_initial_access and has_post_exploitation and len(combined_types) >= 3:
                alert.severity = Severity.CRITICAL
                alert.confidence = min(99, max(alert.confidence, 92))
                alert.details["attack_chain"] = "Possible Full Compromise Chain Detected"

            if "wireshark_filter" not in alert.details:
                alert.details["wireshark_filter"] = self._build_wireshark_filter(alert)

        threshold = (
            min_confidence_override
            if min_confidence_override is not None
            else fp_tolerance.min_confidence
        )
        filtered = [a for a in alerts if a.confidence >= threshold]
        filtered.sort(key=lambda a: (a.confidence, a.severity.value), reverse=True)

        logger.info(
            "ScoringEngine retained %d/%d alert(s) at threshold >= %d%%",
            len(filtered),
            len(alerts),
            threshold,
        )
        return filtered

    def build_timeline(self, alerts: list[Alert]) -> list[TimelineEvent]:
        """Generate a chronological list of TimelineEvent objects from scored alerts."""
        events: list[TimelineEvent] = []
        for alert in alerts:
            ts = alert.timestamp or datetime.utcnow()
            events.append(
                TimelineEvent(
                    timestamp=ts,
                    event_type=alert.detection_type.value,
                    description=alert.description,
                    source_ip=alert.source_ip,
                    destination_ip=alert.destination_ip,
                    severity=alert.severity,
                    details={
                        "confidence": alert.confidence,
                        "mitre_technique": alert.mitre.technique_id if alert.mitre else "",
                    },
                )
            )
        events.sort(key=lambda e: e.timestamp)
        return events

    @staticmethod
    def _build_wireshark_filter(alert: Alert) -> str:
        """Build a copy-pasteable Wireshark display filter for an alert."""
        if alert.detection_type == DetectionType.ARP_SPOOFING:
            if alert.details.get("protocol") == "LLMNR/NBT-NS":
                return f"ip.src == {alert.source_ip} && (udp.port == 5355 || udp.port == 137)"
            mac = alert.details.get("attacker_mac") or alert.details.get("sender_mac")
            if mac:
                return f"arp && eth.src == {mac}"
            return f"arp.src.proto_ipv4 == {alert.source_ip}"

        if alert.detection_type == DetectionType.DNS_TUNNELING:
            return f"dns && ip.src == {alert.source_ip}"

        clauses: list[str] = []
        if alert.source_ip:
            clauses.append(f"ip.addr == {alert.source_ip}")
        if alert.destination_ip and "." in str(alert.destination_ip) and alert.destination_ip[0].isdigit():
            clauses.append(f"ip.addr == {alert.destination_ip}")

        port = alert.details.get("port") or alert.details.get("destination_port")
        if port:
            clauses.append(f"tcp.port == {port} || udp.port == {port}")
        elif alert.detection_type == DetectionType.TLS_ANOMALY:
            clauses.append("tls.handshake")

        return " && ".join(clauses) if clauses else "ip"

