"""Brute force attack detector for SSH, FTP, HTTP, RDP, and SMB."""

from __future__ import annotations

import logging
from collections import defaultdict
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

# Map ports to service names
AUTH_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Alt",
}

# Ports where short TCP connections alone (without payload inspection) indicate auth attempts
CONNECTION_AUTH_PORTS: set[int] = {21, 22, 23, 445, 3306, 3389, 5432}

FAILURE_MARKERS: tuple[bytes, ...] = (
    b"530 Login incorrect",
    b"530 Authentication failed",
    b"401 Unauthorized",
    b"403 Forbidden",
    b"Invalid password",
    b"Login failed",
    b"Access denied",
)

SUCCESS_MARKERS: tuple[bytes, ...] = (
    b"230 Login successful",
    b"230 User logged in",
    b"HTTP/1.1 200 OK",
    b"HTTP/1.0 200 OK",
)


class BruteForceDetector(BaseDetector):
    """Detects single-source and distributed brute-force attacks against authentication services."""

    name = "Brute Force Detector"
    detection_type = DetectionType.BRUTE_FORCE

    def analyze(
        self,
        packets: list[ParsedPacket],
        flows: list[Flow],
        config: dict[str, Any],
    ) -> list[Alert]:
        """Analyze flows and packets for repeated authentication failures and short-lived auth attempts."""
        bf_cfg = config.get("detection", {}).get("brute_force", {})
        min_attempts: int = int(bf_cfg.get("min_attempts", 10))

        alerts: list[Alert] = []

        # Track flows per (src_ip, dst_ip, dst_port)
        grouped_flows: dict[tuple[str, str, int], list[Flow]] = defaultdict(list)
        # Also track HTTP/FTP explicit auth attempts inside a single connection or across connections
        payload_failures: dict[tuple[str, str, int], int] = defaultdict(int)
        payload_successes: dict[tuple[str, str, int], int] = defaultdict(int)
        first_seen_map: dict[tuple[str, str, int], Any] = {}

        for flow in flows:
            target_port = flow.dst_port if flow.dst_port in CONNECTION_AUTH_PORTS else (
                flow.src_port if flow.src_port in CONNECTION_AUTH_PORTS else 0
            )
            if target_port == 0:
                continue

            # Determine client and server
            if flow.dst_port == target_port:
                client_ip, server_ip = flow.src_ip, flow.dst_ip
            else:
                client_ip, server_ip = flow.dst_ip, flow.src_ip

            key = (client_ip, server_ip, target_port)
            grouped_flows[key].append(flow)
            if key not in first_seen_map or (flow.start_time and flow.start_time < first_seen_map[key]):
                first_seen_map[key] = flow.start_time

        # Inspect packet payloads for explicit auth failure/success responses or repeated FTP/HTTP auth requests
        for pkt in packets:
            if not pkt.payload:
                continue

            if pkt.src_port in AUTH_PORTS:
                # Response from server -> client is dst_ip
                key = (pkt.dst_ip, pkt.src_ip, pkt.src_port)
                for marker in FAILURE_MARKERS:
                    if marker.lower() in pkt.payload.lower():
                        payload_failures[key] += 1
                        if key not in first_seen_map:
                            first_seen_map[key] = pkt.timestamp
                        break
                for marker in SUCCESS_MARKERS:
                    if marker.lower() in pkt.payload.lower():
                        payload_successes[key] += 1
                        break
            elif pkt.dst_port in AUTH_PORTS:
                # Request from client -> check for FTP USER/PASS or HTTP login POST/Basic Auth
                key = (pkt.src_ip, pkt.dst_ip, pkt.dst_port)
                lower_pay = pkt.payload.lower()
                if (
                    b"pass " in lower_pay
                    or b"authorization: basic" in lower_pay
                    or (b"post " in lower_pay and (b"password=" in lower_pay or b"pass=" in lower_pay))
                ):
                    payload_failures[key] += 1
                    if key not in first_seen_map:
                        first_seen_map[key] = pkt.timestamp

        # Evaluate each (client_ip, server_ip, port) group
        all_keys = set(grouped_flows.keys()) | set(payload_failures.keys())
        target_distributed: dict[tuple[str, int], set[str]] = defaultdict(set)

        for key in all_keys:
            client_ip, server_ip, port = key
            service = AUTH_PORTS.get(port, f"Port-{port}")
            flist = grouped_flows.get(key, [])

            # Count short-lived connections (typical of SSH/RDP/FTP connection-per-attempt brute force)
            short_flows = [
                f for f in flist
                if f.duration <= 10.0 and (f.bytes_sent + f.bytes_received) < 8000
            ]
            long_flows = [
                f for f in flist
                if f.duration > 15.0 or (f.bytes_sent + f.bytes_received) >= 8000
            ]

            # Check attempt rate: slow periodic connections (< 4 per minute) without explicit auth failures are beacons, not brute force
            if short_flows and payload_failures.get(key, 0) == 0:
                flow_times = sorted(f.start_time for f in short_flows if f.start_time)
                if len(flow_times) >= 2:
                    span_minutes = max(0.1, (flow_times[-1] - flow_times[0]).total_seconds() / 60.0)
                    if (len(short_flows) / span_minutes) < 4.0:
                        continue

            attempts = max(len(short_flows), payload_failures.get(key, 0))
            compromise_likely = len(long_flows) > 0 or payload_successes.get(key, 0) > 0

            if attempts >= 3:
                target_distributed[(server_ip, port)].add(client_ip)

            if attempts < min_attempts:
                continue

            if attempts >= 50 and compromise_likely:
                confidence = 95
                severity = Severity.CRITICAL
            elif attempts >= 25:
                confidence = 88 if compromise_likely else 82
                severity = Severity.HIGH
            else:
                confidence = 78 if compromise_likely else 68
                severity = Severity.HIGH if compromise_likely else Severity.MEDIUM

            status_note = "followed by successful session (POSSIBLE COMPROMISE)" if compromise_likely else "all failed/short-lived"
            alerts.append(
                Alert(
                    detection_type=DetectionType.BRUTE_FORCE,
                    severity=severity,
                    confidence=confidence,
                    source_ip=client_ip,
                    destination_ip=server_ip,
                    description=(
                        f"{service} Brute Force on port {port}: "
                        f"{attempts} rapid auth attempts, {status_note}"
                    ),
                    details={
                        "service": service,
                        "port": port,
                        "attempts": attempts,
                        "short_connections": len(short_flows),
                        "long_connections": len(long_flows),
                        "explicit_failures": payload_failures.get(key, 0),
                        "potential_compromise": compromise_likely,
                    },
                    timestamp=first_seen_map.get(key),
                    related_iocs=[IOC(type=IOCType.IP, value=client_ip, first_seen=first_seen_map.get(key))],
                )
            )

        # Evaluate distributed brute force (many IPs attacking the same server:port)
        for (server_ip, port), sources in target_distributed.items():
            if len(sources) >= 5:
                service = AUTH_PORTS.get(port, f"Port-{port}")
                alerts.append(
                    Alert(
                        detection_type=DetectionType.BRUTE_FORCE,
                        severity=Severity.HIGH,
                        confidence=min(92, 70 + len(sources) * 2),
                        source_ip=f"{len(sources)} distributed IPs",
                        destination_ip=server_ip,
                        description=(
                            f"Distributed {service} Brute Force against {server_ip}:{port} "
                            f"from {len(sources)} unique source IPs"
                        ),
                        details={
                            "service": service,
                            "port": port,
                            "source_count": len(sources),
                            "sample_sources": sorted(sources)[:10],
                        },
                        timestamp=None,
                    )
                )

        logger.info("BruteForceDetector found %d alert(s)", len(alerts))
        return alerts
