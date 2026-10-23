"""CSV exporter for NSHARK IOCs and Alerts (SIEM/Splunk/QRadar ingestion)."""

from __future__ import annotations

import csv

from nshark.core.models import Alert, IOC


def export_csv(iocs: list[IOC], output_path: str) -> None:
    """Export extracted IOCs to a CSV file."""
    fieldnames = [
        "type",
        "value",
        "first_seen",
        "last_seen",
        "context",
        "enrichment_malicious",
        "enrichment_provider",
        "confidence",
    ]
    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for ioc in iocs:
            malicious = False
            providers: list[str] = []
            max_conf = 0
            for prov, info in ioc.enrichment.items():
                if isinstance(info, dict):
                    providers.append(prov)
                    if info.get("malicious"):
                        malicious = True
                    max_conf = max(max_conf, int(info.get("confidence_score", 0)))

            writer.writerow(
                {
                    "type": ioc.type.value,
                    "value": ioc.value,
                    "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else "",
                    "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else "",
                    "context": ioc.context,
                    "enrichment_malicious": malicious,
                    "enrichment_provider": ",".join(providers),
                    "confidence": max_conf,
                }
            )


def export_alerts_csv(alerts: list[Alert], output_path: str) -> None:
    """Export detection alerts to a CSV file."""
    fieldnames = [
        "detection_type",
        "severity",
        "confidence",
        "source_ip",
        "destination_ip",
        "description",
        "mitre_technique",
        "mitre_tactic",
    ]
    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for alert in alerts:
            writer.writerow(
                {
                    "detection_type": alert.detection_type.value,
                    "severity": alert.severity.value,
                    "confidence": alert.confidence,
                    "source_ip": alert.source_ip,
                    "destination_ip": alert.destination_ip,
                    "description": alert.description,
                    "mitre_technique": alert.mitre.technique_id if alert.mitre else "",
                    "mitre_tactic": alert.mitre.tactic if alert.mitre else "",
                }
            )
