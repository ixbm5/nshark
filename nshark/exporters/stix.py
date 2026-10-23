"""STIX 2.1 bundle exporter for NSHARK IOCs and Alerts."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any
import uuid

from nshark.core.models import Alert, IOC, IOCType

STIX_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


def _stix_pattern(ioc: IOC) -> str:
    """Convert an IOC into a STIX 2.1 indicator pattern string."""
    val = ioc.value.replace("'", "\\'")
    if ioc.type == IOCType.IP:
        if ":" in val:
            return f"[ipv6-addr:value = '{val}']"
        return f"[ipv4-addr:value = '{val}']"
    if ioc.type == IOCType.DOMAIN:
        return f"[domain-name:value = '{val}']"
    if ioc.type == IOCType.URL:
        return f"[url:value = '{val}']"
    if ioc.type == IOCType.HASH_MD5:
        return f"[file:hashes.MD5 = '{val}']"
    if ioc.type == IOCType.HASH_SHA256:
        return f"[file:hashes.'SHA-256' = '{val}']"
    if ioc.type == IOCType.EMAIL:
        return f"[email-addr:value = '{val}']"
    return f"[artifact:payload_bin = '{val}']"


def export_stix(iocs: list[IOC], alerts: list[Alert]) -> dict[str, Any]:
    """Build a STIX 2.1 Bundle dictionary from extracted IOCs and detections."""
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    objects: list[dict[str, Any]] = []

    for ioc in iocs:
        det_uuid = uuid.uuid5(STIX_NAMESPACE, f"indicator:{ioc.type.value}:{ioc.value}")
        valid_from = (
            ioc.first_seen.strftime("%Y-%m-%dT%H:%M:%SZ") if ioc.first_seen else now_iso
        )
        labels = ["network-activity", ioc.type.value]
        if any(v.get("malicious") for v in ioc.enrichment.values() if isinstance(v, dict)):
            labels.append("malicious-activity")

        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{det_uuid}",
                "created": now_iso,
                "modified": now_iso,
                "name": f"NSHARK {ioc.type.value.upper()}: {ioc.value}",
                "description": ioc.context or f"Extracted {ioc.type.value} indicator",
                "pattern": _stix_pattern(ioc),
                "pattern_type": "stix",
                "valid_from": valid_from,
                "labels": labels,
            }
        )

    for idx, alert in enumerate(alerts):
        sighting_uuid = uuid.uuid5(
            STIX_NAMESPACE,
            f"attack-pattern:{alert.detection_type.value}:{alert.source_ip}:{idx}",
        )
        ext_refs = []
        if alert.mitre:
            ext_refs.append(
                {
                    "source_name": "mitre-attack",
                    "external_id": alert.mitre.technique_id,
                    "url": alert.mitre.url,
                }
            )
        objects.append(
            {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": f"attack-pattern--{sighting_uuid}",
                "created": now_iso,
                "modified": now_iso,
                "name": (
                    alert.mitre.technique_name
                    if alert.mitre
                    else alert.detection_type.value
                ),
                "description": alert.description,
                "external_references": ext_refs,
            }
        )

    bundle_id = uuid.uuid4()
    return {
        "type": "bundle",
        "id": f"bundle--{bundle_id}",
        "objects": objects,
    }


def save_stix(bundle: dict[str, Any], output_path: str) -> None:
    """Write a STIX 2.1 bundle dictionary to a JSON file."""
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(bundle, fh, indent=2)
