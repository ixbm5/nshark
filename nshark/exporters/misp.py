"""MISP Event JSON exporter for NSHARK IOCs."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any
import uuid

from nshark.core.models import IOC, IOCType

MISP_TYPE_MAPPING: dict[IOCType, tuple[str, str]] = {
    IOCType.IP: ("Network activity", "ip-dst"),
    IOCType.DOMAIN: ("Network activity", "domain"),
    IOCType.URL: ("Network activity", "url"),
    IOCType.HASH_MD5: ("Payload delivery", "md5"),
    IOCType.HASH_SHA256: ("Payload delivery", "sha256"),
    IOCType.EMAIL: ("Payload delivery", "email-src"),
    IOCType.USER_AGENT: ("Network activity", "user-agent"),
}


def export_misp(iocs: list[IOC], event_info: str = "NSHARK PCAP Threat Hunt") -> dict[str, Any]:
    """Generate a MISP Event dictionary containing all extracted IOCs as Attributes."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    now_ts = str(int(datetime.now(timezone.utc).timestamp()))
    attributes: list[dict[str, Any]] = []

    for ioc in iocs:
        category, attr_type = MISP_TYPE_MAPPING.get(
            ioc.type, ("Network activity", "other")
        )
        to_ids = any(
            isinstance(v, dict) and v.get("malicious") for v in ioc.enrichment.values()
        )
        attributes.append(
            {
                "uuid": str(uuid.uuid4()),
                "category": category,
                "type": attr_type,
                "value": ioc.value,
                "comment": ioc.context,
                "to_ids": to_ids,
                "timestamp": now_ts,
            }
        )

    return {
        "Event": {
            "uuid": str(uuid.uuid4()),
            "info": event_info,
            "date": today,
            "threat_level_id": "2",
            "analysis": "2",
            "distribution": "0",
            "Attribute": attributes,
        }
    }


def save_misp(event: dict[str, Any], output_path: str) -> None:
    """Save a MISP Event dictionary to a JSON file."""
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(event, fh, indent=2)
