"""JSON serializer and reporter for NSHARK AnalysisReport."""

from __future__ import annotations

import base64
from dataclasses import asdict, is_dataclass
from datetime import datetime
from enum import Enum
import json
from typing import Any

from nshark.core.models import AnalysisReport


def _default_serializer(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, bytes):
        return base64.b64encode(obj).decode("ascii")
    if is_dataclass(obj) and not isinstance(obj, type):
        return asdict(obj)
    return str(obj)


def generate_json(report: AnalysisReport) -> str:
    """Serialize an AnalysisReport into a formatted JSON string."""
    payload = asdict(report)
    return json.dumps(payload, default=_default_serializer, indent=2)


def save_json(report: AnalysisReport, output_path: str) -> None:
    """Write an AnalysisReport to a JSON file."""
    content = generate_json(report)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(content)
