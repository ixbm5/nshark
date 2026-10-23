"""Abstract base class for all NSHARK detection modules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from nshark.core.models import Alert, DetectionType, Flow, ParsedPacket


class BaseDetector(ABC):
    """Base detector interface that every detection engine module implements."""

    name: str = "base"
    detection_type: DetectionType

    @abstractmethod
    def analyze(
        self,
        packets: list[ParsedPacket],
        flows: list[Flow],
        config: dict[str, Any],
    ) -> list[Alert]:
        """Run detection logic on parsed packets and reconstructed flows.

        Args:
            packets: Chronologically ordered list of ParsedPacket objects.
            flows: Reconstructed bidirectional Flow objects.
            config: Detector configuration dictionary.

        Returns:
            List of Alert instances discovered by this detector.
        """
        raise NotImplementedError
