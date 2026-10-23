"""Detection modules for NSHARK."""

from __future__ import annotations

from nshark.detectors.arp_spoof import ARPSpoofDetector
from nshark.detectors.base import BaseDetector
from nshark.detectors.beaconing import BeaconingDetector
from nshark.detectors.brute_force import BruteForceDetector
from nshark.detectors.cleartext_creds import CleartextCredsDetector
from nshark.detectors.dns_tunnel import DNSTunnelDetector
from nshark.detectors.exfiltration import ExfiltrationDetector
from nshark.detectors.lateral_movement import LateralMovementDetector
from nshark.detectors.port_scan import PortScanDetector
from nshark.detectors.post_exploitation import PostExploitationDetector
from nshark.detectors.tls_analysis import TLSAnalysisDetector

ALL_DETECTORS: list[type[BaseDetector]] = [
    PortScanDetector,
    BruteForceDetector,
    BeaconingDetector,
    DNSTunnelDetector,
    ExfiltrationDetector,
    CleartextCredsDetector,
    PostExploitationDetector,
    TLSAnalysisDetector,
    ARPSpoofDetector,
    LateralMovementDetector,
]

__all__ = [
    "ALL_DETECTORS",
    "ARPSpoofDetector",
    "BaseDetector",
    "BeaconingDetector",
    "BruteForceDetector",
    "CleartextCredsDetector",
    "DNSTunnelDetector",
    "ExfiltrationDetector",
    "LateralMovementDetector",
    "PortScanDetector",
    "PostExploitationDetector",
    "TLSAnalysisDetector",
]
