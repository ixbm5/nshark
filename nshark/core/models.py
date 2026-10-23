"""Core data models for NSHARK analysis pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(Enum):
    """Alert severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IOCType(Enum):
    """Indicator-of-Compromise categories."""

    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    USER_AGENT = "user_agent"


class DetectionType(Enum):
    """Types of detections the engine can produce."""

    PORT_SCAN = "port_scan"
    WEB_ENUMERATION = "web_enumeration"
    BRUTE_FORCE = "brute_force"
    CLEARTEXT_CREDENTIALS = "cleartext_credentials"
    COMMAND_INJECTION = "command_injection"
    REVERSE_SHELL = "reverse_shell"
    C2_BEACONING = "c2_beaconing"
    DNS_TUNNELING = "dns_tunneling"
    DATA_EXFILTRATION = "data_exfiltration"
    TLS_ANOMALY = "tls_anomaly"
    ARP_SPOOFING = "arp_spoofing"
    LATERAL_MOVEMENT = "lateral_movement"


class FPTolerance(Enum):
    """False-positive tolerance presets."""

    STRICT = "strict"      # confidence >= 85 shown
    BALANCED = "balanced"  # confidence >= 70 shown
    LENIENT = "lenient"    # confidence >= 50 shown

    @property
    def min_confidence(self) -> int:
        return {
            FPTolerance.STRICT: 85,
            FPTolerance.BALANCED: 70,
            FPTolerance.LENIENT: 50,
        }[self]


# ---------------------------------------------------------------------------
# Network primitives
# ---------------------------------------------------------------------------

class ParsedPacket:
    """Minimal, memory-optimized representation of a single parsed packet."""

    __slots__ = (
        "timestamp",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "length",
        "flags",
        "payload",
        "raw",
        "src_mac",
        "dst_mac",
        "ttl",
        "tcp_window",
        "tcp_seq",
        "tcp_ack",
    )

    def __init__(
        self,
        timestamp: datetime,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        length: int,
        flags: str = "",
        payload: bytes = b"",
        raw: Any = None,
        src_mac: str = "",
        dst_mac: str = "",
        ttl: int = 0,
        tcp_window: int = 0,
        tcp_seq: int = 0,
        tcp_ack: int = 0,
    ) -> None:
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.length = length
        self.flags = flags
        self.payload = payload
        self.raw = raw
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.ttl = ttl
        self.tcp_window = tcp_window
        self.tcp_seq = tcp_seq
        self.tcp_ack = tcp_ack

    def __repr__(self) -> str:
        return (
            f"ParsedPacket({self.timestamp.strftime('%H:%M:%S.%f')[:12]} "
            f"{self.protocol} {self.src_ip}:{self.src_port} -> "
            f"{self.dst_ip}:{self.dst_port} len={self.length})"
        )


@dataclass
class Flow:
    """Reconstructed network flow (bidirectional conversation)."""

    flow_id: str           # "src_ip:src_port-dst_ip:dst_port-proto"
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packets: list[ParsedPacket] = field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    bytes_sent: int = 0
    bytes_received: int = 0

    @property
    def duration(self) -> float:
        """Flow duration in seconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0

    @property
    def packet_count(self) -> int:
        return len(self.packets)


# ---------------------------------------------------------------------------
# IOCs & Enrichment
# ---------------------------------------------------------------------------

@dataclass
class IOC:
    """An extracted Indicator of Compromise."""

    type: IOCType
    value: str
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    context: str = ""
    enrichment: dict[str, Any] = field(default_factory=dict)


@dataclass
class EnrichmentResult:
    """Result from a single enrichment provider lookup."""

    ip_or_domain: str
    provider: str
    malicious: bool = False
    confidence_score: int = 0       # provider-specific score 0-100
    details: dict[str, Any] = field(default_factory=dict)
    raw_response: dict[str, Any] = field(default_factory=dict)
    cached: bool = False
    error: str = ""


@dataclass
class GeoInfo:
    """GeoIP + ASN metadata for an IP address."""

    ip: str
    country: str = "Unknown"
    country_code: str = ""
    city: str = ""
    asn: int = 0
    org: str = ""
    is_suspicious: bool = False
    suspicion_reason: str = ""


# ---------------------------------------------------------------------------
# MITRE ATT&CK
# ---------------------------------------------------------------------------

@dataclass
class MITREMapping:
    """Maps a detection to a MITRE ATT&CK technique."""

    tactic: str
    technique_id: str
    technique_name: str
    url: str = ""


# ---------------------------------------------------------------------------
# Detections / Alerts
# ---------------------------------------------------------------------------

@dataclass
class Alert:
    """A single detection alert produced by the engine."""

    detection_type: DetectionType
    severity: Severity
    confidence: int                          # 0-100
    source_ip: str
    destination_ip: str = ""
    description: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: Optional[datetime] = None
    mitre: Optional[MITREMapping] = None
    related_iocs: list[IOC] = field(default_factory=list)
    enrichment: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Extractors output
# ---------------------------------------------------------------------------

@dataclass
class CarvedFile:
    """A file carved from network traffic."""

    filename: str
    file_type: str
    size: int
    md5: str
    sha256: str
    source_ip: str
    destination_ip: str
    extraction_path: str = ""
    vt_result: Optional[dict[str, Any]] = None


@dataclass
class DNSQuery:
    """A single observed DNS query/response."""

    timestamp: datetime
    query_name: str
    query_type: str          # A, AAAA, TXT, MX, CNAME, …
    response: str = ""
    source_ip: str = ""
    category: str = "unknown"  # legit | suspicious | dga | tunneling | known_malicious


@dataclass
class HTTPSession:
    """A reconstructed HTTP request/response pair."""

    timestamp: datetime
    method: str
    url: str
    host: str
    source_ip: str
    destination_ip: str
    status_code: int = 0
    user_agent: str = ""
    content_type: str = ""
    request_headers: dict[str, str] = field(default_factory=dict)
    response_headers: dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    response_size: int = 0
    suspicious: bool = False
    suspicion_reason: str = ""


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------

@dataclass
class TimelineEvent:
    """A single event in the incident timeline."""

    timestamp: datetime
    event_type: str         # "detection", "dns", "http", "file_transfer", …
    description: str
    source_ip: str = ""
    destination_ip: str = ""
    severity: Severity = Severity.INFO
    details: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Top-level report
# ---------------------------------------------------------------------------

@dataclass
class AnalysisReport:
    """Complete analysis output - the single object every reporter consumes."""

    pcap_file: str
    analysis_time: datetime = field(default_factory=datetime.utcnow)
    total_packets: int = 0
    total_flows: int = 0
    duration_seconds: float = 0.0
    alerts: list[Alert] = field(default_factory=list)
    iocs: list[IOC] = field(default_factory=list)
    carved_files: list[CarvedFile] = field(default_factory=list)
    dns_queries: list[DNSQuery] = field(default_factory=list)
    http_sessions: list[HTTPSession] = field(default_factory=list)
    geo_info: list[GeoInfo] = field(default_factory=list)
    timeline: list[TimelineEvent] = field(default_factory=list)
    enrichment_results: list[EnrichmentResult] = field(default_factory=list)
    bpf_filter: Optional[str] = None

    @property
    def high_confidence_alerts(self) -> list[Alert]:
        """Alerts with confidence >= 70."""
        return [a for a in self.alerts if a.confidence >= 70]

    @property
    def critical_alerts(self) -> list[Alert]:
        """Alerts rated HIGH or CRITICAL severity."""
        return [
            a for a in self.alerts
            if a.severity in (Severity.HIGH, Severity.CRITICAL)
        ]
