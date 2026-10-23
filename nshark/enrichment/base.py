"""Abstract base class for Threat Intelligence enrichment providers."""

from __future__ import annotations

from abc import ABC, abstractmethod

from nshark.core.models import EnrichmentResult


def mask_api_key(key: str) -> str:
    """Return a masked representation of an API key showing only the last 4 characters."""
    cleaned = key.strip()
    if not cleaned:
        return "<unset>"
    if len(cleaned) <= 4:
        return "****"
    return f"****{cleaned[-4:]}"


class BaseEnricher(ABC):
    """Base interface for all Threat Intelligence providers (VT, AbuseIPDB, Shodan, OTX)."""

    name: str = "base"

    def __init__(self, api_key: str = "", rate_limit_per_min: int = 60) -> None:
        self.api_key = api_key.strip()
        self.rate_limit_per_min = max(1, rate_limit_per_min)

    def is_configured(self) -> bool:
        """Return True if a non-empty API key is configured for this provider."""
        return bool(self.api_key)

    @abstractmethod
    def enrich_ip(self, ip: str) -> EnrichmentResult:
        """Query threat intelligence for an IPv4/IPv6 address."""
        raise NotImplementedError

    @abstractmethod
    def enrich_domain(self, domain: str) -> EnrichmentResult:
        """Query threat intelligence for a domain name."""
        raise NotImplementedError
