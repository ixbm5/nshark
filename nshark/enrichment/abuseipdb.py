"""AbuseIPDB API v2 enrichment provider."""

from __future__ import annotations

import logging
from typing import Any

import requests

from nshark.core.models import EnrichmentResult
from nshark.enrichment.base import BaseEnricher, mask_api_key

logger = logging.getLogger(__name__)

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDBEnricher(BaseEnricher):
    """Queries AbuseIPDB v2 for community abuse confidence score and report counts."""

    name = "AbuseIPDB"

    def enrich_ip(self, ip: str) -> EnrichmentResult:
        """Query AbuseIPDB for an IPv4/IPv6 address."""
        if not self.is_configured():
            return EnrichmentResult(
                ip_or_domain=ip,
                provider=self.name,
                error="API key not configured (set ABUSEIPDB_KEY)",
            )

        headers = {"Key": self.api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""}
        logger.debug("Querying AbuseIPDB for %s with key %s", ip, mask_api_key(self.api_key))

        try:
            resp = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=10)
            resp.raise_for_status()
            payload: dict[str, Any] = resp.json().get("data", {})

            score = int(payload.get("abuseConfidenceScore", 0))
            reports = int(payload.get("totalReports", 0))
            is_malicious = score >= 50 or reports >= 15

            return EnrichmentResult(
                ip_or_domain=ip,
                provider=self.name,
                malicious=is_malicious,
                confidence_score=score,
                details={
                    "abuse_confidence_score": score,
                    "total_reports": reports,
                    "usage_type": payload.get("usageType", ""),
                    "isp": payload.get("isp", ""),
                    "domain": payload.get("domain", ""),
                    "country_code": payload.get("countryCode", ""),
                    "is_tor": bool(payload.get("isTor", False)),
                },
            )
        except requests.RequestException as exc:
            logger.warning("AbuseIPDB request failed for %s: %s", ip, exc)
            return EnrichmentResult(ip_or_domain=ip, provider=self.name, error=str(exc))

    def enrich_domain(self, domain: str) -> EnrichmentResult:
        """AbuseIPDB only supports IP addresses."""
        return EnrichmentResult(
            ip_or_domain=domain,
            provider=self.name,
            details={"note": "AbuseIPDB only supports IP address lookups"},
        )
