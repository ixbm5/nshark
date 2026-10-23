"""AlienVault Open Threat Exchange (OTX) API v1 enrichment provider."""

from __future__ import annotations

import logging
from typing import Any

import requests

from nshark.core.models import EnrichmentResult
from nshark.enrichment.base import BaseEnricher, mask_api_key

logger = logging.getLogger(__name__)

OTX_BASE_URL = "https://otx.alienvault.com/api/v1/indicators"


class OTXEnricher(BaseEnricher):
    """Queries AlienVault OTX for community threat pulses and IOC intelligence."""

    name = "AlienVault OTX"

    def _query(self, indicator_type: str, target: str) -> EnrichmentResult:
        if not self.is_configured():
            return EnrichmentResult(
                ip_or_domain=target,
                provider=self.name,
                error="API key not configured (set OTX_API_KEY)",
            )

        url = f"{OTX_BASE_URL}/{indicator_type}/{target}/general"
        headers = {"X-OTX-API-KEY": self.api_key, "Accept": "application/json"}
        logger.debug("Querying OTX (%s) for %s with key %s", indicator_type, target, mask_api_key(self.api_key))

        try:
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 404:
                return EnrichmentResult(ip_or_domain=target, provider=self.name)
            resp.raise_for_status()
            data: dict[str, Any] = resp.json()

            pulse_info = data.get("pulse_info", {})
            pulse_count = int(pulse_info.get("count", 0))
            pulses = pulse_info.get("pulses", [])
            pulse_names = [p.get("name", "") for p in pulses[:5] if p.get("name")]

            is_malicious = pulse_count > 0
            score = min(95, pulse_count * 18) if pulse_count > 0 else 0

            return EnrichmentResult(
                ip_or_domain=target,
                provider=self.name,
                malicious=is_malicious,
                confidence_score=score,
                details={
                    "pulse_count": pulse_count,
                    "pulse_names": pulse_names,
                    "country": data.get("country_name", ""),
                    "asn": data.get("asn", ""),
                },
            )
        except requests.RequestException as exc:
            logger.warning("OTX request failed for %s: %s", target, exc)
            return EnrichmentResult(ip_or_domain=target, provider=self.name, error=str(exc))

    def enrich_ip(self, ip: str) -> EnrichmentResult:
        """Query OTX for an IPv4 address."""
        return self._query("IPv4", ip)

    def enrich_domain(self, domain: str) -> EnrichmentResult:
        """Query OTX for a domain name."""
        return self._query("domain", domain)
