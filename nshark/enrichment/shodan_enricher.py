"""Shodan API enrichment provider for open ports, banners, and CVEs."""

from __future__ import annotations

import logging
from typing import Any

import requests

from nshark.core.models import EnrichmentResult
from nshark.enrichment.base import BaseEnricher, mask_api_key

logger = logging.getLogger(__name__)

SHODAN_HOST_URL = "https://api.shodan.io/shodan/host"


class ShodanEnricher(BaseEnricher):
    """Queries Shodan for open ports, exposed services, and known CVE vulnerabilities."""

    name = "Shodan"

    def enrich_ip(self, ip: str) -> EnrichmentResult:
        """Query Shodan host endpoint for an IP address."""
        if not self.is_configured():
            return EnrichmentResult(
                ip_or_domain=ip,
                provider=self.name,
                error="API key not configured (set SHODAN_API_KEY)",
            )

        url = f"{SHODAN_HOST_URL}/{ip}"
        params = {"key": self.api_key}
        logger.debug("Querying Shodan for %s with key %s", ip, mask_api_key(self.api_key))

        try:
            resp = requests.get(url, params=params, timeout=10)
            if resp.status_code == 404:
                return EnrichmentResult(
                    ip_or_domain=ip,
                    provider=self.name,
                    details={"status": "No Shodan data available"},
                )
            resp.raise_for_status()
            data: dict[str, Any] = resp.json()

            ports: list[int] = sorted(data.get("ports", []))
            raw_vulns = data.get("vulns", [])
            vulns: list[str] = (
                sorted(raw_vulns.keys()) if isinstance(raw_vulns, dict) else sorted(raw_vulns)
            )
            tags: list[str] = data.get("tags", [])

            is_malicious = bool(vulns) or any(
                t.lower() in ("malware", "c2", "compromised", "tor", "scanner") for t in tags
            )
            score = min(95, len(vulns) * 15 + (40 if is_malicious else 10)) if (vulns or is_malicious) else 0

            return EnrichmentResult(
                ip_or_domain=ip,
                provider=self.name,
                malicious=is_malicious,
                confidence_score=score,
                details={
                    "open_ports": ports[:25],
                    "vulns": vulns[:15],
                    "org": data.get("org", ""),
                    "isp": data.get("isp", ""),
                    "os": data.get("os", "") or "Unknown",
                    "tags": tags,
                    "hostnames": data.get("hostnames", [])[:5],
                },
            )
        except requests.RequestException as exc:
            logger.warning("Shodan request failed for %s: %s", ip, exc)
            return EnrichmentResult(ip_or_domain=ip, provider=self.name, error=str(exc))

    def enrich_domain(self, domain: str) -> EnrichmentResult:
        """Shodan host lookup applies to IP addresses."""
        return EnrichmentResult(
            ip_or_domain=domain,
            provider=self.name,
            details={"note": "Shodan host lookup applies to IP addresses"},
        )
