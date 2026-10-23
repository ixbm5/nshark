"""VirusTotal API v3 enrichment provider for IPs, domains, and SHA-256 file hashes."""

from __future__ import annotations

import logging
from typing import Any

import requests

from nshark.core.models import EnrichmentResult
from nshark.enrichment.base import BaseEnricher, mask_api_key

logger = logging.getLogger(__name__)

VT_BASE_URL = "https://www.virustotal.com/api/v3"


class VirusTotalEnricher(BaseEnricher):
    """Queries VirusTotal API v3 for IP, domain, and file hash reputation."""

    name = "VirusTotal"

    def _query(self, endpoint: str, target: str) -> EnrichmentResult:
        if not self.is_configured():
            return EnrichmentResult(
                ip_or_domain=target,
                provider=self.name,
                error="API key not configured (set VT_API_KEY)",
            )

        url = f"{VT_BASE_URL}/{endpoint}/{target}"
        headers = {"x-apikey": self.api_key, "Accept": "application/json"}
        logger.debug("Querying VirusTotal (%s) with key %s", endpoint, mask_api_key(self.api_key))

        try:
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 404:
                return EnrichmentResult(
                    ip_or_domain=target,
                    provider=self.name,
                    malicious=False,
                    confidence_score=0,
                    details={"status": "Not found in VirusTotal"},
                )
            resp.raise_for_status()
            data: dict[str, Any] = resp.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})

            malicious_count = int(stats.get("malicious", 0))
            suspicious_count = int(stats.get("suspicious", 0))
            harmless_count = int(stats.get("harmless", 0))
            undetected_count = int(stats.get("undetected", 0))
            total_engines = malicious_count + suspicious_count + harmless_count + undetected_count

            is_malicious = malicious_count >= 3 or (malicious_count >= 1 and suspicious_count >= 2)
            score = (
                min(100, int(((malicious_count * 3 + suspicious_count) / max(1, total_engines)) * 100))
                if total_engines > 0
                else 0
            )
            if malicious_count >= 10:
                score = max(score, 90)
            elif malicious_count >= 5:
                score = max(score, 75)
            elif malicious_count >= 1:
                score = max(score, 40)

            threat_class = attrs.get("popular_threat_classification") or {}
            threat_label = str(threat_class.get("suggested_threat_label", "")).strip()
            names_list = attrs.get("names") or []
            file_name = str(attrs.get("meaningful_name") or (names_list[0] if names_list else "")).strip()
            file_type = str(attrs.get("type_description", "")).strip()
            as_owner = str(attrs.get("as_owner", "")).strip()
            asn = attrs.get("asn", "")
            country = str(attrs.get("country", "")).strip()
            raw_cats = attrs.get("categories") or {}
            categories = ", ".join(sorted(set(str(v) for v in raw_cats.values() if v))[:3]) if isinstance(raw_cats, dict) else ""

            details: dict[str, Any] = {
                "detection_ratio": f"{malicious_count}/{total_engines}",
                "malicious": malicious_count,
                "suspicious": suspicious_count,
                "reputation": attrs.get("reputation", 0),
                "as_owner": as_owner,
                "country": country,
            }
            if asn:
                details["asn"] = asn
            if threat_label:
                details["threat_label"] = threat_label
            if file_name:
                details["file_name"] = file_name
            if file_type:
                details["file_type"] = file_type
            if categories:
                details["categories"] = categories

            return EnrichmentResult(
                ip_or_domain=target,
                provider=self.name,
                malicious=is_malicious,
                confidence_score=score,
                details=details,
            )
        except requests.RequestException as exc:
            logger.warning("VirusTotal request failed for %s: %s", target, exc)
            return EnrichmentResult(
                ip_or_domain=target,
                provider=self.name,
                error=str(exc),
            )

    def enrich_ip(self, ip: str) -> EnrichmentResult:
        """Query VirusTotal for an IPv4/IPv6 address."""
        return self._query("ip_addresses", ip)

    def enrich_domain(self, domain: str) -> EnrichmentResult:
        """Query VirusTotal for a domain name."""
        return self._query("domains", domain)

    def enrich_hash(self, file_hash: str) -> EnrichmentResult:
        """Query VirusTotal for a file MD5 or SHA-256 hash."""
        return self._query("files", file_hash)
