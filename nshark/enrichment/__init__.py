"""Threat Intelligence Enrichment Hub coordinating providers, caching, and concurrency."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from typing import Any, Optional

from nshark.core.models import EnrichmentResult, IOC, IOCType
from nshark.enrichment.abuseipdb import AbuseIPDBEnricher
from nshark.enrichment.base import BaseEnricher
from nshark.enrichment.cache import EnrichmentCache
from nshark.enrichment.geoip import GeoIPEnricher
from nshark.enrichment.otx import OTXEnricher
from nshark.enrichment.shodan_enricher import ShodanEnricher
from nshark.enrichment.virustotal import VirusTotalEnricher

logger = logging.getLogger(__name__)


class EnrichmentHub:
    """Orchestrates parallel enrichment across configured Threat Intel providers with SQLite caching."""

    def __init__(
        self,
        config: dict[str, Any],
        selected_providers: Optional[list[str]] = None,
        workers: int = 5,
    ) -> None:
        self.config = config
        self.workers = max(1, workers)

        cache_cfg = config.get("cache", {})
        self.cache_enabled = bool(cache_cfg.get("enabled", True))
        self.cache = EnrichmentCache(
            db_path=str(cache_cfg.get("db_path", "~/.nshark/cache.db")),
            ttl_hours=int(cache_cfg.get("ttl_hours", 24)),
        )

        enrich_cfg = config.get("enrichment", {})
        all_providers: dict[str, BaseEnricher] = {
            "vt": VirusTotalEnricher(
                api_key=str(enrich_cfg.get("virustotal", {}).get("api_key", "")),
                rate_limit_per_min=int(enrich_cfg.get("virustotal", {}).get("rate_limit", 4)),
            ),
            "abuseipdb": AbuseIPDBEnricher(
                api_key=str(enrich_cfg.get("abuseipdb", {}).get("api_key", "")),
                rate_limit_per_min=int(enrich_cfg.get("abuseipdb", {}).get("rate_limit", 60)),
            ),
            "shodan": ShodanEnricher(
                api_key=str(enrich_cfg.get("shodan", {}).get("api_key", "")),
                rate_limit_per_min=int(enrich_cfg.get("shodan", {}).get("rate_limit", 60)),
            ),
            "otx": OTXEnricher(
                api_key=str(enrich_cfg.get("otx", {}).get("api_key", "")),
                rate_limit_per_min=int(enrich_cfg.get("otx", {}).get("rate_limit", 100)),
            ),
        }

        if selected_providers:
            wanted = {p.strip().lower() for p in selected_providers}
            self.providers = [
                prov for key, prov in all_providers.items() if key in wanted and prov.is_configured()
            ]
        else:
            self.providers = [prov for prov in all_providers.values() if prov.is_configured()]

    def enrich_single(self, value: str, ioc_type: IOCType) -> list[EnrichmentResult]:
        """Enrich a single IP or Domain across all active providers."""
        results: list[EnrichmentResult] = []
        for provider in self.providers:
            if self.cache_enabled:
                cached = self.cache.get(value, provider.name)
                if cached is not None:
                    results.append(cached)
                    continue

            if ioc_type == IOCType.IP:
                res = provider.enrich_ip(value)
            elif ioc_type == IOCType.DOMAIN:
                res = provider.enrich_domain(value)
            elif ioc_type in (IOCType.HASH_SHA256, IOCType.HASH_MD5) and hasattr(provider, "enrich_hash"):
                res = provider.enrich_hash(value)
            else:
                continue

            if self.cache_enabled and not res.error:
                self.cache.put(value, provider.name, res)
            results.append(res)
        return results

    def enrich_iocs(self, iocs: list[IOC]) -> list[EnrichmentResult]:
        """Concurrently enrich a list of IOCs using ThreadPoolExecutor."""
        if not self.providers:
            logger.info("No enrichment API keys configured; skipping external TI calls.")
            return []

        enrichable = [
            i for i in iocs
            if i.type in (IOCType.IP, IOCType.DOMAIN, IOCType.HASH_SHA256, IOCType.HASH_MD5)
        ]
        if not enrichable:
            return []

        all_results: list[EnrichmentResult] = []
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            future_to_ioc = {
                pool.submit(self.enrich_single, ioc.value, ioc.type): ioc for ioc in enrichable
            }
            for future in as_completed(future_to_ioc):
                ioc = future_to_ioc[future]
                try:
                    res_list = future.result()
                    for res in res_list:
                        if "note" not in res.details:
                            all_results.append(res)
                            ioc.enrichment[res.provider] = {
                                "malicious": res.malicious,
                                "confidence_score": res.confidence_score,
                                "details": res.details,
                                "cached": res.cached,
                            }
                except Exception as exc:
                    logger.warning("Enrichment worker failed for %s: %s", ioc.value, exc)

        return all_results


__all__ = [
    "AbuseIPDBEnricher",
    "BaseEnricher",
    "EnrichmentCache",
    "EnrichmentHub",
    "GeoIPEnricher",
    "OTXEnricher",
    "ShodanEnricher",
    "VirusTotalEnricher",
]
