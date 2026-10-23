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

        has_sha256 = any(i.type == IOCType.HASH_SHA256 for i in iocs)
        enrichable: list[IOC] = []
        for ioc in iocs:
            if ioc.type in (IOCType.IP, IOCType.DOMAIN, IOCType.HASH_SHA256):
                enrichable.append(ioc)
            elif ioc.type == IOCType.HASH_MD5:
                ctx_upper = (ioc.context or "").upper()
                if "JA3" in ctx_upper or "HASSH" in ctx_upper:
                    continue
                if has_sha256 and ctx_upper.startswith("CARVED "):
                    continue
                enrichable.append(ioc)

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
                            if ioc.context and "context" not in res.details:
                                res.details["context"] = ioc.context
                            all_results.append(res)
                            ioc.enrichment[res.provider] = {
                                "malicious": res.malicious,
                                "confidence_score": res.confidence_score,
                                "details": res.details,
                                "cached": res.cached,
                            }
                except Exception as exc:
                    logger.warning("Enrichment worker failed for %s: %s", ioc.value, exc)

        all_results.sort(key=lambda r: (not r.malicious, -r.confidence_score, r.ip_or_domain))
        return all_results


def format_enrichment_result(res: EnrichmentResult) -> tuple[str, str, str]:
    """Return (verdict_text, rich_style, human_summary) for an EnrichmentResult."""
    if res.error:
        return ("ERROR", "bold yellow", res.error)

    status = str(res.details.get("status", ""))
    if status in ("Not found in VirusTotal", "No Shodan data available"):
        ctx = f" [{res.details['context']}]" if res.details.get("context") else ""
        return ("NOT FOUND", "dim bright_cyan", f"{status}{ctx}")

    susp_count = int(res.details.get("suspicious", 0) or 0)
    if res.malicious:
        verdict, style = ("MALICIOUS", "bold #ff0055")
    elif res.confidence_score >= 25 or susp_count > 0:
        verdict, style = ("SUSPICIOUS", "bold #ffd000")
    else:
        verdict, style = ("CLEAN", "bold bright_green")

    parts: list[str] = []
    d = res.details
    if res.provider == "VirusTotal":
        ratio = d.get("detection_ratio", "0/0")
        parts.append(f"{ratio} engines")
        if d.get("threat_label"):
            parts.append(f"family={d['threat_label']}")
        if d.get("file_name"):
            parts.append(f"file={d['file_name']}")
        if d.get("file_type"):
            parts.append(f"type={d['file_type']}")
        if d.get("as_owner"):
            asn_prefix = f"AS{d['asn']} " if d.get("asn") else ""
            parts.append(f"org={asn_prefix}{d['as_owner']}")
        if d.get("country"):
            parts.append(f"country={d['country']}")
        if d.get("categories"):
            parts.append(f"cat={d['categories']}")
        if d.get("reputation") not in (None, 0, "0") and not d.get("threat_label"):
            parts.append(f"rep={d['reputation']}")
    elif res.provider == "AbuseIPDB":
        parts.append(f"{d.get('total_reports', 0)} abuse reports")
        if d.get("isp"):
            parts.append(f"ISP={d['isp']}")
        if d.get("usage_type"):
            parts.append(f"usage={d['usage_type']}")
        if d.get("country_code"):
            parts.append(f"country={d['country_code']}")
        if d.get("is_tor"):
            parts.append("TOR=True")
    elif res.provider == "Shodan":
        ports = d.get("open_ports") or []
        if ports:
            parts.append(f"ports={','.join(str(p) for p in ports[:8])}")
        vulns = d.get("vulns") or []
        if vulns:
            parts.append(f"CVEs={','.join(vulns[:5])}")
        if d.get("org"):
            parts.append(f"org={d['org']}")
        if d.get("os") and d.get("os") != "Unknown":
            parts.append(f"OS={d['os']}")
    elif res.provider == "AlienVault OTX":
        pcount = int(d.get("pulse_count", 0) or 0)
        parts.append(f"{pcount} threat pulse(s)")
        pnames = d.get("pulse_names") or []
        if pnames:
            parts.append(f"pulses={'; '.join(str(p) for p in pnames[:2])}")
        if d.get("country"):
            parts.append(f"country={d['country']}")
    else:
        parts = [f"{k}={v}" for k, v in list(d.items())[:4] if v not in ("", None, [], {}) and k != "context"]

    if d.get("context"):
        parts.append(f"[{d['context']}]")

    summary = " | ".join(parts) if parts else "No detections reported"
    return (verdict, style, summary)


__all__ = [
    "AbuseIPDBEnricher",
    "BaseEnricher",
    "EnrichmentCache",
    "EnrichmentHub",
    "GeoIPEnricher",
    "OTXEnricher",
    "ShodanEnricher",
    "VirusTotalEnricher",
    "format_enrichment_result",
]
