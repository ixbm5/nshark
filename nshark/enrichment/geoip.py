"""GeoIP and ASN enrichment using MaxMind GeoLite2 (with ip-api.com fallback)."""

from __future__ import annotations

import logging
import os
import re
from typing import Optional

import requests

from nshark.core.models import GeoInfo

logger = logging.getLogger(__name__)

# Known high-risk / bulletproof hosting ASNs frequently abused for C2 infrastructure
BULLETPROOF_ASNS: set[int] = {
    9009,    # M247
    202425,  # IP Volume
    49981,   # WorldStream
    60781,   # LeaseWeb
    51167,   # Contabo
    44477,   # Stark Industries Solutions
    211252,  # Chang Way Technologies
    197695,  # Reg.ru
    48031,   # Eurobyte
    204957,  # Green Floid
}

WATCHLIST_COUNTRY_CODES: set[str] = {"KP", "IR", "SY", "CU", "RU", "BY"}


class GeoIPEnricher:
    """Resolves public IPs to Country, City, ASN, and Organization with anomaly flagging."""

    def __init__(self, db_path: str = "", allow_online_fallback: bool = True) -> None:
        self.db_path = os.path.expanduser(db_path) if db_path else ""
        self.allow_online_fallback = allow_online_fallback

    def lookup(self, ip: str) -> GeoInfo:
        """Resolve geographic and ASN details for `ip`."""
        info = self._lookup_maxmind(ip)
        if info is None and self.allow_online_fallback:
            info = self._lookup_ip_api(ip)
        if info is None:
            return GeoInfo(ip=ip)

        reasons: list[str] = []
        if info.asn in BULLETPROOF_ASNS:
            info.is_suspicious = True
            reasons.append(f"High-risk/bulletproof hosting ASN (AS{info.asn})")
        if info.country_code in WATCHLIST_COUNTRY_CODES:
            info.is_suspicious = True
            reasons.append(f"Watchlist jurisdiction ({info.country})")

        info.suspicion_reason = "; ".join(reasons)
        return info

    def _lookup_maxmind(self, ip: str) -> Optional[GeoInfo]:
        if not self.db_path or not os.path.isfile(self.db_path):
            return None
        try:
            import geoip2.database  # type: ignore[import-untyped]

            with geoip2.database.Reader(self.db_path) as reader:
                resp = reader.city(ip)
                return GeoInfo(
                    ip=ip,
                    country=resp.country.name or "Unknown",
                    country_code=resp.country.iso_code or "",
                    city=resp.city.name or "",
                    asn=0,
                    org="",
                )
        except Exception as exc:
            logger.debug("MaxMind GeoIP lookup failed for %s: %s", ip, exc)
            return None

    def _lookup_ip_api(self, ip: str) -> Optional[GeoInfo]:
        """Fallback lookup using free ip-api.com JSON endpoint."""
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org,as"
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code != 200:
                return None
            data = resp.json()
            if data.get("status") != "success":
                return None

            as_str = data.get("as", "")
            asn_match = re.match(r"AS(\d+)", as_str)
            asn_num = int(asn_match.group(1)) if asn_match else 0

            return GeoInfo(
                ip=ip,
                country=data.get("country", "Unknown"),
                country_code=data.get("countryCode", ""),
                city=data.get("city", ""),
                asn=asn_num,
                org=data.get("org") or data.get("isp", ""),
            )
        except Exception as exc:
            logger.debug("ip-api fallback failed for %s: %s", ip, exc)
            return None
