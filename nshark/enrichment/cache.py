"""Persistent SQLite cache for Threat Intelligence enrichment lookups."""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from typing import Optional

from nshark.core.models import EnrichmentResult

logger = logging.getLogger(__name__)


class EnrichmentCache:
    """Thread-safe SQLite cache storing EnrichmentResult responses with TTL expiry."""

    def __init__(self, db_path: str = "~/.nshark/cache.db", ttl_hours: int = 24) -> None:
        self.db_path = os.path.expanduser(db_path)
        self.ttl_hours = max(1, ttl_hours)
        self._init_db()

    def _init_db(self) -> None:
        """Create cache directory and SQLite table if they do not exist."""
        try:
            parent_dir = os.path.dirname(self.db_path)
            if parent_dir:
                os.makedirs(parent_dir, exist_ok=True)
            with sqlite3.connect(self.db_path, timeout=10) as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS enrichment_cache (
                        cache_key TEXT PRIMARY KEY,
                        provider TEXT NOT NULL,
                        response TEXT NOT NULL,
                        timestamp REAL NOT NULL
                    )
                    """
                )
                conn.commit()
        except Exception as exc:
            logger.warning("Could not initialize SQLite cache at %s: %s", self.db_path, exc)

    @staticmethod
    def is_expired(timestamp: float, ttl_hours: int) -> bool:
        """Return True if `timestamp` is older than `ttl_hours`."""
        return (time.time() - timestamp) > (ttl_hours * 3600)

    def get(self, key: str, provider: str) -> Optional[EnrichmentResult]:
        """Retrieve a cached EnrichmentResult if present and not expired."""
        composite_key = f"{provider}:{key.lower().strip()}"
        try:
            with sqlite3.connect(self.db_path, timeout=10) as conn:
                row = conn.execute(
                    "SELECT response, timestamp FROM enrichment_cache WHERE cache_key = ?",
                    (composite_key,),
                ).fetchone()
                if not row:
                    return None
                raw_json, ts = row[0], float(row[1])
                if self.is_expired(ts, self.ttl_hours):
                    conn.execute(
                        "DELETE FROM enrichment_cache WHERE cache_key = ?", (composite_key,)
                    )
                    conn.commit()
                    return None

                data = json.loads(raw_json)
                return EnrichmentResult(
                    ip_or_domain=data.get("ip_or_domain", key),
                    provider=data.get("provider", provider),
                    malicious=bool(data.get("malicious", False)),
                    confidence_score=int(data.get("confidence_score", 0)),
                    details=data.get("details", {}),
                    raw_response=data.get("raw_response", {}),
                    cached=True,
                    error=data.get("error", ""),
                )
        except Exception as exc:
            logger.debug("Cache read error for %s: %s", composite_key, exc)
            return None

    def put(self, key: str, provider: str, result: EnrichmentResult) -> None:
        """Store an EnrichmentResult in the SQLite cache."""
        if result.error:
            return  # Do not cache transient errors
        composite_key = f"{provider}:{key.lower().strip()}"
        payload = json.dumps(
            {
                "ip_or_domain": result.ip_or_domain,
                "provider": result.provider,
                "malicious": result.malicious,
                "confidence_score": result.confidence_score,
                "details": result.details,
                "raw_response": result.raw_response,
                "error": result.error,
            }
        )
        try:
            with sqlite3.connect(self.db_path, timeout=10) as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO enrichment_cache
                    (cache_key, provider, response, timestamp)
                    VALUES (?, ?, ?, ?)
                    """,
                    (composite_key, provider, payload, time.time()),
                )
                conn.commit()
        except Exception as exc:
            logger.debug("Cache write error for %s: %s", composite_key, exc)

    def clear(self) -> None:
        """Delete all entries from the cache."""
        try:
            with sqlite3.connect(self.db_path, timeout=10) as conn:
                conn.execute("DELETE FROM enrichment_cache")
                conn.commit()
        except Exception as exc:
            logger.warning("Failed to clear cache: %s", exc)
