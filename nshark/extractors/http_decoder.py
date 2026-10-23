"""HTTP session decoder and suspicious payload inspector."""

from __future__ import annotations

import base64
import logging
import re
import urllib.parse
from typing import Optional

from nshark.core.models import Flow, HTTPSession, ParsedPacket

logger = logging.getLogger(__name__)

HTTP_REQUEST_LINE_RE = re.compile(
    r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|PROPFIND)\s+(\S+)\s+HTTP/1\.[01]",
    re.IGNORECASE,
)
HTTP_RESPONSE_LINE_RE = re.compile(r"^HTTP/1\.[01]\s+(\d{3})\b")
BASE64_BLOB_RE = re.compile(r"(?:[A-Za-z0-9+/]{32,}={0,2})")

SUSPICIOUS_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"(?:IEX|Invoke-Expression|Invoke-WebRequest|DownloadString|-enc\b|powershell)", re.I),
        "PowerShell execution/download cradle",
    ),
    (
        re.compile(r"(?:\.\./\.\./|/etc/passwd|/bin/sh|cmd\.exe|whoami)", re.I),
        "Command injection / path traversal attempt",
    ),
    (
        re.compile(r"(?:UNION\s+SELECT|OR\s+1=1|information_schema)", re.I),
        "SQL Injection payload",
    ),
    (
        re.compile(r"(?:<script>|javascript:|onerror=)", re.I),
        "Cross-Site Scripting (XSS) probe",
    ),
]


def _parse_headers(header_block: str) -> dict[str, str]:
    """Parse HTTP headers into a case-normalized dictionary."""
    headers: dict[str, str] = {}
    for line in header_block.splitlines()[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers


def _try_decode_base64(text: str) -> Optional[str]:
    """Attempt to decode embedded Base64 blobs if they decode to readable ASCII/UTF-16LE."""
    for match in BASE64_BLOB_RE.finditer(text):
        candidate = match.group(0)
        try:
            raw = base64.b64decode(candidate)
            if len(raw) >= 12:
                # Check UTF-16LE (PowerShell -EncodedCommand) or UTF-8
                decoded = (
                    raw.decode("utf-16le", errors="ignore")
                    if b"\x00" in raw[:8]
                    else raw.decode("utf-8", errors="ignore")
                )
                printable_ratio = sum(1 for c in decoded if c.isprintable()) / max(1, len(decoded))
                if printable_ratio > 0.75:
                    return decoded[:300]
        except Exception:
            continue
    return None


def decode_http_sessions(
    packets: list[ParsedPacket],
    flows: list[Flow],
    decode_payloads: bool = True,
) -> list[HTTPSession]:
    """Reconstruct HTTP request/response sessions and inspect for suspicious payloads."""
    sessions: list[HTTPSession] = []

    for flow in flows:
        if flow.protocol != "TCP":
            continue

        current_session: Optional[HTTPSession] = None

        for pkt in flow.packets:
            if not pkt.payload:
                continue

            text = pkt.payload.decode("utf-8", errors="ignore")
            req_match = HTTP_REQUEST_LINE_RE.match(text)

            if req_match:
                if current_session is not None:
                    sessions.append(current_session)

                method = req_match.group(1).upper()
                path = req_match.group(2)

                parts = text.split("\r\n\r\n", 1)
                header_block = parts[0]
                body = parts[1] if len(parts) > 1 else ""

                headers = _parse_headers(header_block)
                host = headers.get("Host", headers.get("host", pkt.dst_ip))
                ua = headers.get("User-Agent", headers.get("user-agent", ""))
                url = f"http://{host}{path}"

                if decode_payloads and body:
                    body_unquoted = urllib.parse.unquote_plus(body)
                    b64_decoded = _try_decode_base64(body_unquoted)
                    if b64_decoded:
                        body = f"{body_unquoted[:500]} [Decoded Base64: {b64_decoded}]"
                    else:
                        body = body_unquoted[:500]

                suspicious = False
                reasons: list[str] = []

                combined_inspect = f"{url} {ua} {body}"
                for pattern, label in SUSPICIOUS_PATTERNS:
                    if pattern.search(combined_inspect):
                        suspicious = True
                        reasons.append(label)

                url_b64 = _try_decode_base64(urllib.parse.unquote_plus(path))
                if url_b64:
                    suspicious = True
                    reasons.append(f"Base64 in URI ({url_b64[:60]})")

                if method in ("PROPFIND", "PUT", "DELETE"):
                    suspicious = True
                    reasons.append(f"Unusual HTTP method: {method}")

                if not ua or len(ua) < 8:
                    suspicious = True
                    reasons.append("Missing or abnormally short User-Agent")

                current_session = HTTPSession(
                    timestamp=pkt.timestamp,
                    method=method,
                    url=url,
                    host=host,
                    source_ip=pkt.src_ip,
                    destination_ip=pkt.dst_ip,
                    user_agent=ua,
                    request_headers=headers,
                    request_body=body[:500],
                    suspicious=suspicious,
                    suspicion_reason="; ".join(reasons),
                )
                continue

            resp_match = HTTP_RESPONSE_LINE_RE.match(text)
            if resp_match and current_session is not None:
                current_session.status_code = int(resp_match.group(1))
                parts = text.split("\r\n\r\n", 1)
                resp_headers = _parse_headers(parts[0])
                current_session.response_headers = resp_headers
                current_session.content_type = resp_headers.get(
                    "Content-Type", resp_headers.get("content-type", "")
                )
                current_session.response_size = len(parts[1].encode("utf-8")) if len(parts) > 1 else 0
                sessions.append(current_session)
                current_session = None

        if current_session is not None:
            sessions.append(current_session)

    sessions.sort(key=lambda s: s.timestamp)
    logger.info("Decoded %d HTTP session(s)", len(sessions))
    return sessions
