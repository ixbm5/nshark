"""Cleartext credentials detector for HTTP Basic/POST, FTP, Telnet, and SMTP."""

from __future__ import annotations

import base64
import logging
import re
from typing import Any

from nshark.core.models import (
    Alert,
    DetectionType,
    Flow,
    ParsedPacket,
    Severity,
)
from nshark.detectors.base import BaseDetector

logger = logging.getLogger(__name__)

HTTP_BASIC_RE = re.compile(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", re.IGNORECASE)
HTTP_POST_CRED_RE = re.compile(
    r"(?:user(?:name)?|login|email)=([^&\s]+).*?(?:pass(?:word)?|pwd)=([^&\s]+)",
    re.IGNORECASE | re.DOTALL,
)
FTP_USER_RE = re.compile(r"^USER\s+(\S+)", re.IGNORECASE | re.MULTILINE)
FTP_PASS_RE = re.compile(r"^PASS\s+(\S+)", re.IGNORECASE | re.MULTILINE)
SMTP_AUTH_PLAIN_RE = re.compile(r"AUTH\s+PLAIN\s+([A-Za-z0-9+/=]+)", re.IGNORECASE)


def mask_secret(secret: str) -> str:
    """Mask a password/secret so only the first 2 characters are visible."""
    cleaned = secret.strip()
    if len(cleaned) <= 2:
        return "***"
    return f"{cleaned[:2]}***"


class CleartextCredsDetector(BaseDetector):
    """Detects unencrypted authentication credentials transmitted over the wire."""

    name = "Cleartext Credentials Detector"
    detection_type = DetectionType.CLEARTEXT_CREDENTIALS

    def analyze(
        self,
        packets: list[ParsedPacket],
        flows: list[Flow],
        config: dict[str, Any],
    ) -> list[Alert]:
        """Inspect packet payloads for HTTP Basic/POST, FTP, SMTP, and Telnet credentials."""
        alerts: list[Alert] = []
        seen_creds: set[tuple[str, str, str, str]] = set()
        ftp_users: dict[tuple[str, str], str] = {}
        ftp_files: dict[tuple[str, str], list[str]] = {}
        http_auth_errors: dict[tuple[str, str], str] = {}
        telnet_flagged: set[tuple[str, str]] = set()

        # Pre-scan FTP file operations (STOR / RETR) and HTTP auth error responses
        for pkt in packets:
            if not pkt.payload:
                continue
            t_pre = pkt.payload.decode("utf-8", errors="ignore")
            if pkt.dst_port == 21 or pkt.src_port == 21:
                for m_f in re.finditer(r"^(STOR|RETR)\s+([^\r\n]+)", t_pre, re.IGNORECASE | re.MULTILINE):
                    cmd_op = m_f.group(1).upper()
                    fname = m_f.group(2).strip()
                    flist = ftp_files.setdefault((pkt.src_ip, pkt.dst_ip), [])
                    entry = f"{cmd_op} {fname}"
                    if entry not in flist:
                        flist.append(entry)
            if pkt.src_port in (80, 8000, 8080, 8888) and (
                "INVALIDPASSWORD" in t_pre.upper() or "AUTHENTICATION FAILED" in t_pre.upper()
            ):
                body_part = t_pre.split("\r\n\r\n", 1)[-1].strip()
                first_err = body_part.splitlines()[0].strip()[:90] if body_part else "Authentication Failed"
                http_auth_errors[(pkt.dst_ip, pkt.src_ip)] = first_err

        for pkt in packets:
            if not pkt.payload:
                continue

            text = pkt.payload.decode("utf-8", errors="ignore")

            # 1. HTTP Basic Auth
            basic_match = HTTP_BASIC_RE.search(text)
            if basic_match:
                b64_token = basic_match.group(1)
                try:
                    decoded = base64.b64decode(b64_token).decode("utf-8", errors="ignore")
                    if ":" in decoded:
                        username, password = decoded.split(":", 1)
                        masked = mask_secret(password)
                        dedup_key = (pkt.src_ip, pkt.dst_ip, "HTTP-Basic", username)
                        if dedup_key not in seen_creds:
                            seen_creds.add(dedup_key)
                            alerts.append(
                                Alert(
                                    detection_type=DetectionType.CLEARTEXT_CREDENTIALS,
                                    severity=Severity.HIGH,
                                    confidence=92,
                                    source_ip=pkt.src_ip,
                                    destination_ip=pkt.dst_ip,
                                    description=(
                                        f"Cleartext HTTP Basic Auth credential exposed: "
                                        f"user='{username}', pass='{masked}'"
                                    ),
                                    details={
                                        "protocol": "HTTP Basic",
                                        "username": username,
                                        "masked_password": masked,
                                        "destination_port": pkt.dst_port,
                                    },
                                    timestamp=pkt.timestamp,
                                )
                            )
                except Exception:
                    pass

            # 2. HTTP Form POST or URL Query credentials
            if "POST " in text or "password=" in text.lower() or "pass=" in text.lower():
                post_match = HTTP_POST_CRED_RE.search(text)
                if not post_match:
                    post_match = re.search(
                        r"(?:id|user(?:name)?|login|account)=([^&\s]+).*?(?:pass(?:word)?|pwd)=([^&\s]+)",
                        text,
                        re.IGNORECASE | re.DOTALL,
                    )
                if post_match:
                    username, password = post_match.group(1), post_match.group(2)
                    masked = mask_secret(password)
                    proto_label = "HTTP POST" if text.startswith("POST ") else "HTTP GET Query"
                    err_note = http_auth_errors.get((pkt.src_ip, pkt.dst_ip), "")
                    err_suffix = f" -> Server rejected: '{err_note}'" if err_note else ""
                    dedup_key = (pkt.src_ip, pkt.dst_ip, proto_label, username)
                    if dedup_key not in seen_creds:
                        seen_creds.add(dedup_key)
                        alerts.append(
                            Alert(
                                detection_type=DetectionType.CLEARTEXT_CREDENTIALS,
                                severity=Severity.HIGH,
                                confidence=90,
                                source_ip=pkt.src_ip,
                                destination_ip=pkt.dst_ip,
                                description=(
                                    f"Cleartext {proto_label} login exposed: "
                                    f"user='{username}', pass='{masked}'{err_suffix}"
                                ),
                                details={
                                    "protocol": proto_label,
                                    "username": username,
                                    "masked_password": masked,
                                    "server_response": err_note,
                                    "destination_port": pkt.dst_port,
                                },
                                timestamp=pkt.timestamp,
                            )
                        )

            # 3. FTP USER / PASS
            if pkt.dst_port == 21 or "USER " in text or "PASS " in text:
                u_match = FTP_USER_RE.search(text)
                if u_match:
                    ftp_users[(pkt.src_ip, pkt.dst_ip)] = u_match.group(1)

                p_match = FTP_PASS_RE.search(text)
                if p_match:
                    password = p_match.group(1)
                    username = ftp_users.get((pkt.src_ip, pkt.dst_ip), "unknown")
                    masked = mask_secret(password)
                    files_xferred = ftp_files.get((pkt.src_ip, pkt.dst_ip), [])
                    file_suffix = f" (file ops: {', '.join(files_xferred[:3])})" if files_xferred else ""
                    dedup_key = (pkt.src_ip, pkt.dst_ip, "FTP", username)
                    if dedup_key not in seen_creds:
                        seen_creds.add(dedup_key)
                        alerts.append(
                            Alert(
                                detection_type=DetectionType.CLEARTEXT_CREDENTIALS,
                                severity=Severity.HIGH,
                                confidence=94,
                                source_ip=pkt.src_ip,
                                destination_ip=pkt.dst_ip,
                                description=(
                                    f"Cleartext FTP login exposed: "
                                    f"USER='{username}', PASS='{masked}'{file_suffix}"
                                ),
                                details={
                                    "protocol": "FTP",
                                    "username": username,
                                    "masked_password": masked,
                                    "file_operations": files_xferred,
                                    "destination_port": pkt.dst_port,
                                },
                                timestamp=pkt.timestamp,
                            )
                        )

            # 4. SMTP AUTH PLAIN
            smtp_match = SMTP_AUTH_PLAIN_RE.search(text)
            if smtp_match:
                try:
                    raw_auth = base64.b64decode(smtp_match.group(1))
                    parts = [p.decode("utf-8", errors="ignore") for p in raw_auth.split(b"\x00") if p]
                    if len(parts) >= 2:
                        username, password = parts[-2], parts[-1]
                        masked = mask_secret(password)
                        dedup_key = (pkt.src_ip, pkt.dst_ip, "SMTP", username)
                        if dedup_key not in seen_creds:
                            seen_creds.add(dedup_key)
                            alerts.append(
                                Alert(
                                    detection_type=DetectionType.CLEARTEXT_CREDENTIALS,
                                    severity=Severity.HIGH,
                                    confidence=90,
                                    source_ip=pkt.src_ip,
                                    destination_ip=pkt.dst_ip,
                                    description=(
                                        f"Cleartext SMTP AUTH PLAIN exposed: "
                                        f"user='{username}', pass='{masked}'"
                                    ),
                                    details={
                                        "protocol": "SMTP",
                                        "username": username,
                                        "masked_password": masked,
                                        "destination_port": pkt.dst_port,
                                    },
                                    timestamp=pkt.timestamp,
                                )
                            )
                except Exception:
                    pass

            # 5. Telnet session on port 23 (require actual non-null application data, not a bare SYN probe)
            if (
                pkt.dst_port == 23
                and "S" not in pkt.flags
                and len(pkt.payload.strip(b"\x00")) > 0
                and (pkt.src_ip, pkt.dst_ip) not in telnet_flagged
            ):
                telnet_flagged.add((pkt.src_ip, pkt.dst_ip))
                alerts.append(
                    Alert(
                        detection_type=DetectionType.CLEARTEXT_CREDENTIALS,
                        severity=Severity.MEDIUM,
                        confidence=75,
                        source_ip=pkt.src_ip,
                        destination_ip=pkt.dst_ip,
                        description=f"Unencrypted Telnet session active to {pkt.dst_ip}:23",
                        details={
                            "protocol": "Telnet",
                            "destination_port": 23,
                        },
                        timestamp=pkt.timestamp,
                    )
                )

            # 6. POP3 USER / PASS (port 110)
            if pkt.dst_port == 110:
                u_pop = FTP_USER_RE.search(text)
                if u_pop:
                    ftp_users[(pkt.src_ip, pkt.dst_ip)] = u_pop.group(1)
                p_pop = FTP_PASS_RE.search(text)
                if p_pop:
                    password = p_pop.group(1)
                    username = ftp_users.get((pkt.src_ip, pkt.dst_ip), "unknown")
                    masked = mask_secret(password)
                    dedup_key = (pkt.src_ip, pkt.dst_ip, "POP3", username)
                    if dedup_key not in seen_creds:
                        seen_creds.add(dedup_key)
                        alerts.append(
                            Alert(
                                detection_type=DetectionType.CLEARTEXT_CREDENTIALS,
                                severity=Severity.HIGH,
                                confidence=92,
                                source_ip=pkt.src_ip,
                                destination_ip=pkt.dst_ip,
                                description=f"Cleartext POP3 login exposed: USER='{username}', PASS='{masked}'",
                                details={
                                    "protocol": "POP3",
                                    "username": username,
                                    "masked_password": masked,
                                    "destination_port": 110,
                                },
                                timestamp=pkt.timestamp,
                            )
                        )

            # 7. IMAP LOGIN (port 143)
            if pkt.dst_port == 143 and "LOGIN " in text.upper():
                m_imap = re.search(r"^\S+\s+LOGIN\s+\"?([^\"\s]+)\"?\s+\"?([^\"\r\n]+)\"?", text, re.IGNORECASE | re.MULTILINE)
                if m_imap:
                    username, password = m_imap.group(1), m_imap.group(2)
                    masked = mask_secret(password)
                    dedup_key = (pkt.src_ip, pkt.dst_ip, "IMAP", username)
                    if dedup_key not in seen_creds:
                        seen_creds.add(dedup_key)
                        alerts.append(
                            Alert(
                                detection_type=DetectionType.CLEARTEXT_CREDENTIALS,
                                severity=Severity.HIGH,
                                confidence=92,
                                source_ip=pkt.src_ip,
                                destination_ip=pkt.dst_ip,
                                description=f"Cleartext IMAP login exposed: user='{username}', pass='{masked}'",
                                details={
                                    "protocol": "IMAP",
                                    "username": username,
                                    "masked_password": masked,
                                    "destination_port": 143,
                                },
                                timestamp=pkt.timestamp,
                            )
                        )

            # 8. LDAP Simple Bind (port 389)
            if pkt.dst_port == 389 and b"\x60" in pkt.payload and b"\x80" in pkt.payload:
                # ASN.1 BindRequest (0x60): version INTEGER (0x02 0x01 0x03), name OCTET STRING (0x04), simple auth [0] (0x80)
                m_ldap = re.search(rb"\x02\x01\x03\x04([\x01-\x7f])(.+?)\x80([\x01-\x7f])", pkt.payload, re.DOTALL)
                if m_ldap:
                    dn_len = m_ldap.group(1)[0]
                    dn_raw = m_ldap.group(2)
                    pw_len = m_ldap.group(3)[0]
                    pw_start = m_ldap.end()
                    if len(dn_raw) == dn_len and pw_start + pw_len <= len(pkt.payload):
                        dn_str = dn_raw.decode("utf-8", errors="ignore").strip()
                        pw_str = pkt.payload[pw_start : pw_start + pw_len].decode("utf-8", errors="ignore")
                        if dn_str and pw_str:
                            masked = mask_secret(pw_str)
                            dedup_key = (pkt.src_ip, pkt.dst_ip, "LDAP", dn_str)
                            if dedup_key not in seen_creds:
                                seen_creds.add(dedup_key)
                                alerts.append(
                                    Alert(
                                        detection_type=DetectionType.CLEARTEXT_CREDENTIALS,
                                        severity=Severity.HIGH,
                                        confidence=94,
                                        source_ip=pkt.src_ip,
                                        destination_ip=pkt.dst_ip,
                                        description=f"Cleartext LDAP Simple Bind exposed: DN='{dn_str}', pass='{masked}'",
                                        details={
                                            "protocol": "LDAP",
                                            "username": dn_str,
                                            "masked_password": masked,
                                            "destination_port": 389,
                                        },
                                        timestamp=pkt.timestamp,
                                    )
                                )

            # 9. SNMPv1 / SNMPv2c Cleartext Community String (UDP port 161)
            if pkt.dst_port == 161 and pkt.payload.startswith(b"\x30"):
                # ASN.1 SEQUENCE (0x30) -> version INTEGER (0x02 0x01 0x00|0x01) -> community OCTET STRING (0x04 <len>)
                m_snmp = re.search(rb"\x02\x01[\x00\x01]\x04([\x01-\x40])", pkt.payload[:24])
                if m_snmp:
                    comm_len = m_snmp.group(1)[0]
                    comm_start = m_snmp.end()
                    if comm_start + comm_len <= len(pkt.payload):
                        community = pkt.payload[comm_start : comm_start + comm_len].decode("ascii", errors="ignore")
                        if community and all(32 <= ord(c) < 127 for c in community):
                            dedup_key = (pkt.src_ip, pkt.dst_ip, "SNMP", community)
                            if dedup_key not in seen_creds:
                                seen_creds.add(dedup_key)
                                alerts.append(
                                    Alert(
                                        detection_type=DetectionType.CLEARTEXT_CREDENTIALS,
                                        severity=Severity.MEDIUM if community == "public" else Severity.HIGH,
                                        confidence=88,
                                        source_ip=pkt.src_ip,
                                        destination_ip=pkt.dst_ip,
                                        description=f"Cleartext SNMP v1/v2c community string exposed: '{community}'",
                                        details={
                                            "protocol": "SNMP",
                                            "community_string": community,
                                            "destination_port": 161,
                                        },
                                        timestamp=pkt.timestamp,
                                    )
                                )

            # 10. Unencrypted HTTP Bearer Token / JWT or X-Api-Key header
            if pkt.dst_port in (80, 8000, 8080, 8888, 3000, 5000):
                m_bearer = re.search(r"(?:Authorization:\s*Bearer|X-Api-Key:)\s+([A-Za-z0-9._\-]{16,})", text, re.IGNORECASE)
                if m_bearer:
                    token = m_bearer.group(1).strip()
                    is_jwt = token.startswith("eyJ") and token.count(".") == 2
                    label = "JWT Bearer Token" if is_jwt else "HTTP API / Bearer Token"
                    masked_tok = f"{token[:6]}...{token[-4:]}" if len(token) > 12 else mask_secret(token)
                    dedup_key = (pkt.src_ip, pkt.dst_ip, "BEARER", token[:16])
                    if dedup_key not in seen_creds:
                        seen_creds.add(dedup_key)
                        alerts.append(
                            Alert(
                                detection_type=DetectionType.CLEARTEXT_CREDENTIALS,
                                severity=Severity.HIGH,
                                confidence=91,
                                source_ip=pkt.src_ip,
                                destination_ip=pkt.dst_ip,
                                description=f"Unencrypted {label} transmitted over HTTP: '{masked_tok}'",
                                details={
                                    "protocol": "HTTP",
                                    "token_type": label,
                                    "masked_token": masked_tok,
                                    "destination_port": pkt.dst_port,
                                },
                                timestamp=pkt.timestamp,
                            )
                        )

            # 11. Redis AUTH (port 6379) & IRC PASS (port 6667)
            if pkt.dst_port == 6379:
                m_redis = re.search(r"(?:^AUTH\s+(\S+)|\*\d+\r\n\$4\r\nAUTH\r\n\$\d+\r\n([^\r\n]+))", text, re.IGNORECASE | re.MULTILINE)
                if m_redis:
                    rpass = m_redis.group(1) or m_redis.group(2) or ""
                    if rpass:
                        masked = mask_secret(rpass)
                        dedup_key = (pkt.src_ip, pkt.dst_ip, "REDIS", masked)
                        if dedup_key not in seen_creds:
                            seen_creds.add(dedup_key)
                            alerts.append(
                                Alert(
                                    detection_type=DetectionType.CLEARTEXT_CREDENTIALS,
                                    severity=Severity.HIGH,
                                    confidence=93,
                                    source_ip=pkt.src_ip,
                                    destination_ip=pkt.dst_ip,
                                    description=f"Cleartext Redis AUTH password exposed: pass='{masked}'",
                                    details={
                                        "protocol": "Redis",
                                        "masked_password": masked,
                                        "destination_port": 6379,
                                    },
                                    timestamp=pkt.timestamp,
                                )
                            )

            # 12. PostgreSQL PasswordMessage (port 5432, tag 'p' = 0x70 followed by int32 length + password\x00)
            if pkt.dst_port == 5432 and len(pkt.payload) >= 7 and pkt.payload[0] == 0x70:
                msg_len = int.from_bytes(pkt.payload[1:5], "big")
                if 5 <= msg_len <= len(pkt.payload) - 1 and pkt.payload[msg_len] == 0:
                    pg_pass = pkt.payload[5:msg_len].decode("utf-8", errors="ignore")
                    if pg_pass and all(32 <= ord(c) < 127 for c in pg_pass):
                        masked = mask_secret(pg_pass)
                        dedup_key = (pkt.src_ip, pkt.dst_ip, "POSTGRES", masked)
                        if dedup_key not in seen_creds:
                            seen_creds.add(dedup_key)
                            alerts.append(
                                Alert(
                                    detection_type=DetectionType.CLEARTEXT_CREDENTIALS,
                                    severity=Severity.HIGH,
                                    confidence=92,
                                    source_ip=pkt.src_ip,
                                    destination_ip=pkt.dst_ip,
                                    description=f"PostgreSQL authentication credential exposed: '{masked}'",
                                    details={
                                        "protocol": "PostgreSQL",
                                        "masked_password": masked,
                                        "destination_port": 5432,
                                    },
                                    timestamp=pkt.timestamp,
                                )
                            )

        logger.info("CleartextCredsDetector found %d alert(s)", len(alerts))
        return alerts
