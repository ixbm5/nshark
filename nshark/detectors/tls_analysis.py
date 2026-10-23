"""TLS (JA3 / JA3S / X.509 Certificate) and SSH (HASSH) encrypted channel anomaly detector."""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import struct
from typing import Any, Optional

from nshark.core.models import (
    Alert,
    DetectionType,
    Flow,
    ParsedPacket,
    Severity,
)
from nshark.detectors.base import BaseDetector

logger = logging.getLogger(__name__)

# GREASE values defined by RFC 8701 must be ignored when computing JA3 / JA3S
GREASE_VALUES: set[int] = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A,
    0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}

# Curated database of known malicious / C2 / offensive JA3 MD5 client fingerprints (abuse.ch SSLBL & threat intel)
KNOWN_MALICIOUS_JA3: dict[str, str] = {
    "72a589da586844d7f0818ce684948eea": "Cobalt Strike Beacon (WinHTTP TLS Client)",
    "a0e9f5d64349fb13191bc781f81f42e1": "Metasploit Meterpreter / Reverse HTTPS",
    "51c64c77e60f3980eea90869b68c58a8": "TrickBot / Emotet Banking Trojan",
    "e7d705a3286e19ea42f587b344ee6865": "Tor Client / Darkweb Relay",
    "4d7a28d6f2263ed61de88ca66eb011e3": "Emotet / Heodo Dropper",
    "6734f37431670b3ab4292b8f60f29984": "TrickBot C2 Channel",
    "b386946a5a44d1ddcc843bc75336dfce": "Dridex Loader C2",
    "3b5074b1b5d032e5620f69f9f700ff0e": "Pony / Fareit Credential Stealer",
    "19e29534fd49dd27d09234e639c4057e": "QakBot / QBot C2 Client",
    "e35df3e00ca4ef31d42b34bebaa2f86e": "AsyncRAT / DcRat .NET TLS Client",
    "cd08e31494f9531f560d64c695473da9": "Sliver C2 Implant",
}

# Known malicious JA3S (ServerHello) MD5 fingerprints
KNOWN_MALICIOUS_JA3S: dict[str, str] = {
    "ae4edc6faf64d08308082ad26be60767": "Cobalt Strike TeamServer Default TLS",
    "fd4bc6cea4877646ccd62f0792ec0b62": "Cobalt Strike C2 Server (Linux/Kali)",
    "b742b407517bac9536a77a7b0fee28e9": "Metasploit Meterpreter SSL Handler",
    "ec74a5c51106f0419184d0dd08fb05bc": "Sliver / Empire C2 TLS Listener",
    "f4febc55ea12b31ae17cfb7e614afda8": "AsyncRAT / QuasarRAT C2 Server",
    "15af977ce25de452b96affa2addb1036": "TrickBot / BazarLoader C2 Server",
}

# Known malicious / offensive default X.509 certificate markers in TLS Certificate payloads
MALICIOUS_CERT_MARKERS: list[tuple[bytes, str]] = [
    (b"Major Cobalt Strike", "Cobalt Strike Default TLS Certificate"),
    (b"AsyncRAT Server", "AsyncRAT C2 Default TLS Certificate"),
    (b"Quasar Server CA", "QuasarRAT C2 Default TLS Certificate"),
    (b"MetasploitSelfSignedCA", "Metasploit Default Self-Signed Certificate"),
    (b"Covenant", "Covenant C2 Default Certificate"),
    (b"Pupy", "Pupy RAT Default Certificate"),
    (b"Sliver", "Sliver C2 Default Certificate"),
    (b"Havoc", "Havoc C2 Teamserver Certificate"),
    (b"Mythic", "Mythic C2 Default Certificate"),
]

# Known offensive / scripting SSH banners and HASSH fingerprints
SUSPICIOUS_SSH_BANNERS: list[tuple[str, str]] = [
    ("SSH-2.0-Go", "Go SSH Client / Tunnel (Chisel / Sliver / Ligolo)"),
    ("SSH-2.0-paramiko", "Python Paramiko Automated SSH Tool"),
    ("SSH-2.0-Impacket", "Impacket SSH Module"),
    ("SSH-2.0-Ruby/Net::SSH", "Metasploit / Ruby Net::SSH Client"),
    ("SSH-2.0-AsyncSSH", "Python AsyncSSH Offensive Scanner"),
]

KNOWN_MALICIOUS_HASSH: dict[str, str] = {
    "ec7378c1a92f5a8dde7e8b7a1ddf33d1": "Golang crypto/ssh Default Client (Chisel / C2 Tunnel)",
    "b12d2871a1189eff20364cf5333619ee": "Paramiko Python SSH Client",
}

# Known public DNS-over-TLS / DNS-over-HTTPS resolvers that legitimately connect to bare IPs on 443/853
KNOWN_DOT_IPS: set[str] = {
    "1.1.1.1", "1.0.0.1",
    "8.8.8.8", "8.8.4.4",
    "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220",
}


def _is_public_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return not (addr.is_private or addr.is_loopback or addr.is_multicast or addr.is_link_local)
    except ValueError:
        return False


def parse_tls_client_hello(payload: bytes) -> Optional[dict[str, Any]]:
    """Parse a TLS ClientHello record and compute its JA3 string, JA3 MD5 hash, and SNI."""
    if len(payload) < 44:
        return None

    # TLS Handshake record (0x16), TLS major version 0x03, Handshake type ClientHello (0x01)
    if payload[0] != 0x16 or payload[1] != 0x03 or payload[5] != 0x01:
        return None

    try:
        tls_version = struct.unpack("!H", payload[9:11])[0]
        pos = 43  # Skip 32-byte random

        if pos >= len(payload):
            return None
        sid_len = payload[pos]
        pos += 1 + sid_len

        if pos + 2 > len(payload):
            return None
        cs_len = struct.unpack("!H", payload[pos : pos + 2])[0]
        pos += 2

        if pos + cs_len > len(payload):
            return None
        ciphers: list[int] = []
        for i in range(0, cs_len, 2):
            c_val = struct.unpack("!H", payload[pos + i : pos + i + 2])[0]
            if c_val not in GREASE_VALUES:
                ciphers.append(c_val)
        pos += cs_len

        if pos >= len(payload):
            return None
        comp_len = payload[pos]
        pos += 1 + comp_len

        extensions: list[int] = []
        curves: list[int] = []
        point_formats: list[int] = []
        sni: Optional[str] = None

        if pos + 2 <= len(payload):
            ext_total_len = struct.unpack("!H", payload[pos : pos + 2])[0]
            pos += 2
            ext_end = min(len(payload), pos + ext_total_len)

            while pos + 4 <= ext_end:
                ext_type, ext_len = struct.unpack("!HH", payload[pos : pos + 4])
                pos += 4
                ext_data = payload[pos : pos + ext_len]
                pos += ext_len

                if ext_type not in GREASE_VALUES:
                    extensions.append(ext_type)

                # SNI (0x0000)
                if ext_type == 0x0000 and len(ext_data) >= 5:
                    name_len = struct.unpack("!H", ext_data[3:5])[0]
                    if 5 + name_len <= len(ext_data):
                        sni = ext_data[5 : 5 + name_len].decode("utf-8", errors="ignore")

                # Supported Groups / Elliptic Curves (0x000a)
                elif ext_type == 0x000A and len(ext_data) >= 2:
                    curves_len = struct.unpack("!H", ext_data[:2])[0]
                    for j in range(2, min(len(ext_data), 2 + curves_len) - 1, 2):
                        curve_id = struct.unpack("!H", ext_data[j : j + 2])[0]
                        if curve_id not in GREASE_VALUES:
                            curves.append(curve_id)

                # EC Point Formats (0x000b)
                elif ext_type == 0x000B and len(ext_data) >= 1:
                    pf_len = ext_data[0]
                    for j in range(1, min(len(ext_data), 1 + pf_len)):
                        point_formats.append(ext_data[j])

        ja3_str = (
            f"{tls_version},"
            f"{'-'.join(str(x) for x in ciphers)},"
            f"{'-'.join(str(x) for x in extensions)},"
            f"{'-'.join(str(x) for x in curves)},"
            f"{'-'.join(str(x) for x in point_formats)}"
        )
        ja3_hash = hashlib.md5(ja3_str.encode("ascii")).hexdigest()
        return {
            "tls_version": tls_version,
            "ja3_string": ja3_str,
            "ja3_hash": ja3_hash,
            "sni": sni,
            "cipher_count": len(ciphers),
        }
    except Exception:
        return None


def parse_tls_server_hello(payload: bytes) -> Optional[dict[str, Any]]:
    """Parse a TLS ServerHello record and compute its JA3S string and JA3S MD5 hash."""
    if len(payload) < 47:
        return None

    # TLS Handshake record (0x16), TLS major version 0x03, Handshake type ServerHello (0x02)
    if payload[0] != 0x16 or payload[1] != 0x03 or payload[5] != 0x02:
        return None

    try:
        tls_version = struct.unpack("!H", payload[9:11])[0]
        pos = 43  # Skip 32-byte server random

        if pos >= len(payload):
            return None
        sid_len = payload[pos]
        pos += 1 + sid_len

        if pos + 3 > len(payload):
            return None
        cipher_suite = struct.unpack("!H", payload[pos : pos + 2])[0]
        # Skip cipher_suite (2 bytes) + compression_method (1 byte)
        pos += 3

        extensions: list[int] = []
        if pos + 2 <= len(payload):
            ext_total_len = struct.unpack("!H", payload[pos : pos + 2])[0]
            pos += 2
            ext_end = min(len(payload), pos + ext_total_len)

            while pos + 4 <= ext_end:
                ext_type, ext_len = struct.unpack("!HH", payload[pos : pos + 4])
                pos += 4 + ext_len
                if ext_type not in GREASE_VALUES:
                    extensions.append(ext_type)

        ja3s_str = f"{tls_version},{cipher_suite},{'-'.join(str(x) for x in extensions)}"
        ja3s_hash = hashlib.md5(ja3s_str.encode("ascii")).hexdigest()
        return {
            "tls_version": tls_version,
            "cipher_suite": cipher_suite,
            "ja3s_string": ja3s_str,
            "ja3s_hash": ja3s_hash,
        }
    except Exception:
        return None


def parse_ssh_kexinit(payload: bytes) -> Optional[dict[str, str]]:
    """Parse an SSH_MSG_KEXINIT (code 20) packet and compute HASSH and HASSHServer MD5 fingerprints."""
    data = payload
    # Strip optional SSH-2.0-* banner line if bundled in the same TCP packet
    if data.startswith(b"SSH-"):
        nl = data.find(b"\n")
        if nl == -1:
            return None
        data = data[nl + 1 :]

    if len(data) < 36:
        return None

    try:
        pkt_len = struct.unpack("!I", data[:4])[0]
        pad_len = data[4]
        msg_code = data[5]
        if msg_code != 20 or pkt_len < 22 or pkt_len > 32768:
            return None

        pos = 22  # 4 (pkt_len) + 1 (pad_len) + 1 (msg_code=20) + 16 (cookie)
        lists: list[str] = []
        for _ in range(8):
            if pos + 4 > len(data):
                return None
            slen = struct.unpack("!I", data[pos : pos + 4])[0]
            pos += 4
            if pos + slen > len(data) or slen > 8192:
                return None
            lists.append(data[pos : pos + slen].decode("ascii", errors="ignore"))
            pos += slen

        # lists: [0]=kex, [1]=host_key, [2]=enc_c2s, [3]=enc_s2c, [4]=mac_c2s, [5]=mac_s2c, [6]=comp_c2s, [7]=comp_s2c
        client_hassh_str = f"{lists[0]};{lists[2]};{lists[4]};{lists[6]}"
        server_hassh_str = f"{lists[0]};{lists[3]};{lists[5]};{lists[7]}"
        return {
            "hassh_string": client_hassh_str,
            "hassh": hashlib.md5(client_hassh_str.encode("ascii")).hexdigest(),
            "hassh_server_string": server_hassh_str,
            "hassh_server": hashlib.md5(server_hassh_str.encode("ascii")).hexdigest(),
        }
    except Exception:
        return None


class TLSAnalysisDetector(BaseDetector):
    """Detects malicious JA3/JA3S TLS fingerprints, C2 certificates, SNI-less TLS, and SSH HASSH anomalies."""

    name = "TLS (JA3/JA3S) & SSH (HASSH) Detector"
    detection_type = DetectionType.TLS_ANOMALY

    def analyze(
        self,
        packets: list[ParsedPacket],
        flows: list[Flow],
        config: dict[str, Any],
    ) -> list[Alert]:
        """Inspect TCP payloads for TLS JA3/JA3S fingerprints, Certificate markers, and SSH HASSH anomalies."""
        alerts: list[Alert] = []
        seen_ja3_alerts: set[tuple[str, str, str]] = set()
        seen_ja3s_alerts: set[tuple[str, str, str]] = set()
        seen_cert_alerts: set[tuple[str, str, str]] = set()
        seen_ssh_alerts: set[tuple[str, str, str]] = set()
        seen_proto_alerts: set[tuple[str, str, str]] = set()
        no_sni_flows: dict[tuple[str, str], list[ParsedPacket]] = {}
        tls_client_flows: dict[tuple[str, int, str, int], ParsedPacket] = {}
        ccs_counts: dict[tuple[str, int, str, int], list[ParsedPacket]] = {}
        appdata_seen: set[tuple[str, int, str, int]] = set()
        reneg_handshakes: dict[tuple[str, int, str, int], list[ParsedPacket]] = {}
        heartbleed_flows: dict[tuple[str, str], dict[str, Any]] = {}

        for pkt in packets:
            if pkt.protocol != "TCP" or len(pkt.payload) < 6:
                continue

            flow_4tuple = (
                (pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port)
                if (pkt.src_ip, pkt.src_port) <= (pkt.dst_ip, pkt.dst_port)
                else (pkt.dst_ip, pkt.dst_port, pkt.src_ip, pkt.src_port)
            )

            # 0. Check for TLS Heartbleed (CVE-2014-0160) — TLS Record Type 24 (0x18)
            hb_idx = 0
            while hb_idx <= len(pkt.payload) - 8:
                pos_hb = pkt.payload.find(b"\x18\x03", hb_idx)
                if pos_hb == -1 or pos_hb + 8 > len(pkt.payload):
                    break
                minor_ver = pkt.payload[pos_hb + 2]
                if minor_ver in (0x00, 0x01, 0x02, 0x03):
                    rec_len = struct.unpack("!H", pkt.payload[pos_hb + 3 : pos_hb + 5])[0]
                    hb_type = pkt.payload[pos_hb + 5]
                    hb_pay_len = struct.unpack("!H", pkt.payload[pos_hb + 6 : pos_hb + 8])[0]
                    if hb_type == 1 and ((hb_pay_len > rec_len and rec_len <= 128 and hb_pay_len >= 256) or hb_pay_len >= 4096):
                        pair = (pkt.src_ip, pkt.dst_ip)
                        info = heartbleed_flows.setdefault(
                            pair,
                            {
                                "attacker": pkt.src_ip,
                                "victim": pkt.dst_ip,
                                "port": pkt.dst_port,
                                "req_count": 0,
                                "max_declared": 0,
                                "actual_rec": rec_len,
                                "leaked_bytes": 0,
                                "timestamp": pkt.timestamp,
                            },
                        )
                        info["req_count"] += 1
                        info["max_declared"] = max(info["max_declared"], hb_pay_len)
                    elif hb_type == 2 and rec_len >= 1024:
                        pair = (pkt.dst_ip, pkt.src_ip)
                        if pair in heartbleed_flows:
                            heartbleed_flows[pair]["leaked_bytes"] += rec_len
                hb_idx = pos_hb + 5

            # Track TLS ApplicationData (0x17 0x03) followed by mid-session TLS Handshake records (0x16 0x03) for Renegotiation
            if pkt.payload[0] == 0x17 and pkt.payload[1] == 0x03 and pkt.payload[2] in (0, 1, 2, 3):
                appdata_seen.add(flow_4tuple)
            elif (
                pkt.payload[0] == 0x16
                and pkt.payload[1] == 0x03
                and pkt.payload[2] in (0, 1, 2, 3)
                and flow_4tuple in appdata_seen
            ):
                reneg_handshakes.setdefault(flow_4tuple, []).append(pkt)

            # Track ChangeCipherSpec (0x14 0x03 0x0X) for TLS Renegotiation detection
            if pkt.payload[0] == 0x14 and pkt.payload[1] == 0x03 and pkt.payload[2] in (0, 1, 2, 3):
                ccs_counts.setdefault(flow_4tuple, []).append(pkt)

            if len(pkt.payload) < 8:
                continue

            # 1. Check TLS ClientHello for JA3 and SNI
            ch = parse_tls_client_hello(pkt.payload)
            if ch is not None:
                tls_client_flows[(pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port)] = pkt
                ja3_hash = ch["ja3_hash"]
                sni = ch["sni"]

                if ja3_hash in KNOWN_MALICIOUS_JA3:
                    malware_family = KNOWN_MALICIOUS_JA3[ja3_hash]
                    key = (pkt.src_ip, pkt.dst_ip, ja3_hash)
                    if key not in seen_ja3_alerts:
                        seen_ja3_alerts.add(key)
                        alerts.append(
                            Alert(
                                detection_type=DetectionType.TLS_ANOMALY,
                                severity=Severity.CRITICAL,
                                confidence=94,
                                source_ip=pkt.src_ip,
                                destination_ip=pkt.dst_ip,
                                description=(
                                    f"Malicious JA3 TLS client fingerprint: {malware_family} "
                                    f"(JA3={ja3_hash}, SNI={sni or 'none'})"
                                ),
                                details={
                                    "ja3_hash": ja3_hash,
                                    "ja3_string": ch["ja3_string"],
                                    "malware_family": malware_family,
                                    "sni": sni or "",
                                    "destination_port": pkt.dst_port,
                                },
                                timestamp=pkt.timestamp,
                            )
                        )

                # Track direct-to-IP TLS handshakes (no SNI hostname) to non-DoT public IPs
                if not sni and _is_public_ip(pkt.dst_ip) and pkt.dst_ip not in KNOWN_DOT_IPS:
                    no_sni_flows.setdefault((pkt.src_ip, pkt.dst_ip), []).append(pkt)

            # Check for TLS-to-Plaintext HTTP server mismatch (client sent ClientHello, server replied with HTTP/HTML)
            rev_4tuple = (pkt.dst_ip, pkt.dst_port, pkt.src_ip, pkt.src_port)
            if rev_4tuple in tls_client_flows and (
                pkt.payload.startswith((b"HTTP/1.", b"<!DOCTYPE", b"<html", b"<HTML"))
                or b"400 Bad Request" in pkt.payload[:256]
            ):
                mkey = (pkt.dst_ip, pkt.src_ip, "tls_to_http")
                if mkey not in seen_proto_alerts:
                    seen_proto_alerts.add(mkey)
                    first_line = pkt.payload.split(b"\r\n", 1)[0].decode("ascii", errors="ignore").strip()[:80]
                    alerts.append(
                        Alert(
                            detection_type=DetectionType.TLS_ANOMALY,
                            severity=Severity.MEDIUM,
                            confidence=88,
                            source_ip=pkt.dst_ip,
                            destination_ip=pkt.src_ip,
                            description=(
                                f"TLS-to-Plaintext HTTP Protocol Mismatch: Client sent TLS ClientHello to "
                                f"{pkt.src_ip}:{pkt.src_port}, server replied in plaintext ('{first_line}')"
                            ),
                            details={
                                "client_ip": pkt.dst_ip,
                                "server_ip": pkt.src_ip,
                                "server_port": pkt.src_port,
                                "plaintext_response": first_line,
                            },
                            timestamp=pkt.timestamp,
                        )
                    )

            # 2. Check TLS ServerHello for JA3S C2 Server fingerprints (exclude standard RDP port 3389 TLS 1.0 self-signed)
            sh = parse_tls_server_hello(pkt.payload)
            if sh is not None:
                ja3s_hash = sh["ja3s_hash"]
                if ja3s_hash in KNOWN_MALICIOUS_JA3S and pkt.src_port != 3389:
                    c2_server_label = KNOWN_MALICIOUS_JA3S[ja3s_hash]
                    skey = (pkt.src_ip, pkt.dst_ip, ja3s_hash)
                    if skey not in seen_ja3s_alerts:
                        seen_ja3s_alerts.add(skey)
                        alerts.append(
                            Alert(
                                detection_type=DetectionType.TLS_ANOMALY,
                                severity=Severity.CRITICAL,
                                confidence=93,
                                source_ip=pkt.src_ip,
                                destination_ip=pkt.dst_ip,
                                description=(
                                    f"Malicious JA3S TLS server fingerprint: {c2_server_label} "
                                    f"(JA3S={ja3s_hash} from {pkt.src_ip}:{pkt.src_port})"
                                ),
                                details={
                                    "ja3s_hash": ja3s_hash,
                                    "ja3s_string": sh["ja3s_string"],
                                    "c2_profile": c2_server_label,
                                    "source_port": pkt.src_port,
                                },
                                timestamp=pkt.timestamp,
                            )
                        )

            # 3. Check TLS Handshake payloads for C2 certificates, CVE-2015-3194, expired certs, and missing CN
            if pkt.payload[0] == 0x16 and pkt.payload[1] == 0x03:
                for marker, label in MALICIOUS_CERT_MARKERS:
                    if marker in pkt.payload:
                        ckey = (pkt.src_ip, pkt.dst_ip, label)
                        if ckey not in seen_cert_alerts:
                            seen_cert_alerts.add(ckey)
                            alerts.append(
                                Alert(
                                    detection_type=DetectionType.TLS_ANOMALY,
                                    severity=Severity.CRITICAL,
                                    confidence=95,
                                    source_ip=pkt.src_ip,
                                    destination_ip=pkt.dst_ip,
                                    description=f"{label} observed in TLS handshake from {pkt.src_ip}",
                                    details={
                                        "certificate_indicator": label,
                                        "source_port": pkt.src_port,
                                    },
                                    timestamp=pkt.timestamp,
                                )
                            )

                # CVE-2015-3194: OpenSSL RSASSA-PSS ASN.1 signature algorithm NULL parameter DoS (OID 1.2.840.113549.1.1.10)
                if b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a" in pkt.payload:
                    cve_key = (pkt.src_ip, pkt.dst_ip, "CVE-2015-3194")
                    if cve_key not in seen_cert_alerts:
                        seen_cert_alerts.add(cve_key)
                        alerts.append(
                            Alert(
                                detection_type=DetectionType.TLS_ANOMALY,
                                severity=Severity.CRITICAL,
                                confidence=95,
                                source_ip=pkt.src_ip,
                                destination_ip=pkt.dst_ip,
                                description=(
                                    f"OpenSSL RSASSA-PSS Certificate Exploit / DoS (CVE-2015-3194): "
                                    f"Malformed RSASSA-PSS OID (1.2.840.113549.1.1.10) in X.509 certificate from {pkt.src_ip}"
                                ),
                                details={
                                    "cve": "CVE-2015-3194",
                                    "oid": "1.2.840.113549.1.1.10",
                                    "source_port": pkt.src_port,
                                },
                                timestamp=pkt.timestamp,
                            )
                        )

                # Inspect X.509 Certificate Handshake message (Handshake Type 11 = 0x0b)
                # Look for ASN.1 UTCTime pairs (\x17\x0dYYMMDDHHMMSSZ) to detect expired certificates
                import re as _re
                from datetime import datetime as _dt, timezone as _tz

                utc_times = _re.findall(rb"\x17\x0d([0-9]{12})Z", pkt.payload)
                if len(utc_times) >= 2 and pkt.timestamp:
                    try:
                        not_before_raw = utc_times[0].decode("ascii")
                        not_after_raw = utc_times[1].decode("ascii")
                        yr = int(not_after_raw[:2])
                        full_yr = 2000 + yr if yr < 50 else 1900 + yr
                        not_after_dt = _dt(
                            full_yr,
                            int(not_after_raw[2:4]),
                            int(not_after_raw[4:6]),
                            int(not_after_raw[6:8]),
                            int(not_after_raw[8:10]),
                            int(not_after_raw[10:12]),
                            tzinfo=_tz.utc,
                        )
                        pkt_ts = (
                            pkt.timestamp
                            if pkt.timestamp.tzinfo is not None
                            else pkt.timestamp.replace(tzinfo=_tz.utc)
                        )
                        if not_after_dt < pkt_ts:
                            ekey = (pkt.src_ip, pkt.dst_ip, "expired_cert")
                            if ekey not in seen_cert_alerts:
                                seen_cert_alerts.add(ekey)
                                validity_end = _re.search(rb"\x17\x0d[0-9]{12}Z\x17\x0d[0-9]{12}Z", pkt.payload)
                                cn_re = _re.compile(rb"\x06\x03\x55\x04\x03[\x0c\x13\x14\x16]([\x01-\x40])")
                                cn_match = cn_re.search(pkt.payload, validity_end.end()) if validity_end else None
                                if cn_match is None:
                                    cn_match = cn_re.search(pkt.payload)
                                cn_val = ""
                                if cn_match:
                                    cn_len = cn_match.group(1)[0]
                                    cn_start = cn_match.end()
                                    cn_val = pkt.payload[cn_start : cn_start + cn_len].decode("utf-8", errors="ignore")
                                alerts.append(
                                    Alert(
                                        detection_type=DetectionType.TLS_ANOMALY,
                                        severity=Severity.HIGH,
                                        confidence=90,
                                        source_ip=pkt.src_ip,
                                        destination_ip=pkt.dst_ip,
                                        description=(
                                            f"Expired X.509 TLS Certificate presented by {pkt.src_ip}:{pkt.src_port} "
                                            f"(CN={cn_val or 'unknown'}, expired {not_after_dt.strftime('%Y-%m-%d')}, "
                                            f"captured {pkt_ts.strftime('%Y-%m-%d')})"
                                        ),
                                        details={
                                            "certificate_cn": cn_val,
                                            "not_before": not_before_raw,
                                            "not_after": not_after_dt.isoformat(),
                                            "capture_timestamp": pkt_ts.isoformat(),
                                        },
                                        timestamp=pkt.timestamp,
                                    )
                                )
                    except Exception:
                        pass

                # Check for X.509 Certificate missing Subject CommonName (OID 2.5.4.3 = \x06\x03\x55\x04\x03)
                # Only trigger when a complete single-record Certificate message is present and has Organization (2.5.4.10) but 0 CNs
                if (
                    b"\x06\x03\x55\x04\x0a" in pkt.payload
                    and b"\x06\x03\x55\x04\x03" not in pkt.payload
                    and len(utc_times) >= 2
                ):
                    nkey = (pkt.src_ip, pkt.dst_ip, "cert_no_cn")
                    if nkey not in seen_cert_alerts:
                        seen_cert_alerts.add(nkey)
                        org_m = _re.search(rb"\x06\x03\x55\x04\x0a[\x0c\x13\x14\x16]([\x01-\x40])", pkt.payload)
                        org_val = ""
                        if org_m:
                            olen = org_m.group(1)[0]
                            ostart = org_m.end()
                            org_val = pkt.payload[ostart : ostart + olen].decode("utf-8", errors="ignore")
                        alerts.append(
                            Alert(
                                detection_type=DetectionType.TLS_ANOMALY,
                                severity=Severity.MEDIUM,
                                confidence=86,
                                source_ip=pkt.src_ip,
                                destination_ip=pkt.dst_ip,
                                description=(
                                    f"Anomalous X.509 Certificate missing CommonName (CN) attribute "
                                    f"from {pkt.src_ip}:{pkt.src_port} (O='{org_val or 'unknown'}')"
                                ),
                                details={
                                    "certificate_org": org_val,
                                    "anomaly": "Missing Subject CommonName (OID 2.5.4.3)",
                                },
                                timestamp=pkt.timestamp,
                            )
                        )

            # 3b. OCSP Response Certificate Revocation check (application/ocsp-response with RevokedInfo [1] 0xa1)
            if b"application/ocsp-response" in pkt.payload and b"\x18\x0f20" in pkt.payload:
                import re as _re

                rev_m = _re.search(rb"\xa1[\x11-\x18]\x18\x0f([0-9]{14}Z)", pkt.payload)
                if rev_m:
                    rev_date = rev_m.group(1).decode("ascii", errors="ignore")
                    okey = (pkt.src_ip, pkt.dst_ip, "ocsp_revoked")
                    if okey not in seen_cert_alerts:
                        seen_cert_alerts.add(okey)
                        alerts.append(
                            Alert(
                                detection_type=DetectionType.TLS_ANOMALY,
                                severity=Severity.HIGH,
                                confidence=92,
                                source_ip=pkt.src_ip,
                                destination_ip=pkt.dst_ip,
                                description=(
                                    f"OCSP Revoked Certificate Status returned by {pkt.src_ip}: "
                                    f"Target X.509 certificate was revoked at {rev_date[:4]}-{rev_date[4:6]}-{rev_date[6:8]}"
                                ),
                                details={
                                    "protocol": "OCSP",
                                    "certificate_status": "REVOKED",
                                    "revocation_time": rev_date,
                                },
                                timestamp=pkt.timestamp,
                            )
                        )

            # 4. SSH Banner & HASSH Fingerprinting (Port 22 or non-standard SSH ports)
            if pkt.payload.startswith(b"SSH-2.0-") or b"SSH-2.0-" in pkt.payload[:32]:
                banner_line = pkt.payload.split(b"\n", 1)[0].decode("ascii", errors="ignore").strip()
                for prefix, tool_desc in SUSPICIOUS_SSH_BANNERS:
                    if banner_line.startswith(prefix):
                        bkey = (pkt.src_ip, pkt.dst_ip, prefix)
                        if bkey not in seen_ssh_alerts:
                            seen_ssh_alerts.add(bkey)
                            alerts.append(
                                Alert(
                                    detection_type=DetectionType.TLS_ANOMALY,
                                    severity=Severity.HIGH,
                                    confidence=86,
                                    source_ip=pkt.src_ip,
                                    destination_ip=pkt.dst_ip,
                                    description=f"Suspicious SSH client/tunnel banner: {tool_desc} ({banner_line})",
                                    details={
                                        "protocol": "SSH",
                                        "ssh_banner": banner_line,
                                        "tool": tool_desc,
                                        "destination_port": pkt.dst_port,
                                    },
                                    timestamp=pkt.timestamp,
                                )
                            )
                # Also flag SSH running over non-standard ports (e.g. 443, 8080, 4444) for C2 tunneling
                if pkt.src_port not in (22, 2222) and pkt.dst_port not in (22, 2222):
                    nkey = (pkt.src_ip, pkt.dst_ip, f"nonstd_ssh_{min(pkt.src_port, pkt.dst_port)}")
                    if nkey not in seen_ssh_alerts:
                        seen_ssh_alerts.add(nkey)
                        alerts.append(
                            Alert(
                                detection_type=DetectionType.TLS_ANOMALY,
                                severity=Severity.HIGH,
                                confidence=84,
                                source_ip=pkt.src_ip,
                                destination_ip=pkt.dst_ip,
                                description=(
                                    f"SSH protocol running on non-standard port "
                                    f"({pkt.src_ip}:{pkt.src_port} -> {pkt.dst_ip}:{pkt.dst_port}, banner={banner_line})"
                                ),
                                details={
                                    "protocol": "SSH",
                                    "ssh_banner": banner_line,
                                    "source_port": pkt.src_port,
                                    "destination_port": pkt.dst_port,
                                },
                                timestamp=pkt.timestamp,
                            )
                        )

            kex = parse_ssh_kexinit(pkt.payload)
            if kex is not None:
                hassh = kex["hassh"]
                if hassh in KNOWN_MALICIOUS_HASSH:
                    hlabel = KNOWN_MALICIOUS_HASSH[hassh]
                    hkey = (pkt.src_ip, pkt.dst_ip, hassh)
                    if hkey not in seen_ssh_alerts:
                        seen_ssh_alerts.add(hkey)
                        alerts.append(
                            Alert(
                                detection_type=DetectionType.TLS_ANOMALY,
                                severity=Severity.HIGH,
                                confidence=88,
                                source_ip=pkt.src_ip,
                                destination_ip=pkt.dst_ip,
                                description=f"Suspicious SSH HASSH fingerprint: {hlabel} (HASSH={hassh})",
                                details={
                                    "protocol": "SSH",
                                    "hassh": hassh,
                                    "hassh_string": kex["hassh_string"],
                                    "tool": hlabel,
                                },
                                timestamp=pkt.timestamp,
                            )
                        )

        # Emit Heartbleed (CVE-2014-0160) alerts
        for (attacker_ip, victim_ip), hb in heartbleed_flows.items():
            leak_str = (
                f" -> EXPLOIT SUCCEEDED (leaked {hb['leaked_bytes']:,}B of server heap memory)"
                if hb["leaked_bytes"] > 0
                else " (16KB buffer over-read probe; server did not return HeartbeatResponse)"
            )
            alerts.append(
                Alert(
                    detection_type=DetectionType.TLS_ANOMALY,
                    severity=Severity.CRITICAL,
                    confidence=98,
                    source_ip=attacker_ip,
                    destination_ip=victim_ip,
                    description=(
                        f"OpenSSL TLS Heartbleed Exploit (CVE-2014-0160): {hb['req_count']} "
                        f"HeartbeatRequest(s) to {victim_ip}:{hb['port']} declaring {hb['max_declared']:,}B payload"
                        f"{leak_str}"
                    ),
                    details={
                        "cve": "CVE-2014-0160",
                        "declared_payload_length": hb["max_declared"],
                        "actual_record_length": hb["actual_rec"],
                        "request_count": hb["req_count"],
                        "leaked_bytes": hb["leaked_bytes"],
                    },
                    timestamp=hb["timestamp"],
                )
            )

        # Emit Repeated TLS Renegotiation alerts (post-AppData encrypted Handshake records or >= 3 ChangeCipherSpec)
        all_reneg_flows = set(reneg_handshakes.keys()) | set(ccs_counts.keys())
        for ftuple in all_reneg_flows:
            ip1, p1, ip2, p2 = ftuple
            r_pkts = reneg_handshakes.get(ftuple, [])
            c_pkts = ccs_counts.get(ftuple, [])
            if len(r_pkts) >= 4 or len(c_pkts) >= 3:
                ref_pkt = r_pkts[0] if r_pkts else c_pkts[0]
                alerts.append(
                    Alert(
                        detection_type=DetectionType.TLS_ANOMALY,
                        severity=Severity.HIGH,
                        confidence=88,
                        source_ip=ref_pkt.src_ip,
                        destination_ip=ref_pkt.dst_ip,
                        description=(
                            f"Repeated Mid-Session TLS Renegotiation: {len(r_pkts)} encrypted Handshake records "
                            f"and {len(c_pkts)} ChangeCipherSpec transitions after ApplicationData on "
                            f"{ip1}:{p1} <-> {ip2}:{p2}"
                        ),
                        details={
                            "renegotiation_handshake_packets": len(r_pkts),
                            "change_cipher_spec_count": len(c_pkts),
                            "session": f"{ip1}:{p1}-{ip2}:{p2}",
                        },
                        timestamp=ref_pkt.timestamp,
                    )
                )

        # 5. Alert on repeated SNI-less TLS connections to bare public IPs (>= 3 handshakes)
        for (src_ip, dst_ip), pkts in no_sni_flows.items():
            if len(pkts) >= 3:
                alerts.append(
                    Alert(
                        detection_type=DetectionType.TLS_ANOMALY,
                        severity=Severity.MEDIUM,
                        confidence=76,
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        description=(
                            f"Direct-to-IP TLS handshakes without SNI domain ({len(pkts)} sessions to {dst_ip})"
                        ),
                        details={
                            "handshake_count": len(pkts),
                            "destination_ip": dst_ip,
                        },
                        timestamp=pkts[0].timestamp,
                    )
                )

        logger.info("TLSAnalysisDetector produced %d alerts", len(alerts))
        return alerts

