"""Extract crackable Hashcat-ready hashes (NetNTLMv2/v1, Kerberos RC4/AES AS-REP & TGS-REP, HTTP/SIP Digest) from PCAPs."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import logging
import re
import struct
from typing import Optional

from nshark.core.models import ParsedPacket

logger = logging.getLogger(__name__)

DIGEST_AUTH_RE = re.compile(r"Authorization:\s*Digest\s+([^\r\n]+)", re.IGNORECASE)
DIGEST_KV_RE = re.compile(r'(\w+)\s*=\s*(?:"([^"]*)"|([^\s,]+))')
REQ_METHOD_RE = re.compile(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|REGISTER|INVITE|SUBSCRIBE)\s+(\S+)", re.IGNORECASE)


@dataclass
class ExtractedHash:
    """A crackable authentication hash formatted for Hashcat / John the Ripper."""

    hash_type: str          # e.g. "NetNTLMv2", "NetNTLMv1", "Kerberos 5 TGS-REP (etype 23)", "HTTP/SIP Digest"
    hashcat_mode: int       # e.g. 5600, 5500, 13100, 18200, 19600, 19700, 11400
    username: str
    domain: str
    source_ip: str
    target_ip: str
    hash_string: str        # Ready to paste into hashcat
    timestamp: Optional[datetime] = None


def _decode_ntlm_field(msg: bytes, length: int, offset: int) -> str:
    if length == 0 or offset < 0 or offset + length > len(msg):
        return ""
    raw = msg[offset : offset + length]
    if b"\x00" in raw:
        return raw.decode("utf-16le", errors="ignore").strip("\x00 ")
    return raw.decode("latin-1", errors="ignore").strip("\x00 ")


def _extract_der_octet_strings(data: bytes, min_len: int = 24) -> list[bytes]:
    """Find ASN.1 OCTET STRING (0x04) blobs of at least min_len bytes."""
    blobs: list[bytes] = []
    i = 0
    n = len(data)
    while i < n - 4:
        if data[i] == 0x04:
            length_byte = data[i + 1]
            if length_byte < 0x80:
                length = length_byte
                hdr_len = 2
            elif length_byte == 0x81 and i + 2 < n:
                length = data[i + 2]
                hdr_len = 3
            elif length_byte == 0x82 and i + 3 < n:
                length = (data[i + 2] << 8) | data[i + 3]
                hdr_len = 4
            else:
                i += 1
                continue
            start = i + hdr_len
            end = start + length
            if length >= min_len and end <= n:
                blobs.append(data[start:end])
                i = end
                continue
        i += 1
    return blobs


def _extract_asn1_general_strings(data: bytes) -> list[str]:
    """Extract readable ASN.1 GeneralString (0x1b) values from a Kerberos packet."""
    strings: list[str] = []
    for m in re.finditer(rb"\x1b([\x01-\x40])", data):
        length = m.group(1)[0]
        start = m.end()
        if start + length <= len(data):
            raw = data[start : start + length]
            if all(32 <= b < 127 for b in raw):
                strings.append(raw.decode("ascii", errors="ignore"))
    return strings


def extract_hashes(packets: list[ParsedPacket]) -> list[ExtractedHash]:
    """Scan packets for NTLMSSP Challenge/Response pairs, Kerberos RC4/AES tickets, and HTTP/SIP Digest hashes."""
    results: list[ExtractedHash] = []
    seen_hashes: set[str] = set()

    # Map (client_ip, server_ip, client_port) -> 8-byte ServerChallenge hex
    ntlm_challenges: dict[tuple[str, str, int], str] = {}
    ntlm_challenges_by_pair: dict[tuple[str, str], str] = {}
    pg_users: dict[tuple[str, str], str] = {}
    pg_salts: dict[tuple[str, str], str] = {}
    mysql_salts: dict[tuple[str, str], str] = {}

    for pkt in packets:
        payload = pkt.payload
        if not payload:
            continue

        # ------------------------------------------------------------------
        # 1. NTLMSSP Type 2 (Server Challenge): NTLMSSP\x00\x02\x00\x00\x00
        # ------------------------------------------------------------------
        idx_t2 = payload.find(b"NTLMSSP\x00\x02\x00\x00\x00")
        if idx_t2 >= 0:
            msg2 = payload[idx_t2:]
            if len(msg2) >= 32:
                server_challenge = msg2[24:32].hex()
                ntlm_challenges[(pkt.dst_ip, pkt.src_ip, pkt.dst_port)] = server_challenge
                ntlm_challenges_by_pair[(pkt.dst_ip, pkt.src_ip)] = server_challenge

        # ------------------------------------------------------------------
        # 2. NTLMSSP Type 3 (Client Auth): NTLMSSP\x00\x03\x00\x00\x00
        # ------------------------------------------------------------------
        idx_t3 = payload.find(b"NTLMSSP\x00\x03\x00\x00\x00")
        if idx_t3 >= 0:
            msg3 = payload[idx_t3:]
            if len(msg3) >= 64:
                try:
                    lm_len, _, lm_off = struct.unpack_from("<HHI", msg3, 12)
                    nt_len, _, nt_off = struct.unpack_from("<HHI", msg3, 20)
                    dom_len, _, dom_off = struct.unpack_from("<HHI", msg3, 28)
                    usr_len, _, usr_off = struct.unpack_from("<HHI", msg3, 36)

                    domain = _decode_ntlm_field(msg3, dom_len, dom_off)
                    username = _decode_ntlm_field(msg3, usr_len, usr_off)
                    challenge = (
                        ntlm_challenges.get((pkt.src_ip, pkt.dst_ip, pkt.src_port))
                        or ntlm_challenges_by_pair.get((pkt.src_ip, pkt.dst_ip))
                        or "1122334455667788"
                    )

                    if username and nt_off + nt_len <= len(msg3):
                        nt_resp = msg3[nt_off : nt_off + nt_len]
                        if nt_len > 24:
                            nt_proof = nt_resp[:16].hex()
                            blob = nt_resp[16:].hex()
                            hash_str = f"{username}::{domain}:{challenge}:{nt_proof}:{blob}"
                            dedup = f"v2:{username}:{domain}:{nt_proof}"
                            if dedup not in seen_hashes:
                                seen_hashes.add(dedup)
                                results.append(
                                    ExtractedHash(
                                        hash_type="NetNTLMv2",
                                        hashcat_mode=5600,
                                        username=username,
                                        domain=domain,
                                        source_ip=pkt.src_ip,
                                        target_ip=pkt.dst_ip,
                                        hash_string=hash_str,
                                        timestamp=pkt.timestamp,
                                    )
                                )
                        elif nt_len == 24 and lm_off + lm_len <= len(msg3):
                            lm_resp = msg3[lm_off : lm_off + lm_len].hex() if lm_len == 24 else ("00" * 24)
                            nt_hex = nt_resp.hex()
                            hash_str = f"{username}::{domain}:{lm_resp}:{nt_hex}:{challenge}"
                            dedup = f"v1:{username}:{domain}:{nt_hex}"
                            if dedup not in seen_hashes:
                                seen_hashes.add(dedup)
                                results.append(
                                    ExtractedHash(
                                        hash_type="NetNTLMv1",
                                        hashcat_mode=5500,
                                        username=username,
                                        domain=domain,
                                        source_ip=pkt.src_ip,
                                        target_ip=pkt.dst_ip,
                                        hash_string=hash_str,
                                        timestamp=pkt.timestamp,
                                    )
                                )
                except struct.error:
                    pass

        # ------------------------------------------------------------------
        # 3. Kerberos AS-REP (18200) & TGS-REP (13100 / 19600 / 19700)
        # ------------------------------------------------------------------
        if pkt.src_port == 88:
            body = (
                payload[4:]
                if pkt.protocol == "TCP" and len(payload) > 16 and payload[4] in (0x6B, 0x6D)
                else payload
            )
            is_as_rep = body[:1] == b"\x6b" or b"\xa1\x03\x02\x01\x0b" in payload
            is_tgs_rep = body[:1] == b"\x6d" or b"\xa1\x03\x02\x01\x0d" in payload

            if is_as_rep or is_tgs_rep:
                for etype_seq, etype_num, hc_tgs_mode in (
                    (b"\xa0\x03\x02\x01\x17", 23, 13100),  # RC4-HMAC
                    (b"\xa0\x03\x02\x01\x11", 17, 19600),  # AES-128-CTS-HMAC-SHA1
                    (b"\xa0\x03\x02\x01\x12", 18, 19700),  # AES-256-CTS-HMAC-SHA1
                ):
                    et_pos = payload.find(etype_seq)
                    if et_pos < 0:
                        continue
                    octets = _extract_der_octet_strings(payload[et_pos:], min_len=32)
                    gstrings = _extract_asn1_general_strings(payload)
                    if not octets:
                        continue

                    cipher_bytes = max(octets, key=len)
                    realm = next((s for s in gstrings if "." in s or s.isupper()), "CORP.LOCAL")
                    non_realm = [s for s in gstrings if s != realm and s.lower() != "krbtgt"]
                    user = non_realm[0] if non_realm else "user"

                    if etype_num == 23:
                        checksum = cipher_bytes[:16].hex()
                        enc_data = cipher_bytes[16:].hex()
                        if is_as_rep:
                            hash_str = f"$krb5asrep$23${user}@{realm}:{checksum}${enc_data}"
                            dedup = f"asrep:23:{user}:{realm}:{checksum}"
                            if dedup not in seen_hashes:
                                seen_hashes.add(dedup)
                                results.append(
                                    ExtractedHash(
                                        hash_type="Kerberos 5 AS-REP (etype 23)",
                                        hashcat_mode=18200,
                                        username=user,
                                        domain=realm,
                                        source_ip=pkt.dst_ip,
                                        target_ip=pkt.src_ip,
                                        hash_string=hash_str,
                                        timestamp=pkt.timestamp,
                                    )
                                )
                        else:
                            spn_parts = [s for s in non_realm if s != user]
                            spn = "/".join(spn_parts[:2]) if spn_parts else f"cifs/{realm}"
                            hash_str = f"$krb5tgs$23$*{user}${realm}${spn}*${checksum}${enc_data}"
                            dedup = f"tgsrep:23:{user}:{realm}:{checksum}"
                            if dedup not in seen_hashes:
                                seen_hashes.add(dedup)
                                results.append(
                                    ExtractedHash(
                                        hash_type="Kerberos 5 TGS-REP (etype 23)",
                                        hashcat_mode=13100,
                                        username=user,
                                        domain=realm,
                                        source_ip=pkt.dst_ip,
                                        target_ip=pkt.src_ip,
                                        hash_string=hash_str,
                                        timestamp=pkt.timestamp,
                                    )
                                )
                    elif is_tgs_rep and len(cipher_bytes) > 24:
                        # AES-128 / AES-256 places 12-byte HMAC checksum at the end of cipher_bytes
                        checksum = cipher_bytes[-12:].hex()
                        enc_data = cipher_bytes[:-12].hex()
                        spn_parts = [s for s in non_realm if s != user]
                        spn = "/".join(spn_parts[:2]) if spn_parts else f"cifs/{realm}"
                        hash_str = f"$krb5tgs${etype_num}${user}${realm}$*{spn}*${checksum}${enc_data}"
                        dedup = f"tgsrep:{etype_num}:{user}:{realm}:{checksum}"
                        if dedup not in seen_hashes:
                            seen_hashes.add(dedup)
                            results.append(
                                ExtractedHash(
                                    hash_type=f"Kerberos 5 TGS-REP (etype {etype_num})",
                                    hashcat_mode=hc_tgs_mode,
                                    username=user,
                                    domain=realm,
                                    source_ip=pkt.dst_ip,
                                    target_ip=pkt.src_ip,
                                    hash_string=hash_str,
                                    timestamp=pkt.timestamp,
                                )
                            )

        # ------------------------------------------------------------------
        # 4. HTTP / SIP Digest Authentication (Hashcat -m 11400)
        # ------------------------------------------------------------------
        if b"Digest " in payload and b"Authorization:" in payload:
            text = payload.decode("utf-8", errors="ignore")
            dm = DIGEST_AUTH_RE.search(text)
            if dm:
                kvs: dict[str, str] = {}
                for m_kv in DIGEST_KV_RE.finditer(dm.group(1)):
                    key = m_kv.group(1).lower()
                    val = m_kv.group(2) if m_kv.group(2) is not None else m_kv.group(3)
                    kvs[key] = val

                username = kvs.get("username", "")
                realm = kvs.get("realm", "")
                nonce = kvs.get("nonce", "")
                uri = kvs.get("uri", "/")
                response = kvs.get("response", "")
                if username and nonce and len(response) == 32:
                    req_m = REQ_METHOD_RE.search(text)
                    method = req_m.group(1).upper() if req_m else "GET"
                    cnonce = kvs.get("cnonce", "")
                    nc = kvs.get("nc", "")
                    qop = kvs.get("qop", "")
                    alg = kvs.get("algorithm", "MD5").upper()
                    scheme = "sip" if (pkt.dst_port == 5060 or uri.startswith("sip:")) else "http"
                    hash_str = (
                        f"$sip$*{pkt.dst_ip}*{pkt.dst_port}*{username}*{realm}*{method}"
                        f"*{scheme}*{uri}*{nonce}*{cnonce}*{nc}*{qop}*{alg}*{response}"
                    )
                    dedup = f"digest:{username}:{realm}:{response}"
                    if dedup not in seen_hashes:
                        seen_hashes.add(dedup)
                        results.append(
                            ExtractedHash(
                                hash_type="HTTP/SIP Digest",
                                hashcat_mode=11400,
                                username=username,
                                domain=realm,
                                source_ip=pkt.src_ip,
                                target_ip=pkt.dst_ip,
                                hash_string=hash_str,
                                timestamp=pkt.timestamp,
                            )
                        )

        # ------------------------------------------------------------------
        # 5. PostgreSQL Challenge-Response MD5 (Hashcat -m 11100, port 5432)
        # ------------------------------------------------------------------
        if pkt.dst_port == 5432 or pkt.src_port == 5432:
            # StartupMessage from client containing user\x00<username>\x00
            if pkt.dst_port == 5432 and b"\x00\x03\x00\x00" in payload[:12] and b"user\x00" in payload:
                u_pos = payload.find(b"user\x00") + 5
                u_end = payload.find(b"\x00", u_pos)
                if u_end > u_pos:
                    pg_users[(pkt.src_ip, pkt.dst_ip)] = payload[u_pos:u_end].decode("utf-8", errors="ignore")
            # Server AuthenticationMD5Password: 'R' + int32(12) + int32(5) + 4-byte salt
            elif pkt.src_port == 5432 and len(payload) >= 13 and payload[:9] == b"R\x00\x00\x00\x0c\x00\x00\x00\x05":
                pg_salts[(pkt.dst_ip, pkt.src_ip)] = payload[9:13].hex()
            # Client PasswordMessage: 'p' + int32(40) + "md5" + 32-hex-chars + \x00
            elif pkt.dst_port == 5432 and len(payload) >= 40 and payload[0:1] == b"p" and payload[5:8] == b"md5":
                md5_hex = payload[8:40].decode("ascii", errors="ignore")
                if len(md5_hex) == 32 and all(c in "0123456789abcdefABCDEF" for c in md5_hex):
                    pg_user = pg_users.get((pkt.src_ip, pkt.dst_ip), "postgres")
                    pg_salt = pg_salts.get((pkt.src_ip, pkt.dst_ip), "01020304")
                    hash_str = f"$postgres$*{pg_user}*{pg_salt}*{md5_hex.lower()}"
                    dedup = f"pg:{pg_user}:{md5_hex.lower()}"
                    if dedup not in seen_hashes:
                        seen_hashes.add(dedup)
                        results.append(
                            ExtractedHash(
                                hash_type="PostgreSQL MD5",
                                hashcat_mode=11100,
                                username=pg_user,
                                domain="postgres",
                                source_ip=pkt.src_ip,
                                target_ip=pkt.dst_ip,
                                hash_string=hash_str,
                                timestamp=pkt.timestamp,
                            )
                        )

        # ------------------------------------------------------------------
        # 6. MySQL Challenge-Response SHA1 (Hashcat -m 11200, port 3306)
        # ------------------------------------------------------------------
        if pkt.src_port == 3306 and len(payload) >= 52 and payload[3] == 0x00 and payload[4] == 0x0A:
            # Server Greeting v10: null-terminated version starts at byte 5
            ver_end = payload.find(b"\x00", 5)
            if ver_end > 5 and ver_end + 44 <= len(payload):
                part1 = payload[ver_end + 5 : ver_end + 13]
                part2 = payload[ver_end + 32 : ver_end + 44]
                if len(part1) == 8 and len(part2) == 12:
                    mysql_salts[(pkt.dst_ip, pkt.src_ip)] = (part1 + part2).hex()
        elif pkt.dst_port == 3306 and len(payload) >= 58 and payload[3] == 0x01:
            # Client Handshake Response: username starts at byte 36
            u_end = payload.find(b"\x00", 36)
            if 36 < u_end < len(payload) - 21 and payload[u_end + 1] == 20:
                my_user = payload[36:u_end].decode("utf-8", errors="ignore")
                resp_hex = payload[u_end + 2 : u_end + 22].hex()
                salt_hex = mysql_salts.get((pkt.src_ip, pkt.dst_ip), "1122334455667788990011223344556677889900")
                if my_user and len(resp_hex) == 40:
                    hash_str = f"$mysqlna$*{salt_hex}*{resp_hex}"
                    dedup = f"mysql:{my_user}:{resp_hex}"
                    if dedup not in seen_hashes:
                        seen_hashes.add(dedup)
                        results.append(
                            ExtractedHash(
                                hash_type="MySQL SHA1 CR",
                                hashcat_mode=11200,
                                username=my_user,
                                domain="mysql",
                                source_ip=pkt.src_ip,
                                target_ip=pkt.dst_ip,
                                hash_string=hash_str,
                                timestamp=pkt.timestamp,
                            )
                        )

    return results
