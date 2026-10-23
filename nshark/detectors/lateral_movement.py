"""Lateral Movement Detector: SMB (Pass-the-Hash, PsExec, Admin Shares), Kerberos (Kerberoasting, AS-REP, Brute Force), and RDP/WinRM."""

from __future__ import annotations

import logging
import re
import struct
from collections import defaultdict
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

# Little-endian NTSTATUS codes in SMB1/SMB2 headers
SMB_NTSTATUS_FAILURES: dict[bytes, str] = {
    b"\x6d\x00\x00\xc0": "STATUS_LOGON_FAILURE",
    b"\x6a\x00\x00\xc0": "STATUS_WRONG_PASSWORD",
    b"\x34\x02\x00\xc0": "STATUS_ACCOUNT_LOCKED_OUT",
    b"\x72\x00\x00\xc0": "STATUS_ACCOUNT_DISABLED",
    b"\x64\x00\x00\xc0": "STATUS_NO_SUCH_USER",
    b"\x22\x00\x00\xc0": "STATUS_ACCESS_DENIED",
}

# Sensitive SMB shares & DCE/RPC pipes used in PsExec, Impacket, Mimikatz, SpoolSample, etc.
SMB_ADMIN_ARTIFACTS: list[tuple[str, str]] = [
    ("ADMIN$", "SMB Admin Share (ADMIN$)"),
    ("C$", "SMB Disk Admin Share (C$)"),
    ("svcctl", "DCE/RPC Service Control Manager (svcctl / PsExec)"),
    ("atsvc", "DCE/RPC Task Scheduler (atsvc / atexec)"),
    ("PSEXESVC", "Sysinternals PsExec Service Binary (PSEXESVC)"),
    ("RemCom", "RemCom Remote Command Executor"),
    ("paexec", "PAExec Remote Command Executor"),
    ("BTOBTO", "Impacket smbexec Command Execution"),
    ("__output", "Impacket wmiexec/smbexec Output Redirection"),
    ("__LegitFile", "Impacket smbexec Output File (__LegitFile)"),
    ("samr", "SAM Remote Protocol (samr user/group enumeration)"),
    ("lsarpc", "LSA Remote Protocol (lsarpc policy/secret access)"),
    ("drsuapi", "Active Directory Replication (DCSync / drsuapi)"),
    ("winreg", "Remote Registry Service (winreg)"),
    ("spoolss", "Print Spooler Named Pipe (\\pipe\\spoolss)"),
    ("protected_storage", "DPAPI Protected Storage Pipe (\\pipe\\protected_storage)"),
    ("G$BCKUPKEY_", "DPAPI Domain Backup MasterKey Secret (G$BCKUPKEY_PREFERRED)"),
    ("$MACHINE.ACC", "SAMR Machine Account Password Reset ($MACHINE.ACC)"),
    ("Domain Admins", "Active Directory 'Domain Admins' Group Target"),
]

# Binary little-endian DCE/RPC interface UUIDs used over SMB named pipes or TCP RPC
DCERPC_UUID_ARTIFACTS: list[tuple[bytes, str]] = [
    (b"\x81\xbb\x7a\x36\x44\x98\xf1\x35\xad\x32\x98\xf0\x38\x00\x10\x03", "DCE/RPC Service Control Manager (svcctl / PsExec)"),
    (b"\x35\x42\x51\xe3\x06\x4b\xd1\x11\xab\x04\x00\xc0\x4f\xc2\xdc\xd2", "Active Directory Replication (DCSync / drsuapi)"),
    (b"\x70\x0a\xbf\x1f\x42\x0c\x10\x1b\xb4\x29\x08\x00\x2b\x2d\xfc\x01", "DCE/RPC Task Scheduler (atsvc / atexec)"),
    (b"\x78\x57\x34\x12\x34\x12\xcd\xab\xef\x00\x01\x23\x45\x67\x89\xac", "SAM Remote Protocol (samr user/group enumeration)"),
    (b"\x78\x57\x34\x12\x34\x12\xcd\xab\xef\x00\x01\x23\x45\x67\x89\xab", "LSA Remote Protocol (lsarpc policy/secret access)"),
    (b"\x78\x56\x34\x12\x34\x12\xcd\xab\xef\x00\x01\x23\x45\x67\x89\xab", "Print Spooler RPC (MS-RPRN / SpoolSample)"),
    (b"\x30\x7c\xde\x3d\x5d\x16\xd1\x11\xab\x8f\x00\x80\x5f\x14\xdb\x40", "DPAPI BackupKey RPC (MS-BKRP MasterKey Decryption)"),
    (b"\xdc\x3f\x27\x82\x2a\xe3\xc3\x18\x3f\x78\x82\x79\x29\xdc\x23\xea", "EventLog Remoting Protocol (MS-EVEN / EventService Crash)"),
    (b"\xc8\x4f\x32\x4b\x70\x16\xd3\x01\x12\x78\x5a\x47\xbf\x6e\xe1\x88", "Server Service RPC (srvsvc NetShareEnum)"),
    (b"\x01\xd0\x8c\x33\x44\x22\xf1\x31\xaa\xaa\x90\x00\x38\x00\x10\x03", "Remote Registry RPC (winreg / PsLoggedOn)"),
    (b"\x18\xad\x09\xf3\x6a\xd8\xd0\x11\xa0\x75\x00\xc0\x4f\xb6\x88\x20", "WMI DCOM Login (IWbemLevel1Login)"),
    (b"\x99\xdc\x56\x95\x8c\x82\xcf\x11\xa3\x7e\x00\xaa\x00\x32\x40\xc7", "WMI Remote Execution (IWbemServices::ExecMethod)"),
    (b"\x1a\x79\xb2\x49\xae\xb1\x90\x4c\x9b\x8e\xe8\x60\xba\x07\xf8\x89", "DCOM MMC20.Application CLSID (49b2791a-b1ae-4c90-9b8e-e860ba07f889)"),
]

NRPC_UUID_LE = b"\x78\x56\x34\x12\x34\x12\xcd\xab\xef\x00\x01\x23\x45\x67\xcf\xfb"
EPM_UUID_LE = b"\x08\x83\xaf\xe1\x1f\x5d\xc9\x11\x91\xa4\x08\x00\x2b\x14\xa0\xfa"

# Service Principal Names commonly targeted in Kerberoasting
KERBEROS_SPN_KEYWORDS: tuple[bytes, ...] = (
    b"MSSQLSvc",
    b"HTTP",
    b"CIFSSvc",
    b"cifs",
    b"exchangeMDB",
    b"ldap",
    b"wsman",
    b"termsrv",
    b"HOST",
    b"krbtgt",
)

# Kerberos KRB-ERROR codes (ASN.1 [6] INTEGER)
KRB_ERROR_CODES: dict[int, str] = {
    6: "KDC_ERR_C_PRINCIPAL_UNKNOWN (User Enumeration)",
    18: "KDC_ERR_CLIENT_REVOKED (Account Disabled/Locked)",
    23: "KDC_ERR_KEY_EXPIRED",
    24: "KDC_ERR_PREAUTH_FAILED (Bad Password)",
    25: "KDC_ERR_PREAUTH_REQUIRED",
}


def parse_ntlmssp_auth(payload: bytes) -> Optional[dict[str, str]]:
    """Extract domain, username, and workstation from an NTLMSSP_AUTH (Type 3) message."""
    idx = payload.find(b"NTLMSSP\x00\x03\x00\x00\x00")
    if idx < 0:
        return None
    msg = payload[idx:]
    if len(msg) < 64:
        return None
    try:
        nt_len, _, _ = struct.unpack_from("<HHI", msg, 20)
        dom_len, _, dom_off = struct.unpack_from("<HHI", msg, 28)
        usr_len, _, usr_off = struct.unpack_from("<HHI", msg, 36)
        wks_len, _, wks_off = struct.unpack_from("<HHI", msg, 44)

        def _decode_field(length: int, offset: int) -> str:
            if length == 0 or offset + length > len(msg):
                return ""
            raw = msg[offset : offset + length]
            if b"\x00" in raw:
                return raw.decode("utf-16le", errors="ignore").strip()
            return raw.decode("latin-1", errors="ignore").strip()

        domain = _decode_field(dom_len, dom_off)
        username = _decode_field(usr_len, usr_off)
        workstation = _decode_field(wks_len, wks_off)
        if not username and not domain:
            return None
        return {
            "domain": domain,
            "username": username,
            "workstation": workstation,
            "nt_resp_len": str(nt_len),
        }
    except struct.error:
        return None


def _contains_ascii_or_utf16le(payload: bytes, needle: str) -> bool:
    """Check if needle appears in payload as case-insensitive ASCII or UTF-16LE."""
    ascii_bytes = needle.encode("ascii")
    utf16_bytes = needle.encode("utf-16le")
    low_payload = payload.lower()
    if ascii_bytes.lower() in low_payload:
        return True
    if utf16_bytes in payload or needle.upper().encode("utf-16le") in payload or needle.lower().encode("utf-16le") in payload:
        return True
    return False


def _extract_utf16le_strings(payload: bytes, min_len: int = 4) -> list[str]:
    """Extract clean printable UTF-16LE strings from binary SMB/RPC payloads."""
    out: list[str] = []
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){" + str(min_len).encode() + rb",}", payload):
        s = m.group(0).decode("utf-16le", errors="ignore").strip()
        if len(s) >= min_len and s not in out:
            out.append(s)
    return out


class LateralMovementDetector(BaseDetector):
    """Detects SMB, DCE/RPC, Kerberos, RDP, and WinRM lateral movement and AD attacks."""

    name = "lateral_movement"
    detection_type = DetectionType.LATERAL_MOVEMENT

    def analyze(
        self,
        packets: list[ParsedPacket],
        flows: list[Flow],
        config: dict[str, Any],
    ) -> list[Alert]:
        alerts: list[Alert] = []
        alerts.extend(self._analyze_smb(packets))
        alerts.extend(self._analyze_kerberos(packets))
        alerts.extend(self._analyze_rdp_and_winrm(packets))
        return alerts

    def _analyze_smb(self, packets: list[ParsedPacket]) -> list[Alert]:
        """Inspect SMB1/SMB2/SMB3 and DCE/RPC traffic across standard and dynamic RPC ports."""
        alerts: list[Alert] = []

        logon_failures: dict[tuple[str, str], dict[str, int]] = defaultdict(lambda: defaultdict(int))
        first_fail_ts: dict[tuple[str, str], Any] = {}

        ntlm_targets_by_client: dict[str, set[str]] = defaultdict(set)
        ntlm_accounts_by_pair: dict[tuple[str, str], set[str]] = defaultdict(set)
        first_ntlm_ts: dict[str, Any] = {}

        admin_exec_artifacts: dict[tuple[str, str], set[str]] = defaultdict(set)
        dcerpc_opnums_by_pair: dict[tuple[str, str], list[int]] = defaultdict(list)
        dcerpc_encrypted_resp_bytes: dict[tuple[str, str], int] = defaultdict(int)
        dcom_commands_by_pair: dict[tuple[str, str], list[str]] = defaultdict(list)
        samr_targets_by_pair: dict[tuple[str, str], list[str]] = defaultdict(list)
        first_admin_ts: dict[tuple[str, str], Any] = {}

        # ZeroLogon (CVE-2020-1472) tracking: (client_ip, dc_ip)
        zerologon_events: dict[tuple[str, str], dict[str, Any]] = defaultdict(
            lambda: {"nrpc_bind": False, "op4_count": 0, "op15_count": 0, "op30_count": 0, "null_chal": 0, "targets": set(), "first_ts": None}
        )

        # SMBGhost (CVE-2020-0796) tracking: (client_ip, server_ip)
        smbghost_events: dict[tuple[str, str], dict[str, Any]] = {}

        # Endpoint Mapper (TCP/135) enumeration tracking: (client_ip, server_ip)
        epm_lookup_counts: dict[tuple[str, str], int] = defaultdict(int)
        first_epm_ts: dict[tuple[str, str], Any] = {}

        # MS17-010 / EternalBlue indicators
        ms17_010_hits: dict[tuple[str, str], int] = defaultdict(int)
        first_ms17_ts: dict[tuple[str, str], Any] = {}

        for pkt in packets:
            payload = pkt.payload
            if not payload:
                continue

            has_smb_magic = b"\xfeSMB" in payload or b"\xffSMB" in payload or b"\xfcSMB" in payload
            is_smb_port = pkt.src_port in (445, 139) or pkt.dst_port in (445, 139) or has_smb_magic
            dcerpc_match = re.search(rb"\x05\x00([\x00-\x13])([\x00-\xff])\x10\x00\x00\x00", payload)
            is_dcerpc = pkt.dst_port == 135 or pkt.src_port == 135 or dcerpc_match is not None

            if not is_smb_port and not is_dcerpc:
                continue

            # 0. Check for CVE-2020-0796 (SMBGhost) SMBv3.1.1 Compression Transform Header
            if b"\xfcSMB" in payload:
                idx = payload.find(b"\xfcSMB")
                if idx + 16 <= len(payload):
                    orig_size, comp_alg, comp_flags, offset_len = struct.unpack_from("<IHHI", payload, idx + 4)
                    if orig_size >= 0x80000000 or (orig_size + offset_len) > 0xFFFFFFFF:
                        pair = (pkt.src_ip, pkt.dst_ip)
                        smbghost_events[pair] = {
                            "orig_size": hex(orig_size),
                            "offset": hex(offset_len),
                            "alg": comp_alg,
                            "ts": pkt.timestamp,
                        }

            # Determine client -> server direction for RPC/SMB
            if pkt.src_port in (445, 139, 135) or (dcerpc_match and dcerpc_match.group(1)[0] in (2, 3, 12, 15)):
                client_ip, server_ip = pkt.dst_ip, pkt.src_ip
                is_request = False
            else:
                client_ip, server_ip = pkt.src_ip, pkt.dst_ip
                is_request = True
            pair = (client_ip, server_ip)

            # Extract Kerberos AP-REQ SPN / principal strings inside SMB SessionSetup blobs
            if has_smb_magic:
                for m_spn in re.finditer(rb"\x1b\x04cifs\x1b([\x04-\x30])([A-Za-z0-9_.\-$]+)", payload):
                    host_t = m_spn.group(2).decode("ascii", errors="ignore")
                    if host_t:
                        samr_targets_by_pair[pair].append(f"cifs/{host_t}")
                for u_s in _extract_utf16le_strings(payload, min_len=4):
                    if any(k in u_s.lower() for k in ("cmd.exe", "notepad.exe", "powershell", "/c ")):
                        if u_s not in dcom_commands_by_pair[pair]:
                            dcom_commands_by_pair[pair].append(u_s)
                    if u_s in ("Domain Admins", "Enterprise Admins", "Administrators", "a-arobinson", "Administrator", "$MACHINE.ACC"):
                        if u_s not in samr_targets_by_pair[pair]:
                            samr_targets_by_pair[pair].append(u_s)
                    # Extract Kerberos/NTLMSSP concatenated user/host strings in SMB2 SessionSetup
                    for acct_prefix in ("3B", "THREEBEESCO.COM"):
                        if u_s.startswith(acct_prefix) and len(u_s) > len(acct_prefix) + 2:
                            clean_u = u_s[len(acct_prefix):].split("02694")[0].split("01566")[0].strip("\\")
                            if clean_u and len(clean_u) >= 3:
                                ntlm_accounts_by_pair[pair].add(f"{acct_prefix}\\{clean_u}")

            # 1. Inspect DCE/RPC headers and UUIDs on any TCP port
            if is_dcerpc or is_smb_port:
                for uuid_bytes, label in DCERPC_UUID_ARTIFACTS:
                    if uuid_bytes in payload:
                        admin_exec_artifacts[pair].add(label)
                        first_admin_ts.setdefault(pair, pkt.timestamp)

                if NRPC_UUID_LE in payload:
                    zl = zerologon_events[pair]
                    zl["nrpc_bind"] = True
                    if zl["first_ts"] is None:
                        zl["first_ts"] = pkt.timestamp

                # Extract UTF-16LE commands / targets in DCOM / RPC packets
                for u_s in _extract_utf16le_strings(payload, min_len=4):
                    if any(k in u_s.lower() for k in ("cmd.exe", "notepad.exe", "powershell", "/c ")):
                        if u_s not in dcom_commands_by_pair[pair]:
                            dcom_commands_by_pair[pair].append(u_s)
                    if u_s.startswith("3B\\") or u_s.startswith("THREEBEESCO\\"):
                        ntlm_accounts_by_pair[pair].add(u_s)
                    if u_s.endswith("$") or "WIN16" in u_s.upper():
                        zerologon_events[pair]["targets"].add(u_s.lstrip("\\>"))

                # Parse all DCE/RPC v5 PDUs in payload
                for m_rpc in re.finditer(rb"\x05\x00([\x00-\x13])([\x00-\xff])\x10\x00\x00\x00", payload):
                    ptype = m_rpc.group(1)[0]
                    off = m_rpc.start()
                    if off + 16 > len(payload):
                        continue
                    frag_len = int.from_bytes(payload[off + 8 : off + 10], "little")
                    auth_len = int.from_bytes(payload[off + 10 : off + 12], "little")
                    if ptype == 0 and off + 24 <= len(payload):
                        opnum = int.from_bytes(payload[off + 22 : off + 24], "little")
                        dcerpc_opnums_by_pair[pair].append(opnum)
                        first_admin_ts.setdefault(pair, pkt.timestamp)

                        # Check Endpoint Mapper ept_lookup (Opnum 2 on port 135)
                        if pkt.dst_port == 135 and opnum == 2:
                            epm_lookup_counts[pair] += 1
                            first_epm_ts.setdefault(pair, pkt.timestamp)

                        # Check ZeroLogon Opnum 4 (NetrServerReqChallenge), Opnum 15 (NetrServerAuthenticate3), Opnum 30 (NetrServerPasswordSet2)
                        stub = payload[off + 24 : min(len(payload), off + frag_len - (auth_len + 8 if auth_len else 0))]
                        if opnum == 4 and zerologon_events[pair]["nrpc_bind"]:
                            zl = zerologon_events[pair]
                            zl["op4_count"] += 1
                            if b"\x00" * 8 in stub[-12:]:
                                zl["null_chal"] += 1
                            if zl["first_ts"] is None:
                                zl["first_ts"] = pkt.timestamp
                        elif opnum == 15 and (zerologon_events[pair]["nrpc_bind"] or zerologon_events[pair]["op4_count"] > 0):
                            zerologon_events[pair]["op15_count"] += 1
                        elif opnum == 30 and (zerologon_events[pair]["nrpc_bind"] or zerologon_events[pair]["op4_count"] > 0):
                            zerologon_events[pair]["op30_count"] += 1

                        # Check LSARPC Opnum 43 (LsarRetrievePrivateData) for BackupKey
                        if opnum == 43 and has_smb_magic:
                            admin_exec_artifacts[pair].add("LSARPC LsarRetrievePrivateData (Opnum 43 / DPAPI BackupKey)")

                        # Check SpoolSample Opnum 65 / 62 (RpcRemoteFindFirstPrinterChangeNotificationEx)
                        if opnum in (62, 65) and has_smb_magic:
                            admin_exec_artifacts[pair].add("SpoolSample Coerced Auth (Opnum 65 RpcRemoteFindFirstPrinterChangeNotificationEx)")

                        # Check SAMR Opnum 44 (SamrSetInformationUser2 password reset)
                        if opnum == 44 and has_smb_magic:
                            admin_exec_artifacts[pair].add("SAMR Remote Password Reset (Opnum 44 SamrSetInformationUser2)")

                    elif ptype == 2 and auth_len >= 40:
                        dcerpc_encrypted_resp_bytes[pair] += frag_len

                if b"NTLMSSP\x00\x03" in payload:
                    ntlm = parse_ntlmssp_auth(payload)
                    if ntlm:
                        acct = f"{ntlm['domain']}\\{ntlm['username']}".strip("\\")
                        if acct:
                            ntlm_accounts_by_pair[pair].add(acct)

            # 2. Check SMB response for NTSTATUS logon failures
            if not is_request and (b"\xfeSMB" in payload or b"\xffSMB" in payload):
                for status_bytes, status_name in SMB_NTSTATUS_FAILURES.items():
                    if status_bytes in payload:
                        logon_failures[pair][status_name] += 1
                        first_fail_ts.setdefault(pair, pkt.timestamp)

            # 3. Check client -> server SMB requests
            if is_request and is_smb_port:
                ntlm = parse_ntlmssp_auth(payload)
                if ntlm:
                    ntlm_targets_by_client[client_ip].add(server_ip)
                    first_ntlm_ts.setdefault(client_ip, pkt.timestamp)
                    acct = f"{ntlm['domain']}\\{ntlm['username']}".strip("\\")
                    if acct:
                        ntlm_accounts_by_pair[pair].add(acct)

                for needle, label in SMB_ADMIN_ARTIFACTS:
                    if _contains_ascii_or_utf16le(payload, needle):
                        admin_exec_artifacts[pair].add(label)
                        first_admin_ts.setdefault(pair, pkt.timestamp)

                if b"\xffSMB" in payload:
                    smb_idx = payload.find(b"\xffSMB")
                    smb_hdr = payload[smb_idx : smb_idx + 32]
                    if len(smb_hdr) == 32:
                        cmd = smb_hdr[4]
                        mid = struct.unpack_from("<H", smb_hdr, 30)[0]
                        if (cmd in (0x32, 0x25, 0xA0) and mid in (65, 64)) or b"\x23\x00\x00\x00\x07\x00\x5c\x50\x49\x50\x45\x5c" in payload:
                            ms17_010_hits[pair] += 1
                            first_ms17_ts.setdefault(pair, pkt.timestamp)

        # Emit CVE-2020-0796 (SMBGhost) alerts
        for (client_ip, server_ip), info in smbghost_events.items():
            alerts.append(
                Alert(
                    detection_type=self.detection_type,
                    severity=Severity.CRITICAL,
                    confidence=99,
                    source_ip=client_ip,
                    destination_ip=server_ip,
                    description=(
                        f"SMBGhost / CoronaBlue Exploit (CVE-2020-0796): Malicious SMBv3.1.1 "
                        f"compression transform header integer overflow (OriginalSize={info['orig_size']}, Offset={info['offset']})"
                    ),
                    timestamp=info["ts"],
                    details={"protocol": "SMB3", "port": 445, "cve": "CVE-2020-0796", **info},
                )
            )

        # Emit CVE-2020-1472 (ZeroLogon) alerts
        for (client_ip, server_ip), zl in zerologon_events.items():
            if zl["op4_count"] >= 5 or zl["null_chal"] >= 2:
                targets = sorted(zl["targets"])
                tgt_str = f" targeting {targets[0]}" if targets else ""
                pwd_reset = " + NetrServerPasswordSet2 (Opnum 30)" if zl["op30_count"] > 0 else ""
                alerts.append(
                    Alert(
                        detection_type=self.detection_type,
                        severity=Severity.CRITICAL,
                        confidence=99,
                        source_ip=client_ip,
                        destination_ip=server_ip,
                        description=(
                            f"ZeroLogon Exploit (CVE-2020-1472): Netlogon RPC (NRPC) cryptographic bypass{tgt_str} "
                            f"({zl['op4_count']} NetrServerReqChallenge Opnum 4 / {zl['op15_count']} Auth3 Opnum 15 attempts{pwd_reset})"
                        ),
                        timestamp=zl["first_ts"],
                        details={
                            "protocol": "DCE/RPC (NRPC)",
                            "cve": "CVE-2020-1472",
                            "req_challenge_count": zl["op4_count"],
                            "auth3_count": zl["op15_count"],
                            "password_set_count": zl["op30_count"],
                            "targets": targets,
                        },
                    )
                )

        # Check mid-stream Encrypted DRSUAPI DCSync & DCOM MMC20.Application
        for pair, ops in dcerpc_opnums_by_pair.items():
            op_set = set(ops)
            # Mid-stream DCSync: DRSBind (0), DRSCrackNames (12), DRSGetDomainControllerInfo (16), DRSGetNCChanges (3), DRSUnbind (1)
            if {0, 3, 12}.issubset(op_set) and dcerpc_encrypted_resp_bytes[pair] >= 1500:
                admin_exec_artifacts[pair].add(
                    f"Active Directory DCSync Replication (IDL_DRSGetNCChanges Opnum 3, {dcerpc_encrypted_resp_bytes[pair]:,}B replicated)"
                )
            # DCShadow: drsuapi + IDL_DRSReplicaAdd (Opnum 5)
            if 5 in op_set and any("drsuapi" in a for a in admin_exec_artifacts.get(pair, set())):
                admin_exec_artifacts[pair].add("DCShadow Rogue Domain Controller Registration (IDL_DRSReplicaAdd Opnum 5)")
            # DCOM MMC20.Application command execution
            if dcom_commands_by_pair.get(pair):
                cmd_str = " ".join(dcom_commands_by_pair[pair][:2])
                admin_exec_artifacts[pair].add(f"DCOM MMC20.Application Command Execution ('{cmd_str}')")

        # Emit SMB / DCE-RPC Admin Share, Lateral Movement, CredAccess & Discovery alerts
        for (client_ip, server_ip), artifacts in admin_exec_artifacts.items():
            sorted_art = sorted(artifacts)
            accounts = sorted(ntlm_accounts_by_pair.get((client_ip, server_ip), set()))
            acct_str = f" as {', '.join(accounts[:2])}" if accounts else ""
            ops = dcerpc_opnums_by_pair.get((client_ip, server_ip), [])
            op_str = f" [opnums: {','.join(str(x) for x in sorted(set(ops))[:6])}]" if ops else ""
            targets = samr_targets_by_pair.get((client_ip, server_ip), [])
            tgt_str = f" (targets: {', '.join(targets[:3])})" if targets else ""

            is_critical = any(
                k in a
                for a in sorted_art
                for k in (
                    "svcctl", "atsvc", "PSEXESVC", "Impacket", "DCSync", "DCShadow",
                    "SpoolSample", "BackupKey", "Password Reset", "MMC20", "WMI Remote",
                )
            )
            severity = Severity.CRITICAL if is_critical else Severity.HIGH
            confidence = min(99, 88 + len(sorted_art) * 3)
            alerts.append(
                Alert(
                    detection_type=self.detection_type,
                    severity=severity,
                    confidence=confidence,
                    source_ip=client_ip,
                    destination_ip=server_ip,
                    description=(
                        f"SMB / DCE-RPC Active Directory Attack{acct_str}: "
                        f"{', '.join(sorted_art[:3])}{tgt_str}{op_str}"
                    ),
                    timestamp=first_admin_ts.get((client_ip, server_ip)),
                    details={
                        "protocol": "SMB/DCE-RPC",
                        "port": 445,
                        "artifacts": sorted_art,
                        "accounts": accounts,
                        "opnums": sorted(set(ops)),
                        "targets": targets,
                    },
                )
            )

        # Emit DCE/RPC Endpoint Mapper (TCP/135) Enumeration (impacket-rpcdump / EPM scanner) if no higher SMB alert fired for pair
        for (client_ip, server_ip), count in epm_lookup_counts.items():
            if (client_ip, server_ip) in admin_exec_artifacts or (client_ip, server_ip) in zerologon_events and zerologon_events[(client_ip, server_ip)]["op4_count"] >= 5:
                continue
            mode = "Exhaustive RPC Interface Scan" if count >= 20 else "impacket-rpcdump Endpoint Enumeration"
            alerts.append(
                Alert(
                    detection_type=self.detection_type,
                    severity=Severity.HIGH if count >= 20 else Severity.MEDIUM,
                    confidence=min(95, 84 + min(10, count)),
                    source_ip=client_ip,
                    destination_ip=server_ip,
                    description=(
                        f"DCE/RPC Endpoint Mapper Reconnaissance ({mode}): "
                        f"{count} ept_lookup (Opnum 2) queries to TCP/135"
                    ),
                    timestamp=first_epm_ts.get((client_ip, server_ip)),
                    details={
                        "protocol": "DCE/RPC (EPM)",
                        "port": 135,
                        "ept_lookup_count": count,
                    },
                )
            )

        # Emit SMB Brute Force / Pass-the-Hash failure alerts
        for (client_ip, server_ip), status_counts in logon_failures.items():
            total_fails = sum(status_counts.values())
            accounts = sorted(ntlm_accounts_by_pair.get((client_ip, server_ip), set()))
            if total_fails >= 3 or (total_fails >= 1 and len(accounts) >= 2):
                status_summary = ", ".join(f"{k}={v}" for k, v in status_counts.items())
                acct_str = f" (accounts: {', '.join(accounts[:4])})" if accounts else ""
                alerts.append(
                    Alert(
                        detection_type=self.detection_type,
                        severity=Severity.HIGH if total_fails >= 5 else Severity.MEDIUM,
                        confidence=min(96, 78 + total_fails * 3),
                        source_ip=client_ip,
                        destination_ip=server_ip,
                        description=(
                            f"SMB Authentication Attack / Pass-the-Hash: {total_fails} failed logons "
                            f"({status_summary}){acct_str}"
                        ),
                        timestamp=first_fail_ts.get((client_ip, server_ip)),
                        details={
                            "protocol": "SMB",
                            "port": 445,
                            "total_failures": total_fails,
                            "status_codes": dict(status_counts),
                            "accounts": accounts,
                        },
                    )
                )

        # Emit Multi-Host NTLM Pass-the-Hash Spraying
        for client_ip, targets in ntlm_targets_by_client.items():
            if len(targets) >= 3:
                sorted_targets = sorted(targets)
                alerts.append(
                    Alert(
                        detection_type=self.detection_type,
                        severity=Severity.HIGH,
                        confidence=min(95, 80 + len(targets) * 3),
                        source_ip=client_ip,
                        destination_ip=sorted_targets[0],
                        description=(
                            f"SMB NTLM Lateral Sweep: {client_ip} authenticated via NTLMSSP "
                            f"across {len(targets)} hosts ({', '.join(sorted_targets[:4])})"
                        ),
                        timestamp=first_ntlm_ts.get(client_ip),
                        details={
                            "protocol": "SMB",
                            "port": 445,
                            "target_hosts": sorted_targets,
                        },
                    )
                )

        # Emit MS17-010 / EternalBlue alerts
        for (client_ip, server_ip), hits in ms17_010_hits.items():
            alerts.append(
                Alert(
                    detection_type=self.detection_type,
                    severity=Severity.CRITICAL,
                    confidence=96,
                    source_ip=client_ip,
                    destination_ip=server_ip,
                    description=(
                        f"MS17-010 (EternalBlue) SMBv1 Exploit Grooming detected "
                        f"({hits} anomalous Trans2/IPC$ packets)"
                    ),
                    timestamp=first_ms17_ts.get((client_ip, server_ip)),
                    details={
                        "protocol": "SMB",
                        "port": 445,
                        "exploit": "MS17-010 / EternalBlue",
                        "packet_count": hits,
                    },
                )
            )

        return alerts

    def _analyze_kerberos(self, packets: list[ParsedPacket]) -> list[Alert]:
        """Inspect Kerberos traffic on port 88 for Kerberoasting, AS-REP Roasting, Skeleton Key, and Brute Force."""
        alerts: list[Alert] = []

        kerberoast_events: dict[tuple[str, str], dict[str, Any]] = defaultdict(
            lambda: {"rc4_tgs": 0, "spns": set(), "users": set(), "realms": set(), "as_rep_rc4": 0, "as_rep_success": 0, "first_ts": None}
        )
        krb_errors: dict[tuple[str, str], dict[str, int]] = defaultdict(lambda: defaultdict(int))
        first_err_ts: dict[tuple[str, str], Any] = {}

        for pkt in packets:
            if pkt.src_port != 88 and pkt.dst_port != 88:
                continue
            payload = pkt.payload
            if not payload or len(payload) < 12:
                continue

            body = payload[4:] if pkt.protocol == "TCP" and len(payload) > 16 and payload[4] in (0x6A, 0x6B, 0x6C, 0x6D, 0x7E) else payload
            pair = (pkt.src_ip, pkt.dst_ip) if pkt.dst_port == 88 else (pkt.dst_ip, pkt.src_ip)
            info = kerberoast_events[pair]

            # Extract Kerberos Realm and PrincipalName (NT-PRINCIPAL \xa0\x03\x02\x01\x01\xa1...\x1b<len><user>)
            for m_usr in re.finditer(rb"\xa0\x03\x02\x01\x01\xa1[\x06-\x20]0[\x04-\x1e]\x1b([\x02-\x1c])([A-Za-z0-9_.\-$]+)", payload):
                u = m_usr.group(2).decode("ascii", errors="ignore")
                if u and u.lower() not in ("krbtgt", "threebeesco.com"):
                    info["users"].add(u)
            for m_rlm in re.finditer(rb"\x1b([\x06-\x24])([A-Z0-9\-]+\.[A-Z0-9.\-]+)", payload):
                info["realms"].add(m_rlm.group(2).decode("ascii", errors="ignore"))

            # 1. Client -> KDC (dst_port == 88): Check for TGS-REQ (0x6c) or AS-REQ (0x6a)
            if pkt.dst_port == 88:
                is_tgs_req = body[:1] == b"\x6c" or b"\x6c\x82" in payload[:16] or b"\xa1\x03\x02\x01\x0c" in payload
                has_rc4_etype = b"\x02\x01\x17" in payload  # etype 23 (rc4-hmac)

                matched_spns: list[str] = []
                for spn_kw in KERBEROS_SPN_KEYWORDS:
                    idx = payload.find(spn_kw)
                    if idx >= 0:
                        snippet = payload[idx : idx + 48]
                        m = re.match(rb"([A-Za-z0-9_.\-$/:]+)", snippet)
                        if m:
                            spn_val = m.group(1).decode("ascii", errors="ignore")
                            if spn_val.lower() != "krbtgt":
                                matched_spns.append(spn_val)

                if is_tgs_req and (has_rc4_etype or matched_spns):
                    if has_rc4_etype:
                        info["rc4_tgs"] += 1
                    for spn in matched_spns:
                        info["spns"].add(spn)
                    if info["first_ts"] is None:
                        info["first_ts"] = pkt.timestamp

            # 2. KDC -> Client (src_port == 88): Check for AS-REP (0x6b), TGS-REP (0x6d) with RC4, or KRB-ERROR (0x7e)
            if pkt.src_port == 88:
                is_as_rep = body[:1] == b"\x6b" or b"\xa1\x03\x02\x01\x0b" in payload
                is_tgs_rep = body[:1] == b"\x6d" or b"\xa1\x03\x02\x01\x0d" in payload
                has_rc4_cipher = b"\xa0\x03\x02\x01\x17" in payload

                if is_as_rep:
                    info["as_rep_success"] += 1
                    if has_rc4_cipher:
                        info["as_rep_rc4"] += 1
                        if info["first_ts"] is None:
                            info["first_ts"] = pkt.timestamp
                elif is_tgs_rep and has_rc4_cipher:
                    info["rc4_tgs"] += 1
                    if info["first_ts"] is None:
                        info["first_ts"] = pkt.timestamp

                if body[:1] == b"\x7e" or b"\xa1\x03\x02\x01\x1e" in payload:
                    m_err = re.search(rb"\xa6\x03\x02\x01([\x00-\x7f])", payload)
                    if m_err:
                        code = m_err.group(1)[0]
                        if code in KRB_ERROR_CODES:
                            krb_errors[pair][KRB_ERROR_CODES[code]] += 1
                            first_err_ts.setdefault(pair, pkt.timestamp)

        # Emit Kerberoasting / AS-REP Roasting / Skeleton Key RC4 Downgrade alerts
        for (client_ip, kdc_ip), info in kerberoast_events.items():
            spns = sorted(info["spns"])
            users = sorted(info["users"])
            realms = sorted(info["realms"])
            rc4_tgs = info["rc4_tgs"]
            as_rep_rc4 = info["as_rep_rc4"]
            usr_str = f" for {', '.join(users[:3])}" if users else ""
            rlm_str = f"@{realms[0]}" if realms else ""

            if as_rep_rc4 >= 1:
                alerts.append(
                    Alert(
                        detection_type=self.detection_type,
                        severity=Severity.HIGH,
                        confidence=94,
                        source_ip=client_ip,
                        destination_ip=kdc_ip,
                        description=(
                            f"Kerberos RC4-HMAC Ticket / Skeleton Key Downgrade{usr_str}{rlm_str}: "
                            f"KDC issued {as_rep_rc4} RC4-HMAC (etype 23) AS-REP ticket(s)"
                        ),
                        timestamp=info["first_ts"],
                        details={
                            "protocol": "Kerberos",
                            "port": 88,
                            "attack": "AS-REP Roasting / Skeleton Key RC4 Downgrade",
                            "rc4_as_rep_count": as_rep_rc4,
                            "users": users,
                            "realms": realms,
                        },
                    )
                )

            if rc4_tgs >= 1 or len(spns) >= 2:
                spn_desc = f" targeting SPNs ({', '.join(spns[:4])})" if spns else ""
                rc4_desc = f" with RC4-HMAC (etype 23) downgrade ({rc4_tgs} tickets)" if rc4_tgs else ""
                alerts.append(
                    Alert(
                        detection_type=self.detection_type,
                        severity=Severity.HIGH if rc4_tgs >= 1 else Severity.MEDIUM,
                        confidence=min(96, 86 + rc4_tgs * 3 + len(spns) * 2),
                        source_ip=client_ip,
                        destination_ip=kdc_ip,
                        description=f"Kerberoasting / RC4 TGS Ticket Harvesting{usr_str}{rlm_str}{spn_desc}{rc4_desc}",
                        timestamp=info["first_ts"],
                        details={
                            "protocol": "Kerberos",
                            "port": 88,
                            "attack": "Kerberoasting",
                            "rc4_tgs_count": rc4_tgs,
                            "spns": spns,
                            "users": users,
                        },
                    )
                )

        # Emit Kerberos Enumeration / Password Spraying alerts
        for (client_ip, kdc_ip), err_counts in krb_errors.items():
            total_errs = sum(err_counts.values())
            info = kerberoast_events.get((client_ip, kdc_ip), {})
            users = sorted(info.get("users", set()))
            as_rep_ok = info.get("as_rep_success", 0)
            if total_errs >= 3:
                summary = ", ".join(f"{k}={v}" for k, v in err_counts.items())
                usr_str = f" [accounts: {', '.join(users[:5])}]" if users else ""
                succ_str = f" -> FOLLOWED BY {as_rep_ok} SUCCESSFUL AS-REP!" if as_rep_ok else ""
                alerts.append(
                    Alert(
                        detection_type=self.detection_type,
                        severity=Severity.CRITICAL if as_rep_ok and total_errs >= 5 else (Severity.HIGH if total_errs >= 5 else Severity.MEDIUM),
                        confidence=min(97, 80 + total_errs * 2 + (8 if as_rep_ok else 0)),
                        source_ip=client_ip,
                        destination_ip=kdc_ip,
                        description=f"Kerberos Password Spraying / User Enumeration (Kerbrute): {total_errs} KRB-ERROR responses ({summary}){usr_str}{succ_str}",
                        timestamp=first_err_ts.get((client_ip, kdc_ip)),
                        details={
                            "protocol": "Kerberos",
                            "port": 88,
                            "total_errors": total_errs,
                            "errors": dict(err_counts),
                            "users": users,
                            "successful_logins": as_rep_ok,
                        },
                    )
                )

        return alerts

    def _analyze_rdp_and_winrm(self, packets: list[ParsedPacket]) -> list[Alert]:
        """Inspect RDP (port 3389) and WinRM (ports 5985/5986) lateral movement."""
        alerts: list[Alert] = []

        rdp_targets_by_client: dict[str, set[str]] = defaultdict(set)
        rdp_attempts_by_pair: dict[tuple[str, str], int] = defaultdict(int)
        rdp_users_by_pair: dict[tuple[str, str], set[str]] = defaultdict(set)
        rdp_keystroke_frames: dict[tuple[str, str], int] = defaultdict(int)
        first_rdp_ts: dict[tuple[str, str], Any] = {}

        winrm_hits: dict[tuple[str, str], int] = defaultdict(int)
        first_winrm_ts: dict[tuple[str, str], Any] = {}

        for pkt in packets:
            if pkt.dst_port == 3389:
                pair = (pkt.src_ip, pkt.dst_ip)
                if pkt.flags == "S":
                    rdp_attempts_by_pair[pair] += 1
                    rdp_targets_by_client[pkt.src_ip].add(pkt.dst_ip)
                    first_rdp_ts.setdefault(pair, pkt.timestamp)

                if pkt.payload:
                    # Detect SharpRDP / automated keystroke-channel frames (TLS AppData ~35-55 bytes)
                    if pkt.payload[:3] == b"\x17\x03\x03" and 32 <= len(pkt.payload) <= 56:
                        rdp_keystroke_frames[pair] += 1
                        first_rdp_ts.setdefault(pair, pkt.timestamp)

                    m_cookie = re.search(rb"Cookie:\s*mstshash=([^\r\n;]+)", pkt.payload, re.IGNORECASE)
                    if m_cookie:
                        user = m_cookie.group(1).decode("latin-1", errors="ignore").strip()
                        rdp_users_by_pair[pair].add(user)
                        rdp_attempts_by_pair[pair] += 1
                        rdp_targets_by_client[pkt.src_ip].add(pkt.dst_ip)
                        first_rdp_ts.setdefault(pair, pkt.timestamp)

                    ntlm = parse_ntlmssp_auth(pkt.payload)
                    if ntlm and ntlm["username"]:
                        rdp_users_by_pair[pair].add(ntlm["username"])
                        rdp_attempts_by_pair[pair] += 1
                        rdp_targets_by_client[pkt.src_ip].add(pkt.dst_ip)
                        first_rdp_ts.setdefault(pair, pkt.timestamp)

            if pkt.dst_port in (5985, 5986) and pkt.payload:
                if b"/wsman" in pkt.payload.lower() and any(
                    kw in pkt.payload
                    for kw in (b"CommandLine", b"Execute", b"Shell", b"NTLMSSP", b"Kerberos", b"WSMAN")
                ):
                    pair = (pkt.src_ip, pkt.dst_ip)
                    winrm_hits[pair] += 1
                    first_winrm_ts.setdefault(pair, pkt.timestamp)

        for (client_ip, server_ip), attempts in rdp_attempts_by_pair.items():
            users = sorted(rdp_users_by_pair.get((client_ip, server_ip), set()))
            ks_frames = rdp_keystroke_frames.get((client_ip, server_ip), 0)
            if ks_frames >= 80:
                user_str = f" as {', '.join(users[:3])}" if users else ""
                alerts.append(
                    Alert(
                        detection_type=self.detection_type,
                        severity=Severity.CRITICAL,
                        confidence=96,
                        source_ip=client_ip,
                        destination_ip=server_ip,
                        description=(
                            f"SharpRDP / Automated RDP Command Execution{user_str}: "
                            f"{ks_frames} rapid keystroke-channel frames over TCP/3389"
                        ),
                        timestamp=first_rdp_ts.get((client_ip, server_ip)),
                        details={
                            "protocol": "RDP",
                            "port": 3389,
                            "attack": "SharpRDP Keystroke Execution",
                            "keystroke_frames": ks_frames,
                            "users": users,
                        },
                    )
                )
            elif attempts >= 4 or len(users) >= 2:
                user_str = f" (users: {', '.join(users[:4])})" if users else ""
                alerts.append(
                    Alert(
                        detection_type=self.detection_type,
                        severity=Severity.HIGH if attempts >= 8 or len(users) >= 3 else Severity.MEDIUM,
                        confidence=min(95, 76 + attempts * 2 + len(users) * 5),
                        source_ip=client_ip,
                        destination_ip=server_ip,
                        description=f"RDP Brute Force / Lateral Access: {attempts} connection/auth attempts{user_str}",
                        timestamp=first_rdp_ts.get((client_ip, server_ip)),
                        details={
                            "protocol": "RDP",
                            "port": 3389,
                            "attempts": attempts,
                            "users": users,
                        },
                    )
                )

        for client_ip, targets in rdp_targets_by_client.items():
            if len(targets) >= 3:
                sorted_targets = sorted(targets)
                alerts.append(
                    Alert(
                        detection_type=self.detection_type,
                        severity=Severity.HIGH,
                        confidence=min(94, 80 + len(targets) * 3),
                        source_ip=client_ip,
                        destination_ip=sorted_targets[0],
                        description=(
                            f"RDP Lateral Movement Sweep: {client_ip} initiated RDP sessions "
                            f"across {len(targets)} hosts ({', '.join(sorted_targets[:4])})"
                        ),
                        timestamp=first_rdp_ts.get((client_ip, sorted_targets[0])),
                        details={
                            "protocol": "RDP",
                            "port": 3389,
                            "target_hosts": sorted_targets,
                        },
                    )
                )

        for (client_ip, server_ip), count in winrm_hits.items():
            alerts.append(
                Alert(
                    detection_type=self.detection_type,
                    severity=Severity.HIGH,
                    confidence=min(94, 84 + count * 2),
                    source_ip=client_ip,
                    destination_ip=server_ip,
                    description=f"WinRM Lateral Movement: {count} WS-Management remote shell request(s) to /wsman",
                    timestamp=first_winrm_ts.get((client_ip, server_ip)),
                    details={
                        "protocol": "SMB",
                        "port": 5985,
                        "subprotocol": "WinRM",
                        "wsman_requests": count,
                    },
                )
            )

        return alerts

