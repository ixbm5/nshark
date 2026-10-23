"""Automated test suite for NSHARK core, detectors, extractors, and MITRE mapping."""

from __future__ import annotations

import gzip
import struct
import tempfile
from datetime import datetime, timedelta, timezone

from nshark.core.flow import reconstruct_flows
from nshark.core.models import DetectionType, FPTolerance, ParsedPacket, Severity
from nshark.core.parser import parse_pcap
from nshark.detectors.arp_spoof import ARPSpoofDetector
from nshark.detectors.beaconing import BeaconingDetector
from nshark.detectors.brute_force import BruteForceDetector
from nshark.detectors.cleartext_creds import CleartextCredsDetector
from nshark.detectors.dns_tunnel import DNSTunnelDetector
from nshark.detectors.exfiltration import ExfiltrationDetector
from nshark.detectors.port_scan import PortScanDetector
from nshark.detectors.post_exploitation import PostExploitationDetector
from nshark.detectors.tls_analysis import TLSAnalysisDetector, parse_tls_client_hello
from nshark.extractors.file_carver import carve_files
from nshark.extractors.ioc_extractor import extract_iocs
from nshark.mapping.attack import map_all
from nshark.scoring.engine import ScoringEngine


def _build_client_hello(ciphers: list[int], extensions: list[tuple[int, bytes]]) -> bytes:
    """Construct a synthetic TLS 1.2 ClientHello handshake record."""
    version = struct.pack("!H", 0x0303)
    random_bytes = b"\x11" * 32
    session_id = b"\x00"
    cipher_bytes = b"".join(struct.pack("!H", c) for c in ciphers)
    cipher_block = struct.pack("!H", len(cipher_bytes)) + cipher_bytes
    comp_block = b"\x01\x00"

    ext_payload = b""
    for ext_type, ext_data in extensions:
        ext_payload += struct.pack("!HH", ext_type, len(ext_data)) + ext_data
    ext_block = struct.pack("!H", len(ext_payload)) + ext_payload

    ch_body = version + random_bytes + session_id + cipher_block + comp_block + ext_block
    handshake = b"\x01" + struct.pack("!I", len(ch_body))[1:] + ch_body
    record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
    return record


def test_port_scan_detector() -> None:
    base_ts = datetime(2026, 1, 1, 12, 0, 0)
    packets = [
        ParsedPacket(
            timestamp=base_ts + timedelta(milliseconds=i * 10),
            src_ip="10.0.0.99",
            dst_ip="10.0.0.10",
            src_port=40000 + i,
            dst_port=20 + i,
            protocol="TCP",
            length=60,
            flags="S",
            payload=b"",
        )
        for i in range(120)
    ]
    flows = reconstruct_flows(packets)
    alerts = PortScanDetector().analyze(packets, flows, {})
    assert any(a.detection_type == DetectionType.PORT_SCAN for a in alerts)


def test_brute_force_and_cleartext_creds() -> None:
    base_ts = datetime(2026, 1, 1, 12, 5, 0)
    packets: list[ParsedPacket] = []
    for i in range(30):
        t = base_ts + timedelta(seconds=i)
        packets.append(
            ParsedPacket(
                timestamp=t,
                src_ip="10.0.0.50",
                dst_ip="10.0.0.20",
                src_port=50000 + i,
                dst_port=21,
                protocol="TCP",
                length=74,
                flags="PA",
                payload=b"USER admin\r\nPASS supersecret123\r\n",
            )
        )
        packets.append(
            ParsedPacket(
                timestamp=t + timedelta(milliseconds=50),
                src_ip="10.0.0.20",
                dst_ip="10.0.0.50",
                src_port=21,
                src_port_dummy=0,
                dst_port=50000 + i,
                protocol="TCP",
                length=80,
                flags="PA",
                payload=b"530 Login incorrect.\r\n",
            )
            if False
            else ParsedPacket(
                timestamp=t + timedelta(milliseconds=50),
                src_ip="10.0.0.20",
                dst_ip="10.0.0.50",
                src_port=21,
                dst_port=50000 + i,
                protocol="TCP",
                length=80,
                flags="PA",
                payload=b"530 Login incorrect.\r\n",
            )
        )
    flows = reconstruct_flows(packets)
    bf_alerts = BruteForceDetector().analyze(packets, flows, {})
    cred_alerts = CleartextCredsDetector().analyze(packets, flows, {})
    assert any(a.detection_type == DetectionType.BRUTE_FORCE for a in bf_alerts)
    assert any(a.detection_type == DetectionType.CLEARTEXT_CREDENTIALS for a in cred_alerts)
    assert "su***" in cred_alerts[0].description


def test_c2_beaconing_detector() -> None:
    base_ts = datetime(2026, 1, 1, 13, 0, 0)
    packets = [
        ParsedPacket(
            timestamp=base_ts + timedelta(seconds=i * 30),
            src_ip="192.168.1.15",
            dst_ip="198.51.100.77",
            src_port=51000 + i,
            dst_port=443,
            protocol="TCP",
            length=120,
            flags="S",
            payload=b"",
        )
        for i in range(15)
    ]
    flows = reconstruct_flows(packets)
    alerts = BeaconingDetector().analyze(packets, flows, {})
    assert any(a.detection_type == DetectionType.C2_BEACONING for a in alerts)


def test_exfiltration_detector() -> None:
    base_ts = datetime(2026, 1, 1, 14, 0, 0)
    packets = [
        ParsedPacket(
            timestamp=base_ts,
            src_ip="192.168.1.15",
            dst_ip="203.0.113.88",
            src_port=55111,
            dst_port=443,
            protocol="TCP",
            length=2_500_000,
            flags="PA",
            payload=b"A" * 100,
        ),
        ParsedPacket(
            timestamp=base_ts + timedelta(seconds=1),
            src_ip="203.0.113.88",
            dst_ip="192.168.1.15",
            src_port=443,
            dst_port=55111,
            protocol="TCP",
            length=1000,
            flags="A",
            payload=b"",
        ),
    ]
    flows = reconstruct_flows(packets)
    alerts = ExfiltrationDetector().analyze(packets, flows, {})
    assert any(a.detection_type == DetectionType.DATA_EXFILTRATION for a in alerts)


def test_post_exploitation_detector() -> None:
    base_ts = datetime(2026, 1, 1, 15, 0, 0)
    packets = [
        ParsedPacket(
            timestamp=base_ts,
            src_ip="10.0.0.99",
            dst_ip="10.0.0.10",
            src_port=44111,
            dst_port=80,
            protocol="TCP",
            length=220,
            flags="PA",
            payload=b"GET /cgi-bin/status?cmd=;id;whoami HTTP/1.1\r\nHost: 10.0.0.10\r\n\r\n",
        ),
        ParsedPacket(
            timestamp=base_ts + timedelta(seconds=1),
            src_ip="10.0.0.10",
            dst_ip="10.0.0.99",
            src_port=4444,
            dst_port=53211,
            protocol="TCP",
            length=180,
            flags="PA",
            payload=b"uid=0(root) gid=0(root) groups=0(root)\n# ",
        ),
    ]
    flows = reconstruct_flows(packets)
    alerts = PostExploitationDetector().analyze(packets, flows, {})
    types = {a.detection_type for a in alerts}
    assert DetectionType.COMMAND_INJECTION in types
    assert DetectionType.REVERSE_SHELL in types


def test_tls_ja3_and_cert_detector() -> None:
    base_ts = datetime(2026, 1, 1, 16, 0, 0)
    # Build a ClientHello and verify JA3 parser
    ch_bytes = _build_client_hello([0x002F, 0x0035, 0x0A0A], [(0x000B, b"\x01\x00")])
    parsed = parse_tls_client_hello(ch_bytes)
    assert parsed is not None
    assert parsed["ja3_string"] == "771,47-53,11,,0"

    # Test malicious Cobalt Strike cert detection + bare-IP SNI-less TLS detection
    packets = [
        ParsedPacket(
            timestamp=base_ts + timedelta(seconds=i),
            src_ip="192.168.1.25",
            dst_ip="45.33.32.156",
            src_port=52000 + i,
            dst_port=443,
            protocol="TCP",
            length=len(ch_bytes),
            flags="PA",
            payload=ch_bytes,
        )
        for i in range(3)
    ]
    packets.append(
        ParsedPacket(
            timestamp=base_ts + timedelta(seconds=4),
            src_ip="45.33.32.156",
            dst_ip="192.168.1.25",
            src_port=443,
            dst_port=52000,
            protocol="TCP",
            length=150,
            flags="PA",
            payload=b"\x16\x03\x03\x00\x40\x0b...Major Cobalt Strike...",
        )
    )
    flows = reconstruct_flows(packets)
    alerts = TLSAnalysisDetector().analyze(packets, flows, {})
    assert len(alerts) >= 2
    assert any(a.severity == Severity.CRITICAL for a in alerts)


def test_arp_spoofing_detector() -> None:
    base_ts = datetime(2026, 1, 1, 17, 0, 0)
    packets = [
        ParsedPacket(
            timestamp=base_ts,
            src_ip="192.168.1.1",
            dst_ip="192.168.1.50",
            src_port=0,
            dst_port=0,
            protocol="ARP",
            length=42,
            flags="op=2;hwsrc=aa:bb:cc:11:22:33;hwdst=ff:ff:ff:ff:ff:ff",
            payload=b"",
        ),
        ParsedPacket(
            timestamp=base_ts + timedelta(seconds=1),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.50",
            src_port=0,
            dst_port=0,
            protocol="ARP",
            length=42,
            flags="op=2;hwsrc=de:ad:be:ef:00:99;hwdst=ff:ff:ff:ff:ff:ff",
            payload=b"",
        ),
    ]
    alerts = ARPSpoofDetector().analyze(packets, [], {})
    assert len(alerts) == 1
    assert alerts[0].detection_type == DetectionType.ARP_SPOOFING
    assert alerts[0].severity == Severity.CRITICAL


def test_file_carver_gzip_and_chunked() -> None:
    base_ts = datetime(2026, 1, 1, 18, 0, 0)
    pe_bytes = b"MZ\x90\x00\x03\x00\x00\x00" + b"PAYLOAD_DATA" * 20
    gz_body = gzip.compress(pe_bytes)
    chunk_header = f"{len(gz_body):x}\r\n".encode("ascii")
    http_resp = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Content-Encoding: gzip\r\n"
        b"Content-Disposition: attachment; filename=\"implant.exe\"\r\n\r\n"
        + chunk_header
        + gz_body
        + b"\r\n0\r\n\r\n"
    )
    packets = [
        ParsedPacket(
            timestamp=base_ts,
            src_ip="198.51.100.50",
            dst_ip="192.168.1.10",
            src_port=80,
            dst_port=54321,
            protocol="TCP",
            length=len(http_resp),
            flags="PA",
            payload=http_resp,
        )
    ]
    flows = reconstruct_flows(packets)
    with tempfile.TemporaryDirectory() as tmpdir:
        carved = carve_files(packets, flows, output_dir=tmpdir)
        assert len(carved) == 1
        assert carved[0].filename == "implant.exe"
        assert "PE" in carved[0].file_type
        assert carved[0].size == len(pe_bytes)


def test_mitre_mapping_and_scoring_correlation() -> None:
    base_ts = datetime(2026, 1, 1, 19, 0, 0)
    packets = [
        ParsedPacket(
            timestamp=base_ts + timedelta(milliseconds=i * 10),
            src_ip="10.0.0.77",
            dst_ip="10.0.0.10",
            src_port=40000 + i,
            dst_port=100 + i,
            protocol="TCP",
            length=60,
            flags="S",
            payload=b"",
        )
        for i in range(110)
    ]
    packets.append(
        ParsedPacket(
            timestamp=base_ts + timedelta(seconds=5),
            src_ip="10.0.0.77",
            dst_ip="10.0.0.10",
            src_port=45000,
            dst_port=80,
            protocol="TCP",
            length=200,
            flags="PA",
            payload=b"GET /index.php?cmd=;cat%20/etc/passwd HTTP/1.1\r\nHost: 10.0.0.10\r\n\r\n",
        )
    )
    flows = reconstruct_flows(packets)
    raw = PortScanDetector().analyze(packets, flows, {}) + PostExploitationDetector().analyze(packets, flows, {})
    mapped = map_all(raw)
    assert all(a.mitre is not None for a in mapped)
    scored = ScoringEngine().score_and_correlate(mapped, fp_tolerance=FPTolerance.BALANCED)
    assert len(scored) >= 2
    assert any(a.severity == Severity.CRITICAL for a in scored)


def test_streaming_pcap_parser_and_dns_tunnel() -> None:
    from scapy.all import ARP, DNS, DNSQR, Ether, IP, TCP, UDP, wrpcap
    from nshark.core.parser import parse_pcap

    pkts = [
        Ether() / ARP(op=2, psrc="192.168.1.1", pdst="192.168.1.50", hwsrc="aa:bb:cc:11:22:33"),
        Ether() / IP(src="192.168.1.50", dst="8.8.8.8") / TCP(sport=50000, dport=443, flags="S"),
    ]
    for i in range(18):
        sub = f"a8f9c2e1b4d709123847abcde{i:04x}998877665544332211"
        pkts.append(
            Ether()
            / IP(src="192.168.1.50", dst="8.8.8.8")
            / UDP(sport=53000 + i, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=f"{sub}.c2tunnel.evil.org", qtype=16))
        )

    with tempfile.NamedTemporaryFile(suffix=".pcap") as tmp:
        wrpcap(tmp.name, pkts)
        parsed = parse_pcap(tmp.name)
        assert len(parsed) == 20
        # Non-DNS packets should drop raw scapy object to save memory
        tcp_pkt = [p for p in parsed if p.protocol == "TCP"][0]
        assert tcp_pkt.raw is None
        # DNS packets keep raw for Scapy DNS layer inspection
        dns_pkt = [p for p in parsed if p.protocol == "UDP" and p.dst_port == 53][0]
        assert dns_pkt.raw is not None
        flows = reconstruct_flows(parsed)
        alerts = DNSTunnelDetector().analyze(parsed, flows, {})
        assert any(a.detection_type == DetectionType.DNS_TUNNELING for a in alerts)


def test_lateral_movement_smb_kerberos_rdp() -> None:
    from nshark.detectors.lateral_movement import LateralMovementDetector

    base_ts = datetime(2026, 1, 1, 20, 0, 0)
    packets = [
        # 1. SMB2 Tree Connect to ADMIN$ and svcctl pipe (PsExec / Impacket)
        ParsedPacket(
            timestamp=base_ts,
            src_ip="10.0.0.50",
            dst_ip="10.0.0.10",
            src_port=51234,
            dst_port=445,
            protocol="TCP",
            length=180,
            flags="PA",
            payload=b"\xfeSMB" + "\\\\10.0.0.10\\ADMIN$".encode("utf-16le") + b"svcctl",
        ),
        # 2. Kerberoasting TGS-REQ with RC4-HMAC (etype 23 / \x02\x01\x17) targeting MSSQLSvc
        ParsedPacket(
            timestamp=base_ts + timedelta(seconds=2),
            src_ip="10.0.0.50",
            dst_ip="10.0.0.5",
            src_port=52000,
            dst_port=88,
            protocol="TCP",
            length=220,
            flags="PA",
            payload=b"\x00\x00\x00\x80\x6c\x82\x00\x7c\xa1\x03\x02\x01\x0c\x02\x01\x17MSSQLSvc/sql01.corp.local:1433",
        ),
        # 3. RDP multi-user brute force on port 3389
        ParsedPacket(
            timestamp=base_ts + timedelta(seconds=3),
            src_ip="10.0.0.50",
            dst_ip="10.0.0.20",
            src_port=53001,
            dst_port=3389,
            protocol="TCP",
            length=90,
            flags="PA",
            payload=b"\x03\x00\x00\x2bCookie: mstshash=Administrator\r\n",
        ),
        ParsedPacket(
            timestamp=base_ts + timedelta(seconds=4),
            src_ip="10.0.0.50",
            dst_ip="10.0.0.20",
            src_port=53002,
            dst_port=3389,
            protocol="TCP",
            length=90,
            flags="PA",
            payload=b"\x03\x00\x00\x2bCookie: mstshash=backup_admin\r\n",
        ),
    ]
    flows = reconstruct_flows(packets)
    raw_alerts = LateralMovementDetector().analyze(packets, flows, {})
    mapped = map_all(raw_alerts)
    assert len(mapped) == 3
    mitre_ids = {a.mitre.technique_id for a in mapped if a.mitre}
    assert "T1021.002" in mitre_ids  # SMB Admin Shares
    assert "T1558.003" in mitre_ids  # Kerberoasting
    assert "T1021.001" in mitre_ids  # RDP


def test_hash_extractor_and_host_profiler() -> None:
    from nshark.extractors.hash_extractor import extract_hashes
    from nshark.extractors.host_profiler import profile_hosts

    base_ts = datetime(2026, 1, 1, 21, 0, 0)
    # Build NTLMSSP Type 2 Challenge (8-byte server challenge = 1122334455667788)
    ntlm_t2 = b"NTLMSSP\x00\x02\x00\x00\x00" + b"\x00" * 12 + bytes.fromhex("1122334455667788") + b"\x00" * 16

    # Build NTLMSSP Type 3 Auth with NetNTLMv2 response (48 bytes = 16B proof + 32B blob)
    domain_b = "CORP".encode("utf-16le")
    user_b = "svc_sql".encode("utf-16le")
    wks_b = "WIN10-DEV".encode("utf-16le")
    nt_resp = b"\xaa" * 16 + b"\xbb" * 32
    base_off = 64
    dom_off = base_off
    usr_off = dom_off + len(domain_b)
    wks_off = usr_off + len(user_b)
    nt_off = wks_off + len(wks_b)

    ntlm_t3 = (
        b"NTLMSSP\x00\x03\x00\x00\x00"
        + struct.pack("<HHI", 0, 0, base_off)
        + struct.pack("<HHI", len(nt_resp), len(nt_resp), nt_off)
        + struct.pack("<HHI", len(domain_b), len(domain_b), dom_off)
        + struct.pack("<HHI", len(user_b), len(user_b), usr_off)
        + struct.pack("<HHI", len(wks_b), len(wks_b), wks_off)
        + b"\x00" * 12
        + domain_b
        + user_b
        + wks_b
        + nt_resp
    )

    packets = [
        ParsedPacket(
            timestamp=base_ts,
            src_ip="10.0.0.50",
            dst_ip="10.0.0.10",
            src_port=0,
            dst_port=0,
            protocol="ARP",
            length=42,
            flags="op=2;hwsrc=00:50:56:aa:bb:cc;hwdst=ff:ff:ff:ff:ff:ff",
        ),
        ParsedPacket(
            timestamp=base_ts + timedelta(seconds=1),
            src_ip="10.0.0.10",
            dst_ip="10.0.0.50",
            src_port=445,
            dst_port=51000,
            protocol="TCP",
            length=len(ntlm_t2),
            flags="PA",
            payload=b"\xfeSMB" + ntlm_t2,
        ),
        ParsedPacket(
            timestamp=base_ts + timedelta(seconds=2),
            src_ip="10.0.0.50",
            dst_ip="10.0.0.10",
            src_port=51000,
            dst_port=445,
            protocol="TCP",
            length=len(ntlm_t3),
            flags="PA",
            payload=b"\xfeSMB" + ntlm_t3,
        ),
    ]

    hashes = extract_hashes(packets)
    assert len(hashes) == 1
    assert hashes[0].hashcat_mode == 5600
    assert hashes[0].hash_string.startswith("svc_sql::CORP:1122334455667788:")

    hosts = profile_hosts(packets)
    by_ip = {h.ip: h for h in hosts}
    assert by_ip["10.0.0.50"].vendor == "VMware"
    assert by_ip["10.0.0.50"].hostname == "WIN10-DEV"
    assert by_ip["10.0.0.50"].domain == "CORP"
    assert by_ip["10.0.0.50"].os_guess == "Windows"


def test_llmnr_poisoning_icmp_tunnel_and_extended_creds() -> None:
    base_ts = datetime(2026, 1, 1, 22, 0, 0)
    # LLMNR response (QR=1 -> 0x8000) from rogue responder 10.0.0.99 spoofing WPAD
    llmnr_wpad = b"\x12\x34\x80\x00\x00\x01\x00\x01\x00\x00\x00\x00\x04WPAD\x00\x00\x01\x00\x01"
    # SNMPv2c GetRequest with community string "internal_rw"
    snmp_pkt = b"\x30\x20\x02\x01\x01\x04\x0binternal_rw\xa0\x0e\x02\x01\x01\x02\x01\x00\x02\x01\x00\x30\x03"

    packets = [
        ParsedPacket(
            timestamp=base_ts,
            src_ip="10.0.0.99",
            dst_ip="10.0.0.25",
            src_port=5355,
            dst_port=54111,
            protocol="UDP",
            length=len(llmnr_wpad),
            flags="",
            payload=llmnr_wpad,
        ),
        ParsedPacket(
            timestamp=base_ts + timedelta(seconds=1),
            src_ip="10.0.0.25",
            dst_ip="10.0.0.1",
            src_port=55123,
            dst_port=161,
            protocol="UDP",
            length=len(snmp_pkt),
            flags="",
            payload=snmp_pkt,
        ),
    ]
    # Add 5 oversized ICMP tunnel packets
    for i in range(5):
        packets.append(
            ParsedPacket(
                timestamp=base_ts + timedelta(seconds=2 + i),
                src_ip="10.0.0.25",
                dst_ip="198.51.100.77",
                src_port=0,
                dst_port=0,
                protocol="ICMP",
                length=240,
                flags="",
                payload=b"EXFIL_CHUNK_" + bytes([i]) * 180,
            )
        )

    flows = reconstruct_flows(packets)
    raw = (
        ARPSpoofDetector().analyze(packets, flows, {})
        + CleartextCredsDetector().analyze(packets, flows, {})
        + ExfiltrationDetector().analyze(packets, flows, {})
    )
    mapped = map_all(raw)
    scored = ScoringEngine().score_and_correlate(mapped)
    mitre_ids = {a.mitre.technique_id for a in scored if a.mitre}
    assert "T1557.001" in mitre_ids  # LLMNR/NBT-NS Poisoning
    assert "T1040" in mitre_ids      # SNMP Community String
    assert "T1048.003" in mitre_ids  # ICMP Exfiltration
    assert all("wireshark_filter" in a.details for a in scored)


def test_multi_protocol_file_carving_and_ioc_hashes(tmp_path) -> None:
    from nshark.extractors.ioc_extractor import extract_iocs

    base_ts = datetime(2026, 1, 2, 10, 0, 0)
    # 1. SMB2 CREATE ("implant.exe") + SMB2 WRITE (MZ PE payload)
    fn_utf16 = "implant.exe".encode("utf-16le")
    smb2_create_hdr = bytearray(64)
    smb2_create_hdr[0:4] = b"\xfeSMB"
    struct.pack_into("<H", smb2_create_hdr, 12, 0x0005)  # CREATE
    smb2_create_body = bytearray(56)
    struct.pack_into("<H", smb2_create_body, 44, 64 + 56)  # name_offset = 120
    struct.pack_into("<H", smb2_create_body, 46, len(fn_utf16))
    smb2_create_pkt = bytes(smb2_create_hdr) + bytes(smb2_create_body) + fn_utf16

    pe_data = b"MZ\x90\x00\x03\x00\x00\x00" + b"A" * 64
    smb2_write_hdr = bytearray(64)
    smb2_write_hdr[0:4] = b"\xfeSMB"
    struct.pack_into("<H", smb2_write_hdr, 12, 0x0009)  # WRITE
    smb2_write_body = bytearray(48)
    struct.pack_into("<H", smb2_write_body, 2, 64 + 48)  # data_offset = 112
    struct.pack_into("<I", smb2_write_body, 4, len(pe_data))
    smb2_write_pkt = bytes(smb2_write_hdr) + bytes(smb2_write_body) + pe_data

    # 2. TFTP RRQ ("config.pdf") + TFTP DATA block #1
    tftp_rrq = b"\x00\x01config.pdf\x00octet\x00"
    pdf_data = b"%PDF-1.7\n" + b"B" * 48
    tftp_data = b"\x00\x03\x00\x01" + pdf_data

    # 3. SMTP MIME Base64 attachment ("loot.zip")
    zip_data = b"PK\x03\x04" + b"Z" * 48
    import base64 as _b64
    mime_payload = (
        b"Content-Disposition: attachment; filename=\"loot.zip\"\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n"
        + _b64.b64encode(zip_data)
        + b"\r\n"
    )

    packets = [
        ParsedPacket(base_ts, "10.0.0.5", "10.0.0.20", 51001, 445, "TCP", len(smb2_create_pkt), "PA", smb2_create_pkt),
        ParsedPacket(base_ts + timedelta(seconds=1), "10.0.0.5", "10.0.0.20", 51001, 445, "TCP", len(smb2_write_pkt), "PA", smb2_write_pkt),
        ParsedPacket(base_ts + timedelta(seconds=2), "10.0.0.5", "10.0.0.30", 52000, 69, "UDP", len(tftp_rrq), "", tftp_rrq),
        ParsedPacket(base_ts + timedelta(seconds=3), "10.0.0.30", "10.0.0.5", 69, 52000, "UDP", len(tftp_data), "", tftp_data),
        ParsedPacket(base_ts + timedelta(seconds=4), "10.0.0.5", "10.0.0.40", 53000, 25, "TCP", len(mime_payload), "PA", mime_payload),
    ]

    flows = reconstruct_flows(packets)
    carved = carve_files(packets, flows, output_dir=str(tmp_path))
    names = {c.filename: c for c in carved}
    assert "implant.exe" in names
    assert names["implant.exe"].file_type == "Windows PE Executable"
    assert "config.pdf" in names
    assert names["config.pdf"].file_type == "PDF Document"
    assert "loot.zip" in names
    assert names["loot.zip"].file_type == "ZIP Archive / Office OpenXML"

    iocs = extract_iocs(packets, flows)
    sha256_iocs = {i.value for i in iocs if i.type.value == "hash_sha256"}
    assert names["implant.exe"].sha256 in sha256_iocs


def test_ja3s_ssh_hassh_dhcp_spoofing_and_extended_hashes() -> None:
    from nshark.extractors.hash_extractor import extract_hashes
    from nshark.extractors.host_profiler import profile_hosts

    base_ts = datetime(2026, 1, 2, 12, 0, 0)

    # 1. SSH banner on non-standard port 4444 (Go Chisel/Sliver tunnel)
    ssh_banner = b"SSH-2.0-Go\r\n"

    # 2. HTTP Digest Auth header (Hashcat -m 11400) + JWT Bearer Token + Redis AUTH
    http_digest_pkt = (
        b"GET /admin HTTP/1.1\r\n"
        b"Host: 10.0.0.80\r\n"
        b'Authorization: Digest username="admin", realm="CorpRealm", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", '
        b'uri="/admin", qop=auth, nc=00000001, cnonce="0a4f113b", response="6629fae49393a05397450978507c4ef1"\r\n\r\n'
    )
    http_jwt_pkt = (
        b"GET /api/v1/secrets HTTP/1.1\r\n"
        b"Host: 10.0.0.80\r\n"
        b"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\r\n\r\n"
    )
    redis_auth_pkt = b"AUTH SuperSecretRedis2026\r\n"

    # 3. Competing DHCP OFFERs from two different servers (10.0.0.1 and rogue 10.0.0.66)
    dhcp_offer_1 = b"\x02\x01\x06\x00" + b"\x00" * 236 + b"\x63\x82\x53\x63\x35\x01\x02\x03\x04\x0a\x00\x00\x01\xff"
    dhcp_offer_2 = b"\x02\x01\x06\x00" + b"\x00" * 236 + b"\x63\x82\x53\x63\x35\x01\x02\x03\x04\x0a\x00\x00\x42\xff"

    packets = [
        ParsedPacket(base_ts, "10.0.0.15", "198.51.100.200", 54000, 4444, "TCP", len(ssh_banner), "PA", ssh_banner, src_mac="08:00:27:11:22:33", ttl=64, tcp_window=64240),
        ParsedPacket(base_ts + timedelta(seconds=1), "10.0.0.15", "10.0.0.80", 54001, 80, "TCP", len(http_digest_pkt), "PA", http_digest_pkt),
        ParsedPacket(base_ts + timedelta(seconds=2), "10.0.0.15", "10.0.0.80", 54002, 80, "TCP", len(http_jwt_pkt), "PA", http_jwt_pkt),
        ParsedPacket(base_ts + timedelta(seconds=3), "10.0.0.15", "10.0.0.90", 54003, 6379, "TCP", len(redis_auth_pkt), "PA", redis_auth_pkt),
        ParsedPacket(base_ts + timedelta(seconds=4), "10.0.0.1", "255.255.255.255", 67, 68, "UDP", len(dhcp_offer_1), "", dhcp_offer_1),
        ParsedPacket(base_ts + timedelta(seconds=5), "10.0.0.66", "255.255.255.255", 67, 68, "UDP", len(dhcp_offer_2), "", dhcp_offer_2),
    ]

    # Verify HTTP Digest hash extraction (-m 11400)
    hashes = extract_hashes(packets)
    assert any(h.hashcat_mode == 11400 and h.username == "admin" for h in hashes)

    # Verify passive host profiling via Ethernet MAC + TTL=64
    hosts = {h.ip: h for h in profile_hosts(packets)}
    assert hosts["10.0.0.15"].vendor == "VirtualBox"
    assert hosts["10.0.0.15"].os_guess == "Linux / Unix"

    # Verify detections & MITRE mappings (T1557.003 DHCP Spoofing, T1573 SSH Anomaly, T1040 JWT & Redis)
    flows = reconstruct_flows(packets)
    alerts = map_all(
        TLSAnalysisDetector().analyze(packets, flows, {})
        + CleartextCredsDetector().analyze(packets, flows, {})
        + ARPSpoofDetector().analyze(packets, flows, {})
    )
    mitre_ids = {a.mitre.technique_id for a in alerts if a.mitre}
    assert "T1557.003" in mitre_ids  # Rogue DHCP Spoofing
    assert "T1573" in mitre_ids      # SSH C2 Tunnel Anomaly
    assert "T1040" in mitre_ids      # JWT & Redis Cleartext Creds


def test_vxlan_unwrap_postgres_mysql_hashes_and_out_of_order_carving(tmp_path) -> None:
    from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap  # type: ignore[import-untyped]
    from nshark.extractors.hash_extractor import extract_hashes

    # 1. VXLAN (UDP 4789) packet containing an inner Ether/IP/TCP packet
    inner_frame = Ether(src="00:50:56:11:22:33", dst="00:0c:29:44:55:66") / IP(src="10.99.0.10", dst="10.99.0.20", ttl=128) / TCP(sport=445, dport=50123, flags="SA")
    vxlan_pkt = (
        Ether()
        / IP(src="172.16.0.1", dst="172.16.0.2")
        / UDP(sport=55000, dport=4789)
        / Raw(load=b"\x08\x00\x00\x00\x00\x00\x64\x00" + bytes(inner_frame))
    )
    pcap_path = str(tmp_path / "vxlan.pcap")
    wrpcap(pcap_path, [vxlan_pkt])
    parsed = parse_pcap(pcap_path)
    assert len(parsed) == 1
    assert parsed[0].src_ip == "10.99.0.10"
    assert parsed[0].dst_ip == "10.99.0.20"
    assert parsed[0].src_mac == "00:50:56:11:22:33"

    # 2. PostgreSQL MD5 (-m 11100) + MySQL SHA1 (-m 11200) challenge-response hashes
    base_ts = datetime(2026, 1, 2, 14, 0, 0)
    pg_startup = b"\x00\x00\x00\x20\x00\x03\x00\x00user\x00dbadmin\x00database\x00prod\x00\x00"
    pg_salt_msg = b"R\x00\x00\x00\x0c\x00\x00\x00\x05\xde\xad\xbe\xef"
    pg_md5_msg = b"p\x00\x00\x00\x28md50123456789abcdef0123456789abcdef\x00"

    mysql_greeting = (
        b"\x4a\x00\x00\x00\x0a"
        + b"8.0.32\x00"
        + b"\x01\x00\x00\x00"
        + b"12345678"          # part1 (8 bytes)
        + b"\x00"
        + b"\xff\xf7\x21\x02\x00\xff\x81\x15"
        + b"\x00" * 10
        + b"abcdefghijkl\x00"  # part2 (12 bytes)
    )
    mysql_auth = (
        b"\x40\x00\x00\x01"
        + b"\x85\xa6\xff\x01\x00\x00\x00\x01\x21"
        + b"\x00" * 23
        + b"root\x00"
        + b"\x14" + bytes.fromhex("aabbccddeeff00112233445566778899aabbccdd")
    )

    # 3. Out-of-order HTTP 200 OK file response (seq=2000 arrives BEFORE seq=1000)
    http_hdr = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"ordered.elf\"\r\n\r\n"
    chunk1 = b"\x7fELF" + b"1" * 28   # 32 bytes, should be first (seq=1000)
    chunk2 = b"2" * 32                 # 32 bytes, arrives earlier but has seq=2000

    pkts = [
        ParsedPacket(base_ts, "10.0.0.5", "10.0.0.54", 51000, 5432, "TCP", len(pg_startup), "PA", pg_startup),
        ParsedPacket(base_ts + timedelta(seconds=1), "10.0.0.54", "10.0.0.5", 5432, 51000, "TCP", len(pg_salt_msg), "PA", pg_salt_msg),
        ParsedPacket(base_ts + timedelta(seconds=2), "10.0.0.5", "10.0.0.54", 51000, 5432, "TCP", len(pg_md5_msg), "PA", pg_md5_msg),
        ParsedPacket(base_ts + timedelta(seconds=3), "10.0.0.33", "10.0.0.5", 3306, 52000, "TCP", len(mysql_greeting), "PA", mysql_greeting),
        ParsedPacket(base_ts + timedelta(seconds=4), "10.0.0.5", "10.0.0.33", 52000, 3306, "TCP", len(mysql_auth), "PA", mysql_auth),
        # HTTP headers (seq=500), then chunk2 out-of-order (seq=2000), then chunk1 (seq=1000)
        ParsedPacket(base_ts + timedelta(seconds=5), "10.0.0.80", "10.0.0.5", 80, 53000, "TCP", len(http_hdr), "PA", http_hdr, tcp_seq=500),
        ParsedPacket(base_ts + timedelta(seconds=6), "10.0.0.80", "10.0.0.5", 80, 53000, "TCP", len(chunk2), "PA", chunk2, tcp_seq=2000),
        ParsedPacket(base_ts + timedelta(seconds=7), "10.0.0.80", "10.0.0.5", 80, 53000, "TCP", len(chunk1), "PA", chunk1, tcp_seq=1000),
    ]

    hashes = extract_hashes(pkts)
    modes = {h.hashcat_mode: h for h in hashes}
    assert 11100 in modes
    assert modes[11100].hash_string == "$postgres$*dbadmin*deadbeef*0123456789abcdef0123456789abcdef"
    assert 11200 in modes
    assert modes[11200].username == "root"

    flows = reconstruct_flows(pkts)
    carved = carve_files(pkts, flows, output_dir=str(tmp_path))
    assert len(carved) == 1
    assert carved[0].filename == "ordered.elf"
    assert carved[0].file_type == "Linux ELF Executable"


def test_parsed_packet_slots_and_bpf_filter(tmp_path) -> None:
    from scapy.all import Ether, IP, TCP, UDP, wrpcap  # type: ignore[import-untyped]
    import pytest

    # 1. Test ParsedPacket __slots__ memory efficiency
    p = ParsedPacket(
        timestamp=datetime.now(timezone.utc).replace(tzinfo=None),
        src_ip="192.168.1.100",
        dst_ip="192.168.1.1",
        src_port=54321,
        dst_port=80,
        protocol="TCP",
        length=64,
        flags="S",
    )
    assert hasattr(p, "__slots__")
    assert not hasattr(p, "__dict__")
    assert "ParsedPacket" in repr(p)

    # 2. Test PCAP parsing with BPF filter streaming
    pcap_file = str(tmp_path / "mixed.pcap")
    pkts = [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=10000, dport=80, flags="S"),
        Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=10000, flags="SA"),
        Ether() / IP(src="10.0.0.1", dst="1.1.1.1") / UDP(sport=20000, dport=53),
        Ether() / IP(src="1.1.1.1", dst="10.0.0.1") / UDP(sport=53, dport=20000),
    ]
    wrpcap(pcap_file, pkts)

    # Parse without filter -> all 4 packets
    all_parsed = parse_pcap(pcap_file)
    assert len(all_parsed) == 4

    # Parse with BPF filter -> only TCP port 80
    tcp_parsed = parse_pcap(pcap_file, bpf_filter="tcp port 80")
    assert len(tcp_parsed) == 2
    assert all(pkt.protocol == "TCP" for pkt in tcp_parsed)
    assert all(pkt.src_port == 80 or pkt.dst_port == 80 for pkt in tcp_parsed)

    # Parse with BPF filter -> only UDP port 53
    udp_parsed = parse_pcap(pcap_file, bpf_filter="udp port 53")
    assert len(udp_parsed) == 2
    assert all(pkt.protocol == "UDP" for pkt in udp_parsed)

    # Invalid BPF filter raises ValueError
    with pytest.raises(ValueError, match="Invalid BPF filter expression"):
        parse_pcap(pcap_file, bpf_filter="invalid syntax filter !!!")





