"""Streaming PCAP parsing engine using Scapy PcapReader."""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

from typing import Optional

from nshark.core.models import ParsedPacket

logger = logging.getLogger(__name__)


def parse_pcap(pcap_path: str, bpf_filter: Optional[str] = None) -> list[ParsedPacket]:
    """Stream a PCAP/PCAPNG file and convert packets into ParsedPacket instances.

    Uses Scapy's streaming PcapReader (or libpcap-filtered sniff if bpf_filter
    is specified) to avoid loading entire captures into memory at once. Only
    retains the raw Scapy packet reference for DNS packets (port 53) to minimize
    memory footprint.

    Args:
        pcap_path: Path to the capture file.
        bpf_filter: Optional Berkeley Packet Filter expression (e.g. 'tcp port 80').

    Returns:
        List of ParsedPacket instances sorted by timestamp.
    """
    if not os.path.isfile(pcap_path):
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    try:
        from scapy.all import ARP, Ether, ICMP, IP, IPv6, TCP, UDP, Padding, PcapReader, Raw, sniff  # type: ignore[import-untyped]
    except ImportError as exc:
        raise RuntimeError(
            "Scapy is required to parse PCAP files. Install via `pip install scapy`."
        ) from exc

    logger.info("Streaming PCAP file: %s", pcap_path)
    parsed_packets: list[ParsedPacket] = []

    def _convert_packet(pkt: Any) -> Optional[ParsedPacket]:
        ts = datetime.fromtimestamp(float(pkt.time), tz=timezone.utc).replace(tzinfo=None)
        length = len(pkt)

        # Unwrap VXLAN (UDP 4789 / 8472) or GRE (IP proto 47) overlay tunnels if present
        if pkt.haslayer(UDP) and int(pkt[UDP].dport) in (4789, 8472):
            vxlan_raw = bytes(pkt[UDP].payload)
            if len(vxlan_raw) > 22:
                inner_eth = Ether(vxlan_raw[8:])
                if inner_eth.haslayer(IP) or inner_eth.haslayer(IPv6) or inner_eth.haslayer(ARP):
                    pkt = inner_eth
        elif pkt.haslayer(IP) and int(getattr(pkt[IP], "proto", 0) or 0) == 47:
            gre_inner = pkt[IP].payload
            if gre_inner.haslayer(IP) or gre_inner.haslayer(IPv6):
                pkt = gre_inner

        src_mac = ""
        dst_mac = ""
        if pkt.haslayer(Ether):
            eth = pkt[Ether]
            src_mac = str(getattr(eth, "src", "") or "").lower()
            dst_mac = str(getattr(eth, "dst", "") or "").lower()

        if pkt.haslayer(ARP):
            arp_layer = pkt[ARP]
            op = int(getattr(arp_layer, "op", 0))
            hwsrc = str(getattr(arp_layer, "hwsrc", "")).lower() or src_mac
            hwdst = str(getattr(arp_layer, "hwdst", "")).lower() or dst_mac
            psrc = str(getattr(arp_layer, "psrc", "0.0.0.0"))
            pdst = str(getattr(arp_layer, "pdst", "0.0.0.0"))
            return ParsedPacket(
                timestamp=ts,
                src_ip=psrc,
                dst_ip=pdst,
                src_port=0,
                dst_port=0,
                protocol="ARP",
                length=length,
                flags=f"op={op};hwsrc={hwsrc};hwdst={hwdst}",
                payload=b"",
                raw=None,
                src_mac=hwsrc,
                dst_mac=hwdst,
            )

        has_v4 = pkt.haslayer(IP)
        has_v6 = not has_v4 and pkt.haslayer(IPv6)
        if not has_v4 and not has_v6:
            return None

        if has_v4:
            ip_layer = pkt[IP]
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
            ttl = int(getattr(ip_layer, "ttl", 0) or 0)
        else:
            ip_layer = pkt[IPv6]
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
            ttl = int(getattr(ip_layer, "hlim", 0) or 0)

        src_port = 0
        dst_port = 0
        protocol = "OTHER"
        flags = ""
        payload = b""
        tcp_window = 0
        tcp_seq = 0
        tcp_ack = 0

        if pkt.haslayer(TCP):
            tcp_layer = pkt[TCP]
            protocol = "TCP"
            src_port = int(tcp_layer.sport)
            dst_port = int(tcp_layer.dport)
            flags = str(tcp_layer.flags)
            tcp_window = int(getattr(tcp_layer, "window", 0) or 0)
            tcp_seq = int(getattr(tcp_layer, "seq", 0) or 0)
            tcp_ack = int(getattr(tcp_layer, "ack", 0) or 0)
            raw_pay = bytes(tcp_layer.payload)
            if raw_pay:
                if has_v4:
                    ip_len = int(getattr(ip_layer, "len", 0) or 0)
                    ihl = int(getattr(ip_layer, "ihl", 5) or 5) * 4
                    dataofs = int(getattr(tcp_layer, "dataofs", 5) or 5) * 4
                    if ip_len >= ihl + dataofs:
                        payload = raw_pay[: ip_len - ihl - dataofs]
                    elif not isinstance(tcp_layer.payload, Padding):
                        payload = raw_pay
                elif not isinstance(tcp_layer.payload, Padding):
                    payload = raw_pay
        elif pkt.haslayer(UDP):
            udp_layer = pkt[UDP]
            protocol = "UDP"
            src_port = int(udp_layer.sport)
            dst_port = int(udp_layer.dport)
            raw_pay = bytes(udp_layer.payload)
            if raw_pay:
                udp_len = int(getattr(udp_layer, "len", 0) or 0)
                if udp_len >= 8:
                    payload = raw_pay[: udp_len - 8]
                elif not isinstance(udp_layer.payload, Padding):
                    payload = raw_pay
        elif pkt.haslayer(ICMP) or (has_v6 and int(getattr(ip_layer, "nh", 0) or 0) == 58):
            protocol = "ICMP"
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)

        keep_raw = pkt if (src_port == 53 or dst_port == 53) else None

        return ParsedPacket(
            timestamp=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            length=length,
            flags=flags,
            payload=payload,
            raw=keep_raw,
            src_mac=src_mac,
            dst_mac=dst_mac,
            ttl=ttl,
            tcp_window=tcp_window,
            tcp_seq=tcp_seq,
            tcp_ack=tcp_ack,
        )

    def _collector(pkt: Any) -> None:
        try:
            parsed = _convert_packet(pkt)
            if parsed is not None:
                parsed_packets.append(parsed)
        except Exception as exc:
            logger.warning("Skipping malformed packet: %s", exc)

    try:
        if bpf_filter and bpf_filter.strip():
            filter_str = bpf_filter.strip()
            logger.info("Applying BPF filter '%s' to %s", filter_str, pcap_path)
            devnull = os.open(os.devnull, os.O_WRONLY)
            old_stderr = os.dup(2)
            try:
                try:
                    os.dup2(devnull, 2)
                    sniff(
                        offline=pcap_path,
                        filter=filter_str,
                        store=False,
                        prn=_collector,
                    )
                finally:
                    os.dup2(old_stderr, 2)
                    os.close(old_stderr)
                    os.close(devnull)
            except Exception as exc:
                err_msg = str(exc)
                if "filter expression" in err_msg.lower() or "syntax error" in err_msg.lower():
                    raise ValueError(f"Invalid BPF filter expression '{filter_str}': {err_msg}") from exc
                raise
        else:
            with PcapReader(pcap_path) as reader:
                for idx, pkt in enumerate(reader):
                    try:
                        parsed = _convert_packet(pkt)
                        if parsed is not None:
                            parsed_packets.append(parsed)
                    except Exception as exc:
                        logger.warning("Skipping malformed packet #%d: %s", idx, exc)
    except (FileNotFoundError, ValueError):
        raise
    except Exception as exc:
        logger.error("Failed to read PCAP %s: %s", pcap_path, exc)
        raise

    parsed_packets.sort(key=lambda p: p.timestamp)
    logger.info("Parsed %d IP/ARP packets from %s", len(parsed_packets), pcap_path)
    return parsed_packets
