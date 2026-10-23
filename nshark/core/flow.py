"""Bidirectional network flow reconstruction engine."""

from __future__ import annotations

import logging
from nshark.core.models import Flow, ParsedPacket

logger = logging.getLogger(__name__)


def _normalize_flow_key(
    src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: str
) -> tuple[str, str, int, str, int]:
    """Return a canonical flow ID and normalized endpoints so bidirectional packets group together."""
    ep1 = (src_ip, src_port)
    ep2 = (dst_ip, dst_port)
    if ep1 <= ep2:
        low_ip, low_port = ep1
        high_ip, high_port = ep2
    else:
        low_ip, low_port = ep2
        high_ip, high_port = ep1

    flow_id = f"{low_ip}:{low_port}-{high_ip}:{high_port}-{protocol}"
    return flow_id, low_ip, low_port, high_ip, high_port


def reconstruct_flows(packets: list[ParsedPacket]) -> list[Flow]:
    """Group parsed packets into bidirectional Flow objects.

    The initiator of the first packet in the flow is recorded as `src_ip`/`src_port`.

    Args:
        packets: Chronologically ordered list of ParsedPacket objects.

    Returns:
        List of reconstructed Flow instances.
    """
    flows_by_id: dict[str, Flow] = {}

    for pkt in packets:
        if pkt.protocol == "ARP":
            continue
        flow_id, _, _, _, _ = _normalize_flow_key(
            pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port, pkt.protocol
        )

        if flow_id not in flows_by_id:
            flows_by_id[flow_id] = Flow(
                flow_id=flow_id,
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip,
                src_port=pkt.src_port,
                dst_port=pkt.dst_port,
                protocol=pkt.protocol,
                start_time=pkt.timestamp,
                end_time=pkt.timestamp,
            )

        flow = flows_by_id[flow_id]
        flow.packets.append(pkt)

        if flow.start_time is None or pkt.timestamp < flow.start_time:
            flow.start_time = pkt.timestamp
        if flow.end_time is None or pkt.timestamp > flow.end_time:
            flow.end_time = pkt.timestamp

        if pkt.src_ip == flow.src_ip and pkt.src_port == flow.src_port:
            flow.bytes_sent += pkt.length
        else:
            flow.bytes_received += pkt.length

    flows = list(flows_by_id.values())
    logger.info("Reconstructed %d unique flows from %d packets", len(flows), len(packets))
    return flows
