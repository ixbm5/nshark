"""Terminal console reporter for NSHARK."""

from __future__ import annotations

from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from nshark import __version__
from nshark.core.models import AnalysisReport, Flow, ParsedPacket, Severity

SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "bold #ff0055",
    Severity.HIGH: "bold #ff6b00",
    Severity.MEDIUM: "bold #ffd000",
    Severity.LOW: "bold #00e5ff",
    Severity.INFO: "dim",
}


def _fmt_bytes(num_bytes: int) -> str:
    if num_bytes >= 1_048_576:
        return f"{num_bytes / 1_048_576:.2f} MB"
    if num_bytes >= 1024:
        return f"{num_bytes / 1024:.1f} KB"
    return f"{num_bytes} B"


def _confidence_badge(confidence: int) -> Text:
    filled = max(1, min(5, round(confidence / 20)))
    bar = "█" * filled + "░" * (5 - filled)
    if confidence >= 85:
        style = "bold #ff0055"
    elif confidence >= 70:
        style = "bold #ffd000"
    else:
        style = "#00e5ff"
    return Text(f"{bar} {confidence}%", style=style)


def print_report(
    report: AnalysisReport,
    min_confidence: int = 70,
    packets: Optional[list[ParsedPacket]] = None,
    flows: Optional[list[Flow]] = None,
) -> None:
    """Render analysis results to the terminal."""
    console = Console()
    visible_alerts = [a for a in report.alerts if a.confidence >= min_confidence]

    if any(a.severity == Severity.CRITICAL for a in visible_alerts):
        verdict_text = ("CRITICAL THREAT", "bold #ff0055")
    elif visible_alerts:
        verdict_text = (f"{len(visible_alerts)} ALERT(S) DETECTED", "bold #ff6b00")
    else:
        verdict_text = ("NO ATTACK ALERTS", "bold bright_green")

    banner_parts = [
        ("NSHARK ", "bold #00f5ff"),
        (f"v{__version__} // ", "dim bright_white"),
        verdict_text,
        ("\nFile: ", "dim"),
        (f"{report.pcap_file}  |  ", "bold bright_white"),
        (f"Packets: {report.total_packets:,}  |  ", "bright_green"),
        (f"Flows: {report.total_flows:,}  |  ", "bright_blue"),
        (f"Duration: {report.duration_seconds:.1f}s", "bright_yellow"),
    ]
    if report.bpf_filter:
        banner_parts.extend([
            ("  |  ", "dim"),
            ("BPF: ", "dim yellow"),
            (report.bpf_filter, "bold bright_yellow"),
        ])
    banner = Text.assemble(*banner_parts)
    console.print(Panel(banner, border_style="bright_cyan", expand=False))

    console.print(
        f"\n[bold bright_white][!] ALERTS[/] "
        f"({len(visible_alerts)} found, min confidence {min_confidence}%)"
    )

    if visible_alerts:
        alert_table = Table(
            show_header=True,
            show_lines=True,
            header_style="bold bright_cyan",
            expand=True,
        )
        alert_table.add_column("Sev", no_wrap=True)
        alert_table.add_column("Conf", justify="right", no_wrap=True)
        alert_table.add_column("Detection", ratio=1)
        alert_table.add_column("Source -> Target", ratio=1)
        alert_table.add_column("MITRE", no_wrap=True)
        alert_table.add_column("Details", ratio=2)

        for alert in visible_alerts:
            sev_style = SEVERITY_COLORS.get(alert.severity, "white")
            mitre_str = alert.mitre.technique_id if alert.mitre else "-"
            if alert.destination_ip:
                target_txt = Text.assemble(
                    (alert.source_ip, "bold #ff9e00"),
                    (" ──▶ ", "dim"),
                    (alert.destination_ip, "bold #00e5ff"),
                )
            else:
                target_txt = Text(alert.source_ip, style="bold #ff9e00")

            alert_table.add_row(
                Text(alert.severity.value.upper(), style=sev_style),
                _confidence_badge(alert.confidence),
                Text(alert.detection_type.value.replace("_", " ").title(), style="bold bright_white"),
                target_txt,
                Text(mitre_str, style="bold bright_magenta"),
                alert.description,
            )
        console.print(alert_table)
    else:
        console.print("  [green][+] No alerts above threshold.[/]")

    # Traffic, HTTP/DNS & TCP Transport Health Insights
    if flows or report.http_sessions or report.dns_queries or packets:
        console.print("\n[bold bright_white][*] TRAFFIC & NETWORK INSIGHTS[/]")

        if flows:
            top_flows = sorted(
                flows,
                key=lambda f: (f.bytes_sent + f.bytes_received, f.packet_count),
                reverse=True,
            )[:3]
            for fl in top_flows:
                total_b = fl.bytes_sent + fl.bytes_received
                http_match = next(
                    (
                        s
                        for s in report.http_sessions
                        if {s.source_ip, s.destination_ip} == {fl.src_ip, fl.dst_ip}
                    ),
                    None,
                )
                extra = f"  [bright_yellow]{http_match.method} {http_match.url[:70]}[/]" if http_match else ""
                if not extra and fl.protocol == "TCP":
                    # Check for JetDirect (@PJL), STARTTLS, or TLS Certificate summary
                    for p in fl.packets:
                        if b"@PJL" in p.payload:
                            extra = "  [bright_yellow]HP JetDirect Print Job (@PJL)[/]"
                            break
                        if b"STARTTLS" in p.payload.upper():
                            extra = f"  [bright_yellow]STARTTLS Protocol Upgrade (port {min(fl.src_port, fl.dst_port)})[/]"
                            break
                console.print(
                    f"  [bright_cyan]• Flow:[/] [bold #ff9e00]{fl.src_ip}:{fl.src_port}[/] ──▶ "
                    f"[bold #00e5ff]{fl.dst_ip}:{fl.dst_port}[/] "
                    f"[dim]({fl.protocol} · {fl.packet_count:,} pkts · {_fmt_bytes(total_b)})[/]{extra}"
                )

            # Deep TCP Transport Diagnostics (only show detailed per-flow root causes when not a massive port scan)
            if len(flows) <= 50:
                for fl in flows:
                    if fl.protocol != "TCP" or not fl.packets:
                        continue
                    fl_dur = (
                        (fl.end_time - fl.start_time).total_seconds()
                        if fl.start_time and fl.end_time
                        else 0.0
                    )

                    # 1. TCP Zero-Window Stall (win=0)
                    zero_win_pkts = [
                        p
                        for p in fl.packets
                        if p.tcp_window == 0 and "R" not in p.flags and "S" not in p.flags and "F" not in p.flags
                    ]
                    if zero_win_pkts:
                        stalled_host = zero_win_pkts[0].src_ip
                        peer_host = zero_win_pkts[0].dst_ip
                        console.print(
                            f"  [bold #ffd000][!] TCP Zero-Window Stall:[/] [bold]{stalled_host}[/] advertised "
                            f"[bold red]win=0[/] ({len(zero_win_pkts)} packets) to [bold]{peer_host}[/] "
                            f"— receiver buffer full / connection stalled ({fl_dur:.1f}s)"
                        )

                    # 2. TCP Connection Refused (SYN -> RST/ACK with no application data)
                    syn_pkts = [p for p in fl.packets if p.flags == "S"]
                    rst_pkts = [p for p in fl.packets if "R" in p.flags]
                    sa_pkts = [p for p in fl.packets if "S" in p.flags and "A" in p.flags]
                    data_pkts = [p for p in fl.packets if len(p.payload) > 0]
                    if syn_pkts and rst_pkts and not sa_pkts and not data_pkts:
                        client_p = syn_pkts[0]
                        console.print(
                            f"  [bold #ff0055][!] TCP Connection Refused (RST):[/] [bold]{client_p.dst_ip}:{client_p.dst_port}[/] "
                            f"rejected connection from [bold]{client_p.src_ip}[/] with immediate TCP RST/ACK "
                            f"(port {client_p.dst_port} closed or service down)"
                        )

                    # 3. Unanswered TCP SYN / Firewall Drop (SYNs sent, 0 responses from server)
                    if len(syn_pkts) >= 2 and len(fl.packets) == len(syn_pkts):
                        client_p = syn_pkts[0]
                        console.print(
                            f"  [bold #ff6b00][!] Unanswered TCP SYN (Timeout / Firewall Drop):[/] "
                            f"[bold]{client_p.src_ip}[/] sent [bold]{len(syn_pkts)}[/] TCP SYN attempts to "
                            f"[bold]{client_p.dst_ip}:{client_p.dst_port}[/] over {fl_dur:.1f}s with [bold red]0 replies[/]"
                        )

                    # 4. TCP Retransmissions & Low-Window Throttling
                    seen_data_seqs: dict[tuple[str, int, int], int] = {}
                    retrans_count = 0
                    retrans_sender = ""
                    retrans_receiver = ""
                    for p in fl.packets:
                        if len(p.payload) > 0 and p.tcp_seq > 0:
                            skey = (p.src_ip, p.tcp_seq, len(p.payload))
                            seen_data_seqs[skey] = seen_data_seqs.get(skey, 0) + 1
                            if seen_data_seqs[skey] > 1:
                                retrans_count += 1
                                retrans_sender = p.src_ip
                                retrans_receiver = p.dst_ip

                    if retrans_count >= 2:
                        console.print(
                            f"  [bold #ff6b00][!] TCP Retransmissions Detected:[/] [bold]{retrans_sender}[/] "
                            f"retransmitted [bold red]{retrans_count}[/] data segment(s) to [bold]{retrans_receiver}[/] "
                            f"over {fl_dur:.1f}s (unacknowledged data / packet loss)"
                        )

                    # Receiver window collapse: a host's advertised window drops below 1/8 of its own
                    # peak in this flow (relative check avoids false hits on window-scaled sessions)
                    low_win_pkts: list[ParsedPacket] = []
                    if not zero_win_pkts:
                        max_win_by_host: dict[str, int] = {}
                        for p in fl.packets:
                            if "S" not in p.flags and "R" not in p.flags:
                                max_win_by_host[p.src_ip] = max(max_win_by_host.get(p.src_ip, 0), p.tcp_window)
                        for host, peak in max_win_by_host.items():
                            if peak < 1024:
                                continue
                            collapsed = [
                                p
                                for p in fl.packets
                                if p.src_ip == host
                                and 0 < p.tcp_window <= peak // 8
                                and "S" not in p.flags
                                and "R" not in p.flags
                                and "F" not in p.flags
                            ]
                            if len(collapsed) >= 3:
                                low_win_pkts = collapsed
                                break
                    if low_win_pkts:
                        min_w = min(p.tcp_window for p in low_win_pkts)
                        throttled_host = low_win_pkts[0].src_ip
                        peak_w = max(p.tcp_window for p in fl.packets if p.src_ip == throttled_host)
                        console.print(
                            f"  [bold #ffd000][!] TCP Receiver Window Collapse:[/] [bold]{throttled_host}[/] "
                            f"shrank its receive window from {peak_w}B to [bold red]{min_w}B[/] across "
                            f"{len(low_win_pkts)} packets (receiver cannot drain data fast enough)"
                        )

                    # 5. TCP Triple Duplicate ACKs & Fast Retransmission
                    ack_Wait: dict[tuple[str, int], int] = {}
                    last_ack_by_src: dict[str, int] = {}
                    max_dup_acks = 0
                    dup_ack_host = ""
                    dup_ack_seq = 0
                    for p in fl.packets:
                        if len(p.payload) == 0 and p.flags == "A" and p.tcp_ack > 0:
                            if last_ack_by_src.get(p.src_ip) == p.tcp_ack:
                                ack_Wait[(p.src_ip, p.tcp_ack)] = ack_Wait.get((p.src_ip, p.tcp_ack), 1) + 1
                                if ack_Wait[(p.src_ip, p.tcp_ack)] > max_dup_acks:
                                    max_dup_acks = ack_Wait[(p.src_ip, p.tcp_ack)]
                                    dup_ack_host = p.src_ip
                                    dup_ack_seq = p.tcp_ack
                            else:
                                last_ack_by_src[p.src_ip] = p.tcp_ack
                                ack_Wait[(p.src_ip, p.tcp_ack)] = 1

                    if max_dup_acks >= 3:
                        console.print(
                            f"  [bold #ffd000][!] TCP Duplicate ACKs (Fast Retransmission):[/] "
                            f"[bold]{dup_ack_host}[/] sent [bold red]{max_dup_acks}x Duplicate ACKs[/] "
                            f"(stalled at ack={dup_ack_seq}) indicating dropped upstream segment"
                        )

        # 6. DNS Resolution Diagnostics (Unanswered DNS Queries vs NXDOMAIN parsed directly from UDP payload)
        if packets and not visible_alerts:
            dns_req_counts: dict[tuple[str, str], set[str]] = {}
            dns_req_pkt_counts: dict[tuple[str, str], int] = {}
            dns_answered_qnames: set[str] = set()
            dns_nxdomain_qnames: dict[str, str] = {}
            for p in packets:
                if (p.src_port == 53 or p.dst_port == 53) and len(p.payload) >= 17:
                    pay = p.payload
                    qr = (pay[2] >> 7) & 1
                    rcode = pay[3] & 0x0F
                    ancount = (pay[6] << 8) | pay[7]
                    idx = 12
                    labels: list[str] = []
                    while idx < len(pay):
                        ln = pay[idx]
                        if ln == 0:
                            break
                        if ln > 63 or idx + 1 + ln > len(pay):
                            labels = []
                            break
                        labels.append(pay[idx + 1 : idx + 1 + ln].decode("ascii", errors="ignore"))
                        idx += 1 + ln
                    qname = ".".join(labels)
                    if not qname:
                        continue
                    if qr == 0:
                        dns_req_counts.setdefault((p.src_ip, qname), set()).add(p.dst_ip)
                        dns_req_pkt_counts[(p.src_ip, qname)] = dns_req_pkt_counts.get((p.src_ip, qname), 0) + 1
                    else:
                        dns_answered_qnames.add(qname)
                        if rcode == 3 and ancount == 0:
                            dns_nxdomain_qnames[qname] = p.src_ip

            for (client_ip, qname), resolvers in dns_req_counts.items():
                q_cnt = dns_req_pkt_counts.get((client_ip, qname), 1)
                if qname not in dns_answered_qnames:
                    console.print(
                        f"  [bold #ff0055][!] DNS Resolution Timeout (No Response):[/] [bold]{client_ip}[/] "
                        f"sent [bold]{q_cnt}[/] query attempt(s) for [bold]{qname}[/] to resolver(s) "
                        f"[bold]{', '.join(sorted(resolvers))}[/] — [bold red]0 DNS replies received[/]"
                    )
                elif qname in dns_nxdomain_qnames:
                    console.print(
                        f"  [bold #ffd000][!] DNS NXDOMAIN (Non-Existent Domain):[/] Resolver "
                        f"[bold]{dns_nxdomain_qnames[qname]}[/] returned [bold red]NXDOMAIN (Rcode=3)[/] "
                        f"for [bold]{qname}[/]"
                    )

        # 7. TLS Certificate & Mutual-TLS Handshake Summary (when no alerts fired)
        if packets and not visible_alerts:
            import re as _re

            shown_certs: set[str] = set()
            for p in packets:
                if p.protocol == "TCP" and len(p.payload) > 60 and p.payload[0] == 0x16 and p.payload[1] == 0x03:
                    cns: list[str] = []
                    for m_cn in _re.finditer(rb"\x06\x03\x55\x04\x03[\x0c\x13\x14\x16]([\x01-\x40])", p.payload):
                        clen = m_cn.group(1)[0]
                        cstart = m_cn.end()
                        cval = p.payload[cstart : cstart + clen].decode("utf-8", errors="ignore").strip()
                        if cval and cval not in cns:
                            cns.append(cval)
                    if cns:
                        role = "Server" if p.src_port in (443, 8443, 993, 995, 465, 636) else "Client/Peer"
                        cert_sig = f"{p.src_ip}:{','.join(cns[:2])}"
                        if cert_sig not in shown_certs:
                            shown_certs.add(cert_sig)
                            self_signed = " [Self-Signed]" if len(cns) == 1 else ""
                            console.print(
                                f"  [bright_green]• TLS X.509 ({role}):[/] [bold]{p.src_ip}:{p.src_port}[/] "
                                f"presented certificate CN=[bold]{' -> '.join(cns[:3])}[/]{self_signed}"
                            )

        if report.dns_queries and not visible_alerts:
            for dq in report.dns_queries[:3]:
                ans = dq.response if dq.response else "no response"
                console.print(
                    f"  [bright_magenta]• DNS:[/]  {dq.source_ip} queried [bold]{dq.query_name}[/] "
                    f"({dq.query_type}) -> {ans} [{dq.category.upper()}]"
                )

    if report.enrichment_results:
        console.print("\n[bold bright_white][*] REPUTATION RESULTS[/]")
        ti_table = Table(
            show_header=True,
            show_lines=True,
            header_style="bold bright_magenta",
            expand=True,
        )
        ti_table.add_column("IOC", no_wrap=True)
        ti_table.add_column("Source", no_wrap=True)
        ti_table.add_column("Verdict", no_wrap=True)
        ti_table.add_column("Score", justify="right", no_wrap=True)
        ti_table.add_column("Summary", ratio=2, min_width=20)

        for res in report.enrichment_results:
            if res.error:
                verdict = Text("ERROR", style="dim yellow")
                summary = res.error
            elif res.malicious:
                verdict = Text("MALICIOUS", style="bold red")
                summary = ", ".join(f"{k}={v}" for k, v in list(res.details.items())[:4])
            else:
                verdict = Text("CLEAN", style="green")
                summary = ", ".join(f"{k}={v}" for k, v in list(res.details.items())[:4])

            ti_table.add_row(
                res.ip_or_domain,
                res.provider + (" (cached)" if res.cached else ""),
                verdict,
                f"{res.confidence_score}%",
                summary,
            )
        console.print(ti_table)

    if report.geo_info:
        console.print("\n[bold bright_white][*] GEOIP SUMMARY[/]")
        geo_table = Table(show_header=True, show_lines=True, header_style="bold bright_blue")
        geo_table.add_column("IP", width=18)
        geo_table.add_column("Country", width=20)
        geo_table.add_column("City", width=16)
        geo_table.add_column("ASN / Org", width=32)
        geo_table.add_column("Status", width=24)

        for g in report.geo_info:
            status = (
                Text(f"[!] {g.suspicion_reason}", style="bold red")
                if g.is_suspicious
                else Text("OK", style="green")
            )
            asn_str = f"AS{g.asn} {g.org}".strip() if g.asn else g.org
            geo_table.add_row(
                g.ip,
                f"{g.country} ({g.country_code})" if g.country_code else g.country,
                g.city or "-",
                asn_str or "-",
                status,
            )
        console.print(geo_table)

    if report.timeline:
        console.print("\n[bold bright_white][*] ATTACK TIMELINE[/]")
        events = report.timeline[:20]
        base_ts = events[0].timestamp
        for idx, ev in enumerate(events):
            ts_str = ev.timestamp.strftime("%H:%M:%S")
            delta_s = max(0.0, (ev.timestamp - base_ts).total_seconds())
            if len(events) == 1:
                branch = "──●"
            elif idx == 0:
                branch = "╭─●"
            elif idx == len(events) - 1:
                branch = "╰─●"
            else:
                branch = "├─●"
            sev_style = SEVERITY_COLORS.get(ev.severity, "white")
            flow_str = (
                f"[bold #ff9e00]{ev.source_ip}[/] ──▶ [bold #00e5ff]{ev.destination_ip}[/]  "
                if ev.source_ip and ev.destination_ip
                else ""
            )
            console.print(
                f"  [dim]{ts_str}[/] [bright_cyan](+{delta_s:>5.1f}s)[/]  "
                f"[bright_cyan]{branch}[/] [{sev_style}][{ev.severity.value.upper()}][/] "
                f"{flow_str}{ev.description}"
            )
    console.print()
