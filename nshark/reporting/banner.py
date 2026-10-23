"""Animated NSHARK ASCII/Block-Art Banner and Live Tactical HUD."""

from __future__ import annotations

import os
import sys
import time
from typing import Any, Optional

from rich.columns import Columns
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from nshark import __version__
from nshark.core.models import Alert, ParsedPacket, Severity

SHARK_ART_LINES: list[tuple[str, str]] = [
    ("                               ▄▄", "bold #00ffff"),
    ("                             ▄███", "bold #00f0ff"),
    ("                           ▄█████               ▄▄▄▄▄▄", "bold #00e0ff"),
    ("                         ▄███████         ▄▄▄████████████▄▄▄", "bold #00ccff"),
    ("                       ▄█████████    ▄▄▄███████████████████████▄▄", "bold #00b8ff"),
    ("    ▄▄▄              ▄███████████▄▄█████████████████████████████████▄▄", "bold #00a0ff"),
    ("     ▀███▄▄        ▄██████████████████████████████████████▀▀▀▀██████████▄", "bold #0088ff"),
    ("       ▀█████▄▄  ▄███████████████████████████████████████  ▄▄  ▀█████████▌", "bold #0074ee"),
    ("         ▀███████████████████████████████████████████████  ▀▀ ▄████████▀", "bold #0060dd"),
    (" ~^~^~^~   ▄████████████████████████████████████████████████████████▀  ~^~^~", "bold #0050cc"),
    (" 01001110 ▄███▀▀      ▀▀███████████████████████▀▀▀▀████████████▀▀▀  01010011", "bold #0040aa"),
    ("         ██▀              ▀▀█████████████▀▀▀         ▀██████▀", "#003588"),
    ("                              ▀▀██████▀▀               ▀███", "#002b6e"),
    ("                                  ▀▀                     ▀", "#002055"),
]

LOGO_LINES: list[str] = [
    " ███╗   ██╗███████╗██╗  ██╗ █████╗ ██████╗ ██╗  ██╗",
    " ████╗  ██║██╔════╝██║  ██║██╔══██╗██╔══██╗██║ ██╔╝",
    " ██╔██╗ ██║███████╗███████║███████║██████╔╝█████╔╝",
    " ██║╚██╗██║╚════██║██╔══██║██╔══██║██╔══██╗██╔═██╗",
    " ██║ ╚████║███████║██║  ██║██║  ██║██║  ██║██║  ██╗",
    " ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝",
]


def _style_shark_line(raw: str, base_style: str) -> Text:
    """Apply multi-tone highlights (waves, binary, glowing eye) to a shark art line."""
    line = Text()
    if "~^~" in raw:
        parts = raw.split("  ")
        for idx, part in enumerate(parts):
            if idx > 0:
                line.append("  ")
            if "~^~" in part:
                line.append(part, style="bold bright_cyan")
            else:
                line.append(part, style=base_style)
        return line

    if "01001110" in raw:
        left_idx = raw.find("01001110") + len("01001110")
        right_idx = raw.find("01010011")
        line.append(raw[:left_idx], style="dim bright_green")
        line.append(raw[left_idx:right_idx], style=base_style)
        line.append(raw[right_idx:], style="dim bright_green")
        return line

    if "  ▄▄  " in raw or "  ▀▀ " in raw:
        marker = "  ▄▄  " if "  ▄▄  " in raw else "  ▀▀ "
        before, after = raw.split(marker, 1)
        line.append(before, style=base_style)
        line.append(marker, style="bold #ff1e56")
        line.append(after, style=base_style)
        return line

    line.append(raw, style=base_style)
    return line


def _style_logo_line(raw: str) -> Text:
    """Colorize solid blocks vs 3D box-drawing shadow characters."""
    text = Text()
    for ch in raw:
        if ch == "█":
            text.append(ch, style="bold #00f5ff")
        elif ch in "╔╗╚╝║═":
            text.append(ch, style="bold #0066cc")
        else:
            text.append(ch)
    return text


def build_banner(config: Optional[dict[str, Any]] = None) -> Text:
    """Assemble the full NSHARK block-art + typography banner (fits <= 78 cols)."""
    enrich_cfg = (config or {}).get("enrichment", {})
    feeds = [
        ("VT", bool(enrich_cfg.get("virustotal", {}).get("api_key"))),
        ("AbuseIPDB", bool(enrich_cfg.get("abuseipdb", {}).get("api_key"))),
        ("Shodan", bool(enrich_cfg.get("shodan", {}).get("api_key"))),
        ("OTX", bool(enrich_cfg.get("otx", {}).get("api_key"))),
    ]

    out = Text()
    for raw, style in SHARK_ART_LINES:
        out.append_text(_style_shark_line(raw, style))
        out.append("\n")

    out.append("\n")

    right_info: list[Text] = [
        Text.assemble(
            ("  v", "bold #00f5ff"),
            (f"{__version__}", "bold #00f5ff"),
            (" // ", "dim bright_white"),
            ("APEX PCAP ENGINE", "bold bright_cyan"),
        ),
        Text("  Fast PCAP Analysis & Threat Intel", style="bold bright_white"),
        Text("  ─────────────────────────────────", style="dim cyan"),
        Text.assemble(
            ("  [DET] ", "bold bright_cyan"),
            ("12 Behavioral Modules", "bright_white"),
        ),
        Text.assemble(
            ("  [EXT] ", "bold bright_cyan"),
            ("IOC · DNS · HTTP · Carve", "bright_white"),
        ),
    ]

    cti_line = Text("  [CTI] ", style="bold bright_cyan")
    for idx, (name, active) in enumerate(feeds):
        if idx > 0:
            cti_line.append("·", style="dim")
        cti_line.append(name, style="bright_green" if active else "bright_white")
    right_info.append(cti_line)

    for i, logo_raw in enumerate(LOGO_LINES):
        out.append_text(_style_logo_line(logo_raw.ljust(51)))
        if i < len(right_info):
            out.append_text(right_info[i])
        out.append("\n")

    return out


def print_banner(
    console: Console,
    config: Optional[dict[str, Any]] = None,
    animate: bool = True,
) -> None:
    """Print the NSHARK banner with an optional fast fin-slice & scanline reveal."""
    if os.environ.get("NSHARK_NO_BANNER") == "1":
        return

    is_tty = console.is_terminal and sys.stdout.isatty()
    if animate and is_tty:
        width = 54
        frames = 10
        try:
            with Live(console=console, refresh_per_second=60, transient=True) as live:
                for step in range(frames):
                    pos = int((step / max(1, frames - 1)) * width)
                    wave_left = "~^" * (pos // 2)
                    wave_right = "~^" * ((width - pos) // 2)
                    frame = Text()
                    frame.append("\n")
                    frame.append(" " * pos + "   ▄▄\n", style="bold #00ffff")
                    frame.append(" " * pos + "  ▄███\n", style="bold #00e0ff")
                    frame.append(" " * pos + " ▄█████\n", style="bold #00b8ff")
                    frame.append(f" {wave_left}", style="bold bright_cyan")
                    frame.append("▄████████▄", style="bold #0088ff")
                    frame.append(f"{wave_right}\n", style="dim cyan")
                    frame.append(
                        " " + "01001110 " * ((pos // 9) + 1),
                        style="dim bright_green",
                    )
                    live.update(frame)
                    time.sleep(0.018)
        except Exception:
            pass

    console.print(build_banner(config), no_wrap=True, overflow="ignore", crop=False)


class LiveAnalysisHUD:
    """Real-time animated tactical HUD while NSHARK analyzes a PCAP."""

    DETECTOR_LABELS: list[tuple[str, str]] = [
        ("PortScanDetector", "Port Scan (T1046)"),
        ("BruteForceDetector", "Brute Force (T1110)"),
        ("BeaconingDetector", "C2 Beaconing (T1071)"),
        ("DNSTunnelDetector", "DNS Tunnel (T1048)"),
        ("ExfiltrationDetector", "Exfiltration (T1041)"),
        ("CleartextCredsDetector", "Cleartext Creds"),
        ("PostExploitationDetector", "Web Enum / RCE / Shell"),
        ("TLSAnalysisDetector", "TLS / JA3 (T1573)"),
        ("ARPSpoofDetector", "ARP Spoofing (T1557)"),
        ("LateralMovementDetector", "Lateral Move (T1021)"),
    ]

    def __init__(self, console: Console, pcap_file: str, bpf_filter: Optional[str] = None) -> None:
        self.console = console
        self.pcap_file = os.path.basename(pcap_file)
        self.bpf_filter = bpf_filter
        self.start_time = time.monotonic()
        self.phase = "Parsing packet capture..."
        self.total_packets = 0
        self.total_flows = 0
        self.proto_counts: dict[str, int] = {"TCP": 0, "UDP": 0, "DNS": 0, "HTTP": 0}
        self.detector_state: dict[str, tuple[str, int]] = {
            cls_name: ("queued", 0) for cls_name, _ in self.DETECTOR_LABELS
        }
        self.intercepts: list[Alert] = []
        self.steps_done = 0
        self.total_steps = len(self.DETECTOR_LABELS) + 3

    def set_packets(self, packets: list[ParsedPacket], total_flows: int) -> None:
        """Update packet and protocol telemetry."""
        self.total_packets = len(packets)
        self.total_flows = total_flows
        tcp = udp = dns = http = 0
        for pkt in packets:
            if pkt.protocol == "TCP":
                tcp += 1
                if pkt.src_port in (80, 8080, 8000, 8443) or pkt.dst_port in (80, 8080, 8000, 8443):
                    http += 1
            elif pkt.protocol == "UDP":
                udp += 1
                if pkt.src_port == 53 or pkt.dst_port == 53:
                    dns += 1
        self.proto_counts = {"TCP": tcp, "UDP": udp, "DNS": dns, "HTTP": http}
        self.steps_done = 1

    def mark_detector_running(self, cls_name: str) -> None:
        self.detector_state[cls_name] = ("running", 0)
        self.phase = f"Running {cls_name}..."

    def mark_detector_done(self, cls_name: str, alerts: list[Alert]) -> None:
        self.detector_state[cls_name] = ("done", len(alerts))
        self.steps_done += 1
        for alert in alerts:
            if alert.severity in (Severity.CRITICAL, Severity.HIGH) or len(self.intercepts) < 5:
                self.intercepts.append(alert)

    def set_phase(self, phase: str, advance: bool = True) -> None:
        self.phase = phase
        if advance:
            self.steps_done = min(self.total_steps, self.steps_done + 1)

    def _bar(self, ratio: float, width: int = 14, color: str = "bright_cyan") -> Text:
        filled = max(0, min(width, int(round(ratio * width))))
        bar = Text()
        bar.append("█" * filled, style=f"bold {color}")
        bar.append("░" * (width - filled), style="dim")
        return bar

    def render(self) -> Panel:
        elapsed = time.monotonic() - self.start_time
        pct = min(1.0, self.steps_done / max(1, self.total_steps))

        left = Table.grid(padding=(0, 1))
        left.add_column(style="bold bright_cyan", width=9)
        left.add_column(width=26)

        left.add_row("Target", Text(self.pcap_file[:24], style="bold bright_white"))
        if self.bpf_filter:
            left.add_row("Filter", Text(self.bpf_filter[:24], style="bold bright_yellow"))
        left.add_row(
            "Traffic",
            Text(f"{self.total_packets:,} pkts | {self.total_flows:,} flows", style="bright_green"),
        )
        prog_line = Text()
        prog_line.append_text(self._bar(pct, width=12, color="#00f5ff"))
        prog_line.append(f" {int(pct * 100):>3}% ({elapsed:.1f}s)", style="bold bright_white")
        left.add_row("Progress", prog_line)
        left.add_row("Status", Text(self.phase[:25], style="italic bright_yellow"))
        left.add_row("PROTO", Text("DISTRIBUTION", style="dim"))

        denom = max(1, self.total_packets)
        for proto, color in [("TCP", "bright_cyan"), ("UDP", "bright_blue"), ("DNS", "bright_magenta"), ("HTTP", "bright_green")]:
            count = self.proto_counts.get(proto, 0)
            ratio = count / denom if self.total_packets else 0.0
            row = Text()
            row.append_text(self._bar(ratio, width=12, color=color))
            row.append(f" {int(ratio * 100):>3}%", style="white")
            left.add_row(proto, row)

        right = Table.grid(padding=(0, 1))
        right.add_column(no_wrap=True)
        right.add_column(width=21, no_wrap=True)
        right.add_column(width=7, justify="right", no_wrap=True)

        for cls_name, label in self.DETECTOR_LABELS:
            state, hits = self.detector_state.get(cls_name, ("queued", 0))
            if state == "done":
                badge = Text("[✓]", style="bold bright_green" if hits == 0 else "bold bright_red")
                hit_txt = (
                    Text(f"{hits} hit{'s' if hits != 1 else ''}", style="bold bright_red")
                    if hits > 0
                    else Text("clean", style="dim green")
                )
                lbl_style = "bright_white"
            elif state == "running":
                badge = Text("[»]", style="bold bright_yellow")
                hit_txt = Text("scan", style="bold bright_yellow")
                lbl_style = "bold bright_yellow"
            else:
                badge = Text("[·]", style="dim")
                hit_txt = Text("wait", style="dim")
                lbl_style = "dim"
            right.add_row(badge, Text(label[:21], style=lbl_style), hit_txt)

        top_grid = Table.grid(padding=(0, 1))
        top_grid.add_column()
        top_grid.add_column()
        top_grid.add_row(
            Panel(left, title="[bold #00f5ff]SONAR TELEMETRY[/]", border_style="bright_cyan", width=38),
            Panel(right, title="[bold #00f5ff]DETECTION MATRIX[/]", border_style="bright_cyan", width=37),
        )

        intercept_lines = Text()
        if self.intercepts:
            for idx, alert in enumerate(self.intercepts[-4:]):
                if idx > 0:
                    intercept_lines.append("\n")
                sev = alert.severity.value.upper()
                sev_style = "bold red" if alert.severity == Severity.CRITICAL else "red"
                target = (
                    f"{alert.source_ip} -> {alert.destination_ip}"
                    if alert.destination_ip
                    else alert.source_ip
                )
                intercept_lines.append(" ⚡ ", style="bold bright_yellow")
                intercept_lines.append(f"[{sev}] ", style=sev_style)
                intercept_lines.append(
                    f"{alert.detection_type.value.replace('_', ' ').title()}",
                    style="bold bright_white",
                )
                intercept_lines.append(f"  {target} ", style="bright_cyan")
                intercept_lines.append(f"({alert.confidence}%)", style="bold yellow")
        else:
            intercept_lines.append("  Scanning packet streams for threat signatures...", style="dim")

        intercept_panel = Panel(
            intercept_lines,
            title="[bold bright_red]LIVE INTERCEPTS[/]",
            border_style="red" if self.intercepts else "dim cyan",
            width=76,
        )

        return Panel(
            Group(top_grid, intercept_panel),
            title=f"[bold #00f5ff]NSHARK v{__version__} // Fast PCAP Analysis & Threat Intel[/]",
            border_style="#00f5ff",
            expand=False,
        )
