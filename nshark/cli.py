"""Main Click CLI entrypoint for NSHARK."""

from __future__ import annotations

import ipaddress
import logging
import os
import sys
from typing import Any, Optional

import click
from dotenv import load_dotenv
from rich.console import Console
from rich.live import Live
from rich.table import Table
import yaml

from nshark import __version__
from nshark.core.flow import reconstruct_flows
from nshark.core.models import AnalysisReport, FPTolerance, IOC, IOCType
from nshark.core.parser import parse_pcap
from nshark.detectors import ALL_DETECTORS
from nshark.enrichment import EnrichmentHub, GeoIPEnricher, VirusTotalEnricher
from nshark.exporters.csv_export import export_csv
from nshark.exporters.misp import export_misp, save_misp
from nshark.exporters.stix import export_stix, save_stix
from nshark.extractors.dns_logger import extract_dns_timeline
from nshark.extractors.file_carver import carve_files
from nshark.extractors.hash_extractor import extract_hashes
from nshark.extractors.host_profiler import profile_hosts
from nshark.extractors.http_decoder import decode_http_sessions
from nshark.extractors.ioc_extractor import extract_iocs
from nshark.mapping.attack import map_all
from nshark.reporting.banner import LiveAnalysisHUD, print_banner
from nshark.reporting.console import print_report
from nshark.reporting.json_report import generate_json, save_json
from nshark.scoring.engine import ScoringEngine

console = Console()

DEFAULT_CONFIG_TEMPLATE = """# NSHARK Configuration
enrichment:
  virustotal:
    api_key: ""
    rate_limit: 4
  abuseipdb:
    api_key: ""
    rate_limit: 60
  shodan:
    api_key: ""
    rate_limit: 1
  otx:
    api_key: ""
    rate_limit: 100
cache:
  enabled: true
  ttl_hours: 24
  db_path: "~/.nshark/cache.db"
geoip:
  db_path: ""
detection:
  port_scan:
    min_ports: 20
    time_window_seconds: 60
  brute_force:
    min_attempts: 10
  beaconing:
    min_beacons: 10
    jitter_tolerance: 0.15
  dns_tunneling:
    entropy_threshold: 3.5
    min_query_length: 30
    min_txt_ratio: 0.3
  exfiltration:
    upload_ratio_threshold: 3.0
    min_bytes: 1048576
reporting:
  default_format: "console"
  min_confidence: 70
workers: 5
"""


def load_config(config_path: Optional[str] = None) -> dict[str, Any]:
    """Load configuration from YAML and environment variables."""
    load_dotenv()
    load_dotenv(os.path.expanduser("~/.nshark/.env"))
    load_dotenv(os.path.expanduser("~/.env"))

    cfg: dict[str, Any] = yaml.safe_load(DEFAULT_CONFIG_TEMPLATE) or {}
    candidate_paths = (
        [config_path]
        if config_path
        else [
            "config.yaml",
            os.path.expanduser("~/.nshark/config.yaml"),
            "/etc/nshark/config.yaml",
        ]
    )

    for path in candidate_paths:
        if path and os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    loaded = yaml.safe_load(fh)
                    if isinstance(loaded, dict):
                        cfg.update(loaded)
                break
            except Exception as exc:
                logging.warning("Failed to load config %s: %s", path, exc)

    enrich_cfg = cfg.setdefault("enrichment", {})
    env_map = {
        "virustotal": "VT_API_KEY",
        "abuseipdb": "ABUSEIPDB_KEY",
        "shodan": "SHODAN_API_KEY",
        "otx": "OTX_API_KEY",
    }
    for provider, env_var in env_map.items():
        env_val = os.environ.get(env_var, "").strip()
        if env_val:
            enrich_cfg.setdefault(provider, {})["api_key"] = env_val

    return cfg


def _detect_ioc_type(val: str) -> IOCType:
    try:
        ipaddress.ip_address(val)
        return IOCType.IP
    except ValueError:
        pass
    clean = val.strip()
    if clean.startswith(("http://", "https://")):
        return IOCType.URL
    if len(clean) == 64 and all(c in "0123456789abcdefABCDEF" for c in clean):
        return IOCType.HASH_SHA256
    if len(clean) == 32 and all(c in "0123456789abcdefABCDEF" for c in clean):
        return IOCType.HASH_MD5
    return IOCType.DOMAIN


MAIN_HELP = """\
Usage: nshark <command> [options] <pcap>

TRIAGE:
  analyze <pcap>           Run all detectors, score alerts, map to MITRE ATT&CK
  hashes <pcap>            Extract Hashcat-ready NetNTLMv2/v1 & Kerberos hashes
  hosts <pcap>             Passive asset inventory (IP, MAC vendor, OS, ports)
  iocs <pcap>              Extract IPs, domains, URLs, emails, user agents
  carve <pcap>             Pull files out of HTTP traffic and hash them
INSPECT:
  dns <pcap>               DNS query timeline with DGA / tunneling labels
  http <pcap>              HTTP requests, decoded payloads, suspicious patterns
THREAT INTEL:
  enrich <ip|domain|file>  Check reputation on VT, AbuseIPDB, Shodan, OTX
  export <pcap>            Write IOCs as STIX 2.1, MISP, or CSV
SETUP:
  config --reset           Write a fresh config.yaml in the current folder

ANALYZE OPTIONS:
  -f, --bpf <expr>             Filter packets with BPF before analysis
  --enrich                     Look up extracted IOCs (needs API keys in .env)
  --fp-tolerance <mode>        strict | balanced (default) | lenient
  --min-confidence <0-100>     Hide alerts below this score (default 70)
  --report <fmt> -o <file>     console (default) | json
  --workers <n>                Threads for reputation lookups (default 5)
GLOBAL OPTIONS:
  --config <file>              Use a custom config.yaml
  -q, --no-banner              Suppress the startup ASCII banner
  -v, --verbose                Debug logging
  --version                    Print version
  -h, --help                   This help. Use 'nshark <command> -h' for more

EXAMPLES:
  nshark analyze capture.pcap
  nshark analyze capture.pcap -f "tcp port 80 or port 445"
  nshark hashes capture.pcap -o hashes.txt
  nshark hosts capture.pcap
"""


class NSharkGroup(click.Group):
    """Click group that prints the NSHARK banner + compact nmap-style help screen."""

    def format_help(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        cfg = (ctx.obj or {}).get("config") or load_config()
        print_banner(console, config=cfg, animate=True)
        formatter.write(MAIN_HELP.format(version=__version__))


@click.group(
    cls=NSharkGroup,
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.version_option(version=__version__, prog_name="NSHARK")
@click.option("--config", "config_path", type=click.Path(), default=None, help="Path to custom config.yaml.")
@click.option("-q", "--no-banner", is_flag=True, help="Suppress startup ASCII banner.")
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging.")
@click.pass_context
def cli(ctx: click.Context, config_path: Optional[str], no_banner: bool, verbose: bool) -> None:
    """NSHARK: Fast PCAP Analysis & Threat Intel CLI."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="[%(levelname)s] %(name)s: %(message)s",
    )
    ctx.ensure_object(dict)
    ctx.obj["config"] = load_config(config_path)
    ctx.obj["no_banner"] = no_banner


@cli.command("analyze", epilog="\b\nExamples:\n  nshark analyze capture.pcap\n  nshark analyze capture.pcap -f 'tcp port 80 or port 445'\n  nshark analyze capture.pcap --fp-tolerance strict\n  nshark analyze capture.pcap --enrich --report json -o report.json")
@click.argument("pcap", type=click.Path(exists=True))
@click.option("-f", "--bpf", "bpf_filter", type=str, default=None, help="Filter packets with BPF expression before analysis.")
@click.option("--enrich", is_flag=True, help="Check extracted IOCs against reputation APIs.")
@click.option("--min-confidence", type=int, default=None, help="Minimum alert confidence (0-100).")
@click.option(
    "--fp-tolerance",
    type=click.Choice(["strict", "balanced", "lenient"], case_sensitive=False),
    default="balanced",
    help="False-positive tolerance preset.",
)
@click.option(
    "--report",
    "report_format",
    type=click.Choice(["console", "json"], case_sensitive=False),
    default="console",
    help="Output report format (console or json).",
)
@click.option("-o", "--output", type=click.Path(), default=None, help="Output file path for json report.")
@click.option("--workers", type=int, default=5, help="Concurrent threads for reputation checks.")
@click.pass_context
def analyze_cmd(
    ctx: click.Context,
    pcap: str,
    bpf_filter: Optional[str],
    enrich: bool,
    min_confidence: Optional[int],
    fp_tolerance: str,
    report_format: str,
    output: Optional[str],
    workers: int,
) -> None:
    """Run triage pipeline on a PCAP file."""
    cfg = ctx.obj["config"]
    no_banner = ctx.obj.get("no_banner", False)
    preset = FPTolerance(fp_tolerance.lower())
    effective_min_conf = min_confidence if min_confidence is not None else preset.min_confidence

    raw_json_stdout = report_format.lower() == "json" and not output
    show_ui = not raw_json_stdout and not no_banner

    if show_ui:
        print_banner(console, config=cfg, animate=True)

    hud = LiveAnalysisHUD(console, pcap, bpf_filter=bpf_filter)
    enrichment_results = []
    geo_info = []

    try:
        if show_ui:
            with Live(hud.render(), console=console, refresh_per_second=20, transient=True) as live:
                packets = parse_pcap(pcap, bpf_filter=bpf_filter)
                flows = reconstruct_flows(packets)
                hud.set_packets(packets, len(flows))
                live.update(hud.render())

                duration = (
                    (packets[-1].timestamp - packets[0].timestamp).total_seconds()
                    if len(packets) >= 2
                    else 0.0
                )

                raw_alerts = []
                for detector_cls in ALL_DETECTORS:
                    cls_name = detector_cls.__name__
                    hud.mark_detector_running(cls_name)
                    live.update(hud.render())
                    detector = detector_cls()
                    found = detector.analyze(packets, flows, cfg)
                    raw_alerts.extend(found)
                    hud.mark_detector_done(cls_name, found)
                    live.update(hud.render())

                hud.mark_detector_running("_correlate")
                hud.set_phase("Correlating multi-stage alerts & MITRE ATT&CK...")
                live.update(hud.render())
                mapped_alerts = map_all(raw_alerts)
                scorer = ScoringEngine()
                scored_alerts = scorer.score_and_correlate(
                    mapped_alerts,
                    fp_tolerance=preset,
                    min_confidence_override=min_confidence,
                )
                timeline = scorer.build_timeline(scored_alerts)
                hud.mark_detector_done("_correlate", [])

                hud.mark_detector_running("_extract")
                hud.set_phase("Extracting IOCs, DNS timeline, and HTTP sessions...")
                live.update(hud.render())
                iocs = extract_iocs(packets, flows)
                dns_queries = extract_dns_timeline(packets)
                http_sessions = decode_http_sessions(packets, flows)
                hud.mark_detector_done("_extract", [])
                live.update(hud.render())

                if enrich:
                    hud.set_phase(f"Enriching {len(iocs)} IOCs across Threat Intel feeds...")
                    live.update(hud.render())
                    hub = EnrichmentHub(cfg, workers=workers)
                    enrichment_results = hub.enrich_iocs(iocs)
                    geo_enricher = GeoIPEnricher(
                        db_path=str(cfg.get("geoip", {}).get("db_path", "")),
                        allow_online_fallback=True,
                    )
                    public_ips = [i.value for i in iocs if i.type == IOCType.IP][:25]
                    geo_info = [geo_enricher.lookup(ip) for ip in public_ips]
        else:
            packets = parse_pcap(pcap, bpf_filter=bpf_filter)
            flows = reconstruct_flows(packets)
            duration = (
                (packets[-1].timestamp - packets[0].timestamp).total_seconds()
                if len(packets) >= 2
                else 0.0
            )
            raw_alerts = []
            for detector_cls in ALL_DETECTORS:
                detector = detector_cls()
                raw_alerts.extend(detector.analyze(packets, flows, cfg))
            mapped_alerts = map_all(raw_alerts)
            scorer = ScoringEngine()
            scored_alerts = scorer.score_and_correlate(
                mapped_alerts,
                fp_tolerance=preset,
                min_confidence_override=min_confidence,
            )
            timeline = scorer.build_timeline(scored_alerts)
            iocs = extract_iocs(packets, flows)
            dns_queries = extract_dns_timeline(packets)
            http_sessions = decode_http_sessions(packets, flows)
            if enrich:
                hub = EnrichmentHub(cfg, workers=workers)
                enrichment_results = hub.enrich_iocs(iocs)
                geo_enricher = GeoIPEnricher(
                    db_path=str(cfg.get("geoip", {}).get("db_path", "")),
                    allow_online_fallback=True,
                )
                public_ips = [i.value for i in iocs if i.type == IOCType.IP][:25]
                geo_info = [geo_enricher.lookup(ip) for ip in public_ips]
    except ValueError as exc:
        console.print(f"[bold #ff0055][!] Error:[/] {exc}")
        sys.exit(1)

    report = AnalysisReport(
        pcap_file=pcap,
        total_packets=len(packets),
        total_flows=len(flows),
        duration_seconds=duration,
        alerts=scored_alerts,
        iocs=iocs,
        dns_queries=dns_queries,
        http_sessions=http_sessions,
        geo_info=geo_info,
        timeline=timeline,
        enrichment_results=enrichment_results,
        bpf_filter=bpf_filter,
    )

    if report_format.lower() == "json":
        if output:
            save_json(report, output)
            console.print(f"[green][+] JSON report written to {output}[/]")
        else:
            click.echo(generate_json(report))
    else:
        print_report(report, min_confidence=effective_min_conf, packets=packets, flows=flows)
        if output:
            save_json(report, output)
            console.print(f"[green][+] JSON report saved to {output}[/]")


@cli.command("iocs", epilog="\b\nExamples:\n  nshark iocs capture.pcap\n  nshark iocs capture.pcap --type ip,domain --enrich")
@click.argument("pcap", type=click.Path(exists=True))
@click.option("--type", "ioc_types", default=None, help="Comma-separated filter: ip,domain,url,email,user_agent.")
@click.option("--enrich", is_flag=True, help="Enrich extracted IPs and domains.")
@click.pass_context
def iocs_cmd(ctx: click.Context, pcap: str, ioc_types: Optional[str], enrich: bool) -> None:
    """Extract deduplicated IOCs from a PCAP."""
    cfg = ctx.obj["config"]
    if not ctx.obj.get("no_banner", False):
        print_banner(console, config=cfg, animate=True)

    with console.status("[bold bright_cyan]Extracting IOCs from packet capture...[/]", spinner="dots"):
        packets = parse_pcap(pcap)
        iocs = extract_iocs(packets)
        if ioc_types:
            wanted = {t.strip().lower() for t in ioc_types.split(",") if t.strip()}
            iocs = [i for i in iocs if i.type.value in wanted]
        if enrich:
            hub = EnrichmentHub(cfg)
            hub.enrich_iocs(iocs)

    table = Table(title=f"[*] Extracted IOCs ({len(iocs)})", header_style="bold bright_cyan", show_lines=True, expand=True)
    table.add_column("Type", no_wrap=True)
    table.add_column("Indicator Value", ratio=2, min_width=20)
    table.add_column("First Seen", no_wrap=True)
    table.add_column("Context", ratio=1, min_width=14)

    for ioc in iocs:
        ts_str = ioc.first_seen.strftime("%H:%M:%S") if ioc.first_seen else "-"
        table.add_row(ioc.type.value.upper(), ioc.value, ts_str, ioc.context)
    console.print(table)


@cli.command("carve", epilog="\b\nExamples:\n  nshark carve capture.pcap\n  nshark carve capture.pcap -o ./files --hash-check")
@click.argument("pcap", type=click.Path(exists=True))
@click.option("-o", "--output-dir", type=click.Path(), default="./carved_files", help="Output folder for carved files.")
@click.option("--hash-check", is_flag=True, help="Check carved SHA-256 hashes against VirusTotal.")
@click.pass_context
def carve_cmd(ctx: click.Context, pcap: str, output_dir: str, hash_check: bool) -> None:
    """Carve transferred files from HTTP streams and compute MD5/SHA-256 hashes."""
    cfg = ctx.obj["config"]
    if not ctx.obj.get("no_banner", False):
        print_banner(console, config=cfg, animate=True)

    with console.status("[bold bright_cyan]Carving transferred payloads from HTTP streams...[/]", spinner="dots"):
        packets = parse_pcap(pcap)
        flows = reconstruct_flows(packets)
        carved = carve_files(packets, flows, output_dir=output_dir)

    vt_key = str(cfg.get("enrichment", {}).get("virustotal", {}).get("api_key", ""))
    vt = VirusTotalEnricher(api_key=vt_key) if hash_check and vt_key else None

    table = Table(title=f"[*] Carved Files ({len(carved)})", header_style="bold bright_cyan", show_lines=True, expand=True)
    table.add_column("Filename", min_width=14, no_wrap=True)
    table.add_column("Type", min_width=16)
    table.add_column("Size", justify="right", no_wrap=True)
    table.add_column("SHA-256", ratio=2, min_width=24)
    if vt:
        table.add_column("VT Status", no_wrap=True)

    for cf in carved:
        row = [cf.filename, cf.file_type, f"{cf.size:,} B", cf.sha256]
        if vt:
            res = vt.enrich_hash(cf.sha256)
            verdict = "MALICIOUS" if res.malicious else "CLEAN"
            row.append(f"{verdict} ({res.details.get('detection_ratio', '0/0')})")
        table.add_row(*row)
    console.print(table)


@cli.command("enrich", epilog="\b\nExamples:\n  nshark enrich 45.33.32.156\n  nshark enrich evil.example.com --providers vt,otx\n  nshark enrich iocs.txt\n  cat ips.txt | nshark enrich --stdin")
@click.argument("target", required=False)
@click.option("--stdin", "use_stdin", is_flag=True, help="Read IOC list from standard input.")
@click.option("--providers", default=None, help="Comma-separated providers: vt,abuseipdb,shodan,otx.")
@click.option("--workers", type=int, default=5, help="Worker thread count.")
@click.pass_context
def enrich_cmd(
    ctx: click.Context,
    target: Optional[str],
    use_stdin: bool,
    providers: Optional[str],
    workers: int,
) -> None:
    """Check reputation for a single IP/domain, file of IOCs, or stdin."""
    cfg = ctx.obj["config"]
    if not ctx.obj.get("no_banner", False):
        print_banner(console, config=cfg, animate=True)

    iocs: list[IOC] = []

    if use_stdin:
        raw_targets = [line.strip() for line in sys.stdin if line.strip()]
        iocs = [IOC(type=_detect_ioc_type(t), value=t) for t in raw_targets]
    elif target:
        if os.path.isfile(target):
            is_pcap = False
            lower_target = target.lower()
            if lower_target.endswith((".pcap", ".pcapng", ".cap")):
                is_pcap = True
            else:
                try:
                    with open(target, "rb") as bf:
                        magic = bf.read(4)
                        if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a", b"\x4d\x3c\x2b\x1a"):
                            is_pcap = True
                except Exception:
                    pass

            if is_pcap:
                console.print(f"[bold bright_cyan][*] Detected packet capture:[/] extracting indicators from [bold white]{os.path.basename(target)}[/]...")
                packets = parse_pcap(target)
                iocs = extract_iocs(packets)
                iocs = [
                    i for i in iocs
                    if i.type in (IOCType.IP, IOCType.DOMAIN, IOCType.HASH_SHA256, IOCType.HASH_MD5)
                ]
                if not iocs:
                    console.print("[yellow][!] No external IOCs (public IPs, domains, or hashes) found in this capture to enrich.[/]")
                    console.print("[dim]Tip: Use 'nshark analyze <pcap>' for full attack and behavioral detection.[/]")
                    return
            else:
                try:
                    with open(target, "r", encoding="utf-8", errors="replace") as fh:
                        raw_targets = [
                            line.strip()
                            for line in fh
                            if line.strip() and not line.strip().startswith("#")
                        ]
                        iocs = [IOC(type=_detect_ioc_type(t), value=t) for t in raw_targets]
                except Exception as exc:
                    console.print(f"[bold #ff0055][!] Error reading file:[/] {exc}")
                    return
        else:
            raw_targets = [target.strip()]
            iocs = [IOC(type=_detect_ioc_type(t), value=t) for t in raw_targets]
    else:
        raise click.UsageError("Provide a TARGET (IP, domain, hash, file, or PCAP) or use --stdin.")
    prov_list = [p.strip() for p in providers.split(",")] if providers else None

    with console.status(f"[bold bright_cyan]Querying Threat Intel feeds for {len(iocs)} indicator(s)...[/]", spinner="dots"):
        hub = EnrichmentHub(cfg, selected_providers=prov_list, workers=workers)
        results = hub.enrich_iocs(iocs)

    table = Table(title=f"[*] Reputation Results ({len(results)})", header_style="bold bright_magenta", show_lines=True, expand=True)
    table.add_column("Indicator", no_wrap=True)
    table.add_column("Provider", no_wrap=True)
    table.add_column("Verdict", no_wrap=True)
    table.add_column("Score", justify="right", no_wrap=True)
    table.add_column("Details", ratio=2, min_width=20)

    for r in results:
        verdict = "MALICIOUS" if r.malicious else ("ERROR" if r.error else "CLEAN")
        detail_str = r.error if r.error else ", ".join(f"{k}={v}" for k, v in list(r.details.items())[:4])
        table.add_row(r.ip_or_domain, r.provider, verdict, f"{r.confidence_score}%", detail_str)
    console.print(table)


@cli.command("export", epilog="\b\nExamples:\n  nshark export capture.pcap --format stix -o iocs.json\n  nshark export capture.pcap --format misp -o event.json\n  nshark export capture.pcap --format csv -o iocs.csv")
@click.argument("pcap", type=click.Path(exists=True))
@click.option(
    "--format",
    "export_format",
    type=click.Choice(["stix", "csv", "misp"], case_sensitive=False),
    default="stix",
    help="Export format (stix, csv, misp).",
)
@click.option("-o", "--output", type=click.Path(), required=True, help="Output file path.")
@click.pass_context
def export_cmd(ctx: click.Context, pcap: str, export_format: str, output: str) -> None:
    """Export extracted IOCs and detections in STIX 2.1, CSV, or MISP format."""
    cfg = ctx.obj["config"]
    if not ctx.obj.get("no_banner", False):
        print_banner(console, config=cfg, animate=True)

    with console.status("[bold bright_cyan]Extracting IOCs and building SIEM export...[/]", spinner="dots"):
        packets = parse_pcap(pcap)
        flows = reconstruct_flows(packets)
        iocs = extract_iocs(packets)

        alerts = []
        for det_cls in ALL_DETECTORS:
            alerts.extend(det_cls().analyze(packets, flows, cfg))
        alerts = map_all(alerts)

        fmt = export_format.lower()
        if fmt == "stix":
            bundle = export_stix(iocs, alerts)
            save_stix(bundle, output)
        elif fmt == "csv":
            export_csv(iocs, output)
        elif fmt == "misp":
            event = export_misp(iocs, event_info=f"NSHARK Triage: {os.path.basename(pcap)}")
            save_misp(event, output)

    console.print(f"[green][+] Exported {len(iocs)} IOCs ({fmt.upper()}) to {output}[/]")


@cli.command("dns", epilog="\b\nExamples:\n  nshark dns capture.pcap\n  nshark dns capture.pcap --suspicious-only")
@click.argument("pcap", type=click.Path(exists=True))
@click.option("--suspicious-only", is_flag=True, help="Show only non-legit DNS queries.")
@click.pass_context
def dns_cmd(ctx: click.Context, pcap: str, suspicious_only: bool) -> None:
    """Display DNS query timeline."""
    cfg = ctx.obj["config"]
    if not ctx.obj.get("no_banner", False):
        print_banner(console, config=cfg, animate=True)

    with console.status("[bold bright_cyan]Analyzing DNS query timeline...[/]", spinner="dots"):
        packets = parse_pcap(pcap)
        queries = extract_dns_timeline(packets)
        if suspicious_only:
            queries = [q for q in queries if q.category != "legit"]

    table = Table(title=f"[*] DNS Queries ({len(queries)})", header_style="bold bright_cyan", show_lines=True, expand=True)
    table.add_column("Time", no_wrap=True)
    table.add_column("Source IP", no_wrap=True)
    table.add_column("Type", no_wrap=True)
    table.add_column("Query Name", ratio=2, min_width=22)
    table.add_column("Response", ratio=1, min_width=12)
    table.add_column("Category", no_wrap=True)

    for q in queries:
        cat_style = (
            "bold red"
            if q.category in ("tunneling", "dga", "known_malicious")
            else ("yellow" if q.category == "suspicious" else "green")
        )
        table.add_row(
            q.timestamp.strftime("%H:%M:%S"),
            q.source_ip,
            q.query_type,
            q.query_name,
            q.response or "-",
            f"[{cat_style}]{q.category.upper()}[/]",
        )
    console.print(table)


@cli.command("http", epilog="\b\nExamples:\n  nshark http capture.pcap")
@click.argument("pcap", type=click.Path(exists=True))
@click.option("--decode-payloads", is_flag=True, default=True, help="Decode URL/Base64 payloads.")
@click.pass_context
def http_cmd(ctx: click.Context, pcap: str, decode_payloads: bool) -> None:
    """Reconstruct HTTP sessions and inspect requests."""
    cfg = ctx.obj["config"]
    if not ctx.obj.get("no_banner", False):
        print_banner(console, config=cfg, animate=True)

    with console.status("[bold bright_cyan]Reconstructing HTTP streams...[/]", spinner="dots"):
        packets = parse_pcap(pcap)
        flows = reconstruct_flows(packets)
        sessions = decode_http_sessions(packets, flows, decode_payloads=decode_payloads)

    table = Table(title=f"[*] HTTP Sessions ({len(sessions)})", header_style="bold bright_cyan", show_lines=True, expand=True)
    table.add_column("Time", no_wrap=True)
    table.add_column("Source IP", no_wrap=True)
    table.add_column("Method", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("URL", ratio=2, min_width=24)
    table.add_column("Notes", ratio=1, min_width=14)

    for s in sessions:
        flag = f"[bold red][!] {s.suspicion_reason}[/]" if s.suspicious else "[green]OK[/]"
        table.add_row(
            s.timestamp.strftime("%H:%M:%S"),
            s.source_ip,
            s.method,
            str(s.status_code or "-"),
            s.url[:80],
            flag,
        )
    console.print(table)


@cli.command("hashes", epilog="\b\nExamples:\n  nshark hashes capture.pcap\n  nshark hashes capture.pcap -o hashes.txt")
@click.argument("pcap", type=click.Path(exists=True))
@click.option("-o", "--output", type=click.Path(), default=None, help="Write raw Hashcat lines to file.")
@click.pass_context
def hashes_cmd(ctx: click.Context, pcap: str, output: Optional[str]) -> None:
    """Extract crackable Hashcat-ready NetNTLMv2/v1 & Kerberos hashes."""
    cfg = ctx.obj["config"]
    if not ctx.obj.get("no_banner", False):
        print_banner(console, config=cfg, animate=True)

    with console.status("[bold bright_cyan]Extracting authentication hashes...[/]", spinner="dots"):
        packets = parse_pcap(pcap)
        captured = extract_hashes(packets)

    if not captured:
        console.print("[yellow][*] No crackable NetNTLM or Kerberos RC4 hashes found in capture.[/]")
        return

    table = Table(
        title=f"[!] Captured Crackable Hashes ({len(captured)})",
        header_style="bold bright_cyan",
        show_lines=True,
        expand=True,
    )
    table.add_column("Type", width=10)
    table.add_column("Mode", width=8, style="bold yellow")
    table.add_column("Account", ratio=1, min_width=14, style="bold bright_white")
    table.add_column("Source -> Target", ratio=1, min_width=15)
    table.add_column("Hash Preview", ratio=2, min_width=20)

    for h in captured:
        short_type = (
            "KRB5-TGS"
            if "TGS-REP" in h.hash_type
            else ("KRB5-ASREP" if "AS-REP" in h.hash_type else h.hash_type)
        )
        acct = f"{h.domain}\\{h.username}".strip("\\")
        preview = h.hash_string[:44] + "..." if len(h.hash_string) > 44 else h.hash_string
        table.add_row(
            short_type,
            f"-m {h.hashcat_mode}",
            acct,
            f"{h.source_ip} -> {h.target_ip}",
            preview,
        )
    console.print(table)

    if output:
        with open(output, "w", encoding="utf-8") as fh:
            for h in captured:
                fh.write(h.hash_string + "\n")
        console.print(f"\n[bold green][+] Saved {len(captured)} raw Hashcat hash(es) to {output}[/]")
        modes = sorted({str(h.hashcat_mode) for h in captured})
        console.print(f"[dim]    Run: hashcat -m {modes[0]} {output} wordlist.txt[/]")
    else:
        console.print("\n[bold bright_cyan][*] Raw Hashcat Strings (use -o hashes.txt to save):[/]")
        for h in captured:
            click.echo(h.hash_string)


@cli.command("hosts", epilog="\b\nExamples:\n  nshark hosts capture.pcap")
@click.argument("pcap", type=click.Path(exists=True))
@click.pass_context
def hosts_cmd(ctx: click.Context, pcap: str) -> None:
    """Discover hosts, MAC vendors, hostnames, OS, and open services."""
    cfg = ctx.obj["config"]
    if not ctx.obj.get("no_banner", False):
        print_banner(console, config=cfg, animate=True)

    with console.status("[bold bright_cyan]Profiling network hosts and services...[/]", spinner="dots"):
        packets = parse_pcap(pcap)
        profiles = profile_hosts(packets)

    table = Table(
        title=f"[*] Host & Asset Inventory ({len(profiles)} hosts)",
        header_style="bold bright_cyan",
        show_lines=True,
        expand=True,
    )
    table.add_column("IP Address", no_wrap=True, style="bold bright_white")
    table.add_column("MAC / Vendor", ratio=1, min_width=14)
    table.add_column("Hostname / Domain", ratio=1, min_width=14)
    table.add_column("OS Fingerprint", ratio=1, min_width=14)
    table.add_column("Active Services", ratio=1, min_width=14)

    for hp in profiles:
        mac_str = hp.mac or "-"
        if hp.vendor:
            mac_str = f"{hp.mac}\n[dim]({hp.vendor})[/]"
        host_str = hp.hostname or "-"
        if hp.domain:
            host_str = f"{hp.hostname} [cyan]({hp.domain})[/]".strip()
        os_style = "bold bright_cyan" if "Domain Controller" in hp.os_guess else ("bright_green" if hp.os_guess != "Unknown" else "dim")
        svc_str = ", ".join(hp.services[:6]) if hp.services else "-"
        table.add_row(
            hp.ip,
            mac_str,
            host_str,
            f"[{os_style}]{hp.os_guess}[/]",
            svc_str,
        )
    console.print(table)


@cli.command("config")
@click.option("--reset", is_flag=True, help="Regenerate default config.yaml in current directory.")
def config_cmd(reset: bool) -> None:
    """Manage NSHARK configuration."""
    if reset:
        with open("config.yaml", "w", encoding="utf-8") as fh:
            fh.write(DEFAULT_CONFIG_TEMPLATE)
        console.print("[green][+] Wrote default config.yaml[/]")
    else:
        console.print("Use [bold]nshark config --reset[/] to create a default config.yaml.")


@cli.command("help")
@click.argument("command", required=False)
@click.pass_context
def help_cmd(ctx: click.Context, command: Optional[str]) -> None:
    """Show help for NSHARK or a single command."""
    parent = ctx.parent
    if command:
        sub = cli.get_command(parent, command)
        if sub is None:
            raise click.UsageError(f"Unknown command '{command}'. Run 'nshark help'.")
        with click.Context(sub, info_name=command, parent=parent) as sub_ctx:
            click.echo(sub.get_help(sub_ctx))
    else:
        click.echo(cli.get_help(parent))


def main() -> None:
    """CLI entrypoint."""
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/]")
        sys.exit(130)


if __name__ == "__main__":
    main()
