"""Passive Host & Asset Inventory Profiler (IP, MAC/Vendor, Hostname, OS, Banners, Open Services)."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
import ipaddress
import re
from typing import Optional

from nshark.core.models import ParsedPacket
from nshark.detectors.lateral_movement import parse_ntlmssp_auth

# Common OUI (first 3 bytes of MAC) -> Vendor name
OUI_VENDORS: dict[str, str] = {
    "00:0c:29": "VMware",
    "00:50:56": "VMware",
    "00:05:69": "VMware",
    "00:1c:14": "VMware",
    "08:00:27": "VirtualBox",
    "0a:00:27": "VirtualBox",
    "52:54:00": "QEMU / KVM",
    "00:15:5d": "Microsoft Hyper-V",
    "00:16:3e": "Xen / AWS",
    "02:42:ac": "Docker Container",
    "00:1b:21": "Intel",
    "00:1e:67": "Intel",
    "dc:fb:48": "Intel",
    "00:25:b3": "Hewlett Packard",
    "3c:d9:2b": "Hewlett Packard",
    "00:14:22": "Dell",
    "f8:b1:56": "Dell",
    "00:1a:a0": "Dell",
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi",
    "00:00:0c": "Cisco",
    "00:1b:d5": "Cisco",
    "00:24:14": "Cisco",
    "00:05:85": "Juniper Networks",
    "00:1c:73": "Arista Networks",
    "00:09:0f": "Fortinet",
    "00:1b:17": "Palo Alto Networks",
    "f0:9f:c2": "Ubiquiti",
    "78:8a:20": "Ubiquiti",
    "00:17:f2": "Apple",
    "3c:07:54": "Apple",
    "a4:83:e7": "Apple",
    "bc:d0:74": "Apple",
    "00:e0:4c": "Realtek",
    "54:e1:ad": "Lenovo",
    "00:11:32": "Synology",
    "ac:cc:8e": "Axis Communications",
}

WELL_KNOWN_SERVICES: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    69: "tftp",
    80: "http",
    88: "kerberos",
    110: "pop3",
    135: "msrpc",
    139: "netbios",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "smb",
    502: "modbus",
    636: "ldaps",
    1433: "mssql",
    1883: "mqtt",
    3306: "mysql",
    3389: "rdp",
    5060: "sip",
    5432: "postgres",
    5900: "vnc",
    5985: "winrm",
    5986: "winrm-ssl",
    6379: "redis",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
}

HTTP_SERVER_RE = re.compile(r"^Server:\s*([^\r\n]+)", re.IGNORECASE | re.MULTILINE)


@dataclass
class HostProfile:
    """Discovered network host asset profile."""

    ip: str
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    domain: str = ""
    os_guess: str = "Unknown"
    services: list[str] = field(default_factory=list)
    packets_sent: int = 0
    bytes_sent: int = 0


def lookup_mac_vendor(mac: str) -> str:
    """Resolve a MAC address prefix to a hardware/hypervisor vendor."""
    if not mac or len(mac) < 8:
        return ""
    prefix = mac.lower()[:8]
    return OUI_VENDORS.get(prefix, "")


def _is_private_or_local(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_link_local
    except ValueError:
        return False


def _decode_netbios_name(encoded: bytes) -> str:
    """Decode a 32-byte first-level encoded NetBIOS name (RFC 1002)."""
    if len(encoded) < 32:
        return ""
    chars: list[int] = []
    for i in range(0, 30, 2):
        hi = encoded[i] - ord("A")
        lo = encoded[i + 1] - ord("A")
        if 0 <= hi <= 15 and 0 <= lo <= 15:
            chars.append((hi << 4) | lo)
        else:
            return ""
    raw = bytes(chars).decode("ascii", errors="ignore").strip()
    return re.sub(r"[^\x21-\x7e]", "", raw)


def _extract_dns_style_name(payload: bytes) -> Optional[str]:
    """Extract query name from LLMNR (5355) or mDNS (5353) packet."""
    if len(payload) < 16:
        return None
    idx = 12
    labels: list[str] = []
    while idx < len(payload):
        length = payload[idx]
        if length == 0:
            break
        if length > 63 or idx + 1 + length > len(payload):
            return None
        lbl = payload[idx + 1 : idx + 1 + length].decode("ascii", errors="ignore")
        if lbl:
            labels.append(lbl)
        idx += 1 + length
    if not labels:
        return None
    name = ".".join(labels)
    if name.endswith(".local"):
        name = name[:-6]
    return name if re.match(r"^[A-Za-z0-9._-]+$", name) else None


def profile_hosts(packets: list[ParsedPacket]) -> list[HostProfile]:
    """Build passive asset inventory profiles for hosts seen in the capture."""
    hosts: dict[str, dict] = defaultdict(
        lambda: {
            "mac": "",
            "hostname": "",
            "domain": "",
            "os_signals": set(),
            "ttl_samples": [],
            "syn_windows": [],
            "ports": set(),
            "banners": {},
            "packets_sent": 0,
            "bytes_sent": 0,
        }
    )

    for pkt in packets:
        src = pkt.src_ip
        dst = pkt.dst_ip
        if not src or src in ("0.0.0.0", "255.255.255.255", "::"):
            continue

        h_src = hosts[src]
        h_src["packets_sent"] += 1
        h_src["bytes_sent"] += pkt.length

        # Ensure destination host entry also exists if private/unicast
        if dst and dst not in ("0.0.0.0", "255.255.255.255", "::") and not dst.startswith(("224.", "239.", "ff0")):
            _ = hosts[dst]

        # 1. Ethernet & ARP MAC extraction
        if pkt.src_mac and pkt.src_mac not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            if pkt.protocol == "ARP" or _is_private_or_local(src) or not h_src["mac"]:
                h_src["mac"] = pkt.src_mac
        if pkt.dst_mac and pkt.dst_mac not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            if dst and _is_private_or_local(dst) and not hosts[dst]["mac"]:
                hosts[dst]["mac"] = pkt.dst_mac

        if pkt.protocol == "ARP" and pkt.flags:
            kv = dict(item.split("=", 1) for item in pkt.flags.split(";") if "=" in item)
            hwsrc = kv.get("hwsrc", "").lower()
            if hwsrc and hwsrc not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                h_src["mac"] = hwsrc

        # 1b. Passive TTL + TCP SYN Window collection (p0f-style)
        if pkt.ttl > 0 and len(h_src["ttl_samples"]) < 10:
            h_src["ttl_samples"].append(pkt.ttl)
        if pkt.protocol == "TCP" and "S" in pkt.flags and pkt.tcp_window > 0 and len(h_src["syn_windows"]) < 10:
            h_src["syn_windows"].append(pkt.tcp_window)

        # 2. Active server port detection
        if pkt.protocol == "TCP":
            if "S" in pkt.flags and "A" in pkt.flags and pkt.src_port in WELL_KNOWN_SERVICES:
                h_src["ports"].add(pkt.src_port)
            elif pkt.dst_port in WELL_KNOWN_SERVICES and pkt.payload:
                hosts[dst]["ports"].add(pkt.dst_port)
            elif pkt.src_port in WELL_KNOWN_SERVICES and pkt.payload:
                h_src["ports"].add(pkt.src_port)
        elif pkt.protocol == "UDP":
            if pkt.dst_port in WELL_KNOWN_SERVICES:
                hosts[dst]["ports"].add(pkt.dst_port)
            if pkt.src_port in WELL_KNOWN_SERVICES:
                h_src["ports"].add(pkt.src_port)

        payload = pkt.payload
        if not payload:
            continue

        # 3. NTLMSSP Workstation, Domain, and Windows OS signals
        ntlm = parse_ntlmssp_auth(payload)
        if ntlm:
            wks = ntlm.get("workstation", "")
            dom = ntlm.get("domain", "")
            if wks and wks.upper() not in ("WORKSTATION", "NULL"):
                h_src["hostname"] = wks
            if dom:
                h_src["domain"] = dom
            h_src["os_signals"].add("Windows")

        if pkt.src_port in (445, 139, 135, 3389) or pkt.dst_port in (445, 139):
            if b"\xfeSMB" in payload or b"\xffSMB" in payload:
                if pkt.src_port in (445, 139):
                    h_src["os_signals"].add("Windows")
                else:
                    hosts[dst]["os_signals"].add("Windows")

        # 4. Kerberos Domain Controller & Realm identification
        if pkt.src_port == 88 or pkt.dst_port == 88:
            dc_ip = pkt.src_ip if pkt.src_port == 88 else pkt.dst_ip
            hosts[dc_ip]["os_signals"].add("Windows Server (Active Directory DC)")
            hosts[dc_ip]["ports"].add(88)
            for m in re.finditer(rb"\x1b([\x02-\x30])", payload):
                ln = m.group(1)[0]
                st = m.end()
                if st + ln <= len(payload):
                    val = payload[st : st + ln].decode("ascii", errors="ignore")
                    if "." in val and val.isupper():
                        hosts[dc_ip]["domain"] = val
                        h_src["domain"] = h_src["domain"] or val

        # 5. NetBIOS Name Service (UDP 137)
        if pkt.protocol == "UDP" and (pkt.src_port == 137 or pkt.dst_port == 137) and len(payload) >= 46:
            if payload[12] == 0x20:
                nb_name = _decode_netbios_name(payload[13:45])
                if nb_name and not h_src["hostname"]:
                    h_src["hostname"] = nb_name

        # 6. LLMNR (UDP 5355) & mDNS (UDP 5353) responses
        if pkt.protocol == "UDP" and pkt.src_port in (5353, 5355) and len(payload) >= 16:
            if payload[2] & 0x80:
                name = _extract_dns_style_name(payload)
                if name and not h_src["hostname"]:
                    h_src["hostname"] = name

        # 7. DHCP Option 12 (Host Name) on UDP 67/68
        if pkt.protocol == "UDP" and pkt.dst_port in (67, 68) and len(payload) > 240:
            magic = payload.find(b"\x63\x82\x53\x63")
            if magic >= 0:
                opt_idx = magic + 4
                while opt_idx + 2 < len(payload):
                    opt_code = payload[opt_idx]
                    if opt_code == 255:
                        break
                    if opt_code == 0:
                        opt_idx += 1
                        continue
                    opt_len = payload[opt_idx + 1]
                    if opt_code == 12 and opt_idx + 2 + opt_len <= len(payload):
                        dhcp_host = payload[opt_idx + 2 : opt_idx + 2 + opt_len].decode("ascii", errors="ignore").strip()
                        if dhcp_host:
                            h_src["hostname"] = dhcp_host
                        break
                    opt_idx += 2 + opt_len

        # 8. HTTP User-Agent / Server OS fingerprinting & SSH / FTP / SMTP Banners
        if b"User-Agent:" in payload or b"Server:" in payload or payload.startswith((b"SSH-", b"220 ")):
            text = payload[:512].decode("latin-1", errors="ignore")
            if "Windows NT" in text or "Microsoft-IIS" in text:
                h_src["os_signals"].add("Windows")
            elif "Macintosh" in text or "Mac OS X" in text:
                h_src["os_signals"].add("macOS")
            elif "Linux" in text or "Ubuntu" in text or "Debian" in text:
                h_src["os_signals"].add("Linux")

            srv_m = HTTP_SERVER_RE.search(text)
            if srv_m and pkt.src_port in (80, 443, 8000, 8080, 8443):
                h_src["banners"][pkt.src_port] = srv_m.group(1).strip()[:28]

            if text.startswith("SSH-"):
                ssh_ver = text.split("\n", 1)[0].strip()
                if pkt.src_port == 22:
                    h_src["banners"][22] = ssh_ver.replace("SSH-2.0-", "")[:24]
                if "Ubuntu" in ssh_ver or "Debian" in ssh_ver or "OpenSSH" in ssh_ver:
                    h_src["os_signals"].add("Linux / Unix")

    profiles: list[HostProfile] = []
    for ip, info in hosts.items():
        if info["packets_sent"] == 0 and not info["ports"] and not info["os_signals"]:
            continue

        os_signals = info["os_signals"]
        ports = sorted(info["ports"])
        ttl_samples = info["ttl_samples"]
        max_ttl = max(ttl_samples) if ttl_samples else 0
        syn_windows = info["syn_windows"]

        if "Windows Server (Active Directory DC)" in os_signals or (88 in ports and 445 in ports):
            os_guess = "Windows Server (Domain Controller)"
        elif "Windows" in os_signals or any(p in ports for p in (135, 139, 445, 3389, 5985)):
            os_guess = "Windows"
        elif "macOS" in os_signals:
            os_guess = "macOS"
        elif "Linux" in os_signals or "Linux / Unix" in os_signals or 22 in ports:
            os_guess = "Linux / Unix"
        elif 64 < max_ttl <= 128:
            os_guess = "Windows"
        elif 0 < max_ttl <= 64:
            if 65535 in syn_windows:
                os_guess = "macOS / BSD"
            else:
                os_guess = "Linux / Unix"
        elif max_ttl > 128:
            os_guess = "Network Appliance / Cisco"
        else:
            os_guess = "Unknown"

        mac = info["mac"]
        vendor = lookup_mac_vendor(mac)
        banners = info["banners"]
        services: list[str] = []
        for p in ports:
            base_svc = f"{p}/{WELL_KNOWN_SERVICES.get(p, 'tcp')}"
            if p in banners:
                base_svc = f"{base_svc} ({banners[p]})"
            services.append(base_svc)

        profiles.append(
            HostProfile(
                ip=ip,
                mac=mac,
                vendor=vendor,
                hostname=info["hostname"],
                domain=info["domain"],
                os_guess=os_guess,
                services=services,
                packets_sent=info["packets_sent"],
                bytes_sent=info["bytes_sent"],
            )
        )

    def _sort_key(hp: HostProfile) -> tuple[int, int, str]:
        try:
            is_priv = 0 if ipaddress.ip_address(hp.ip).is_private else 1
        except ValueError:
            is_priv = 1
        return (is_priv, -len(hp.services), hp.ip)

    profiles.sort(key=_sort_key)
    return profiles
