"""MITRE ATT&CK automatic technique and tactic mapper for NSHARK alerts."""

from __future__ import annotations

from nshark.core.models import Alert, DetectionType, MITREMapping

ATTACK_MAPPINGS: dict[DetectionType, MITREMapping] = {
    DetectionType.PORT_SCAN: MITREMapping(
        tactic="Discovery",
        technique_id="T1046",
        technique_name="Network Service Discovery",
        url="https://attack.mitre.org/techniques/T1046/",
    ),
    DetectionType.WEB_ENUMERATION: MITREMapping(
        tactic="Reconnaissance",
        technique_id="T1595.003",
        technique_name="Active Scanning: Wordlist Scanning",
        url="https://attack.mitre.org/techniques/T1595/003/",
    ),
    DetectionType.BRUTE_FORCE: MITREMapping(
        tactic="Credential Access",
        technique_id="T1110.001",
        technique_name="Brute Force: Password Guessing",
        url="https://attack.mitre.org/techniques/T1110/001/",
    ),
    DetectionType.CLEARTEXT_CREDENTIALS: MITREMapping(
        tactic="Credential Access",
        technique_id="T1040",
        technique_name="Network Sniffing",
        url="https://attack.mitre.org/techniques/T1040/",
    ),
    DetectionType.COMMAND_INJECTION: MITREMapping(
        tactic="Initial Access",
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        url="https://attack.mitre.org/techniques/T1190/",
    ),
    DetectionType.REVERSE_SHELL: MITREMapping(
        tactic="Execution / Persistence",
        technique_id="T1059.004",
        technique_name="Unix Shell & SSH Authorized Keys",
        url="https://attack.mitre.org/techniques/T1059/004/",
    ),
    DetectionType.C2_BEACONING: MITREMapping(
        tactic="Command and Control",
        technique_id="T1071.001",
        technique_name="Application Layer Protocol: Web Protocols",
        url="https://attack.mitre.org/techniques/T1071/001/",
    ),
    DetectionType.DNS_TUNNELING: MITREMapping(
        tactic="Exfiltration",
        technique_id="T1048.001",
        technique_name="Exfiltration Over Alternative Protocol: DNS",
        url="https://attack.mitre.org/techniques/T1048/001/",
    ),
    DetectionType.DATA_EXFILTRATION: MITREMapping(
        tactic="Exfiltration",
        technique_id="T1041",
        technique_name="Exfiltration Over C2 Channel",
        url="https://attack.mitre.org/techniques/T1041/",
    ),
    DetectionType.TLS_ANOMALY: MITREMapping(
        tactic="Command and Control",
        technique_id="T1573",
        technique_name="Encrypted Channel: Malicious TLS / JA3 Fingerprint",
        url="https://attack.mitre.org/techniques/T1573/",
    ),
    DetectionType.ARP_SPOOFING: MITREMapping(
        tactic="Credential Access",
        technique_id="T1557.002",
        technique_name="Adversary-in-the-Middle: ARP Cache Poisoning",
        url="https://attack.mitre.org/techniques/T1557/002/",
    ),
    DetectionType.LATERAL_MOVEMENT: MITREMapping(
        tactic="Lateral Movement",
        technique_id="T1021.002",
        technique_name="Remote Services: SMB/Windows Admin Shares",
        url="https://attack.mitre.org/techniques/T1021/002/",
    ),
}


def map_alert(alert: Alert) -> Alert:
    """Attach the corresponding MITRE ATT&CK mapping to an Alert."""
    if alert.mitre is None:
        proto = str(alert.details.get("protocol", "")).upper()
        subproto = str(alert.details.get("subprotocol", "")).upper()
        if alert.detection_type == DetectionType.LATERAL_MOVEMENT:
            if "KERBEROS" in proto:
                alert.mitre = MITREMapping(
                    tactic="Credential Access",
                    technique_id="T1558.003",
                    technique_name="Steal or Forge Kerberos Tickets: Kerberoasting",
                    url="https://attack.mitre.org/techniques/T1558/003/",
                )
                return alert
            if "RDP" in proto:
                alert.mitre = MITREMapping(
                    tactic="Lateral Movement",
                    technique_id="T1021.001",
                    technique_name="Remote Services: Remote Desktop Protocol",
                    url="https://attack.mitre.org/techniques/T1021/001/",
                )
                return alert
            if "WINRM" in proto or "WINRM" in subproto:
                alert.mitre = MITREMapping(
                    tactic="Lateral Movement",
                    technique_id="T1021.006",
                    technique_name="Remote Services: Windows Remote Management",
                    url="https://attack.mitre.org/techniques/T1021/006/",
                )
                return alert
        elif alert.detection_type == DetectionType.ARP_SPOOFING and "LLMNR" in proto:
            alert.mitre = MITREMapping(
                tactic="Credential Access",
                technique_id="T1557.001",
                technique_name="Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning",
                url="https://attack.mitre.org/techniques/T1557/001/",
            )
            return alert
        elif alert.detection_type == DetectionType.ARP_SPOOFING and proto == "DHCP":
            alert.mitre = MITREMapping(
                tactic="Credential Access",
                technique_id="T1557.003",
                technique_name="Adversary-in-the-Middle: DHCP Spoofing",
                url="https://attack.mitre.org/techniques/T1557/003/",
            )
            return alert
        elif alert.detection_type == DetectionType.DATA_EXFILTRATION and proto == "ICMP":
            alert.mitre = MITREMapping(
                tactic="Exfiltration",
                technique_id="T1048.003",
                technique_name="Exfiltration Over Alternative Protocol: ICMP",
                url="https://attack.mitre.org/techniques/T1048/003/",
            )
            return alert
        alert.mitre = ATTACK_MAPPINGS.get(alert.detection_type)
    return alert


def map_all(alerts: list[Alert]) -> list[Alert]:
    """Attach MITRE ATT&CK mappings to all alerts in a list."""
    return [map_alert(a) for a in alerts]
