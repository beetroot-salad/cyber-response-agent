"""Hand-curated MITRE ATT&CK Enterprise technique sample, tagged by tactic.

This is the sampling corpus for the actor menu. Each per-run actor call draws
``MENU_SIZE`` techniques from this list, formats them by tactic, and injects
them into the actor prompt as constraints. The actor selects a coherent subset
in its Section 0 table.

Coverage is intentionally broad rather than exhaustive — roughly 50 techniques
across all 12 ATT&CK Enterprise tactics, weighted toward the patterns most
relevant to Linux/cloud SOC triage. In a mature deployment this list would be
pulled from MITRE's STIX bundle, not hand-maintained.

The corpus is the maintenance surface: add a technique when a real case
exposes a gap; remove one when it produces persistently incoherent menus.
"""
from __future__ import annotations

import random

MENU_SIZE = 12

# (tactic, technique_id, technique_name)
CORPUS: list[tuple[str, str, str]] = [
    # Reconnaissance
    ("Reconnaissance", "T1595.002", "Active Scanning: Vulnerability Scanning"),
    ("Reconnaissance", "T1589.002", "Gather Victim Identity Info: Email Addresses"),
    # Resource Development
    ("Resource Development", "T1583.001", "Acquire Infrastructure: Domains"),
    ("Resource Development", "T1587.001", "Develop Capabilities: Malware"),
    ("Resource Development", "T1588.004", "Obtain Capabilities: Digital Certificates"),
    # Initial Access
    ("Initial Access", "T1190", "Exploit Public-Facing Application"),
    ("Initial Access", "T1133", "External Remote Services"),
    ("Initial Access", "T1078.002", "Valid Accounts: Domain Accounts"),
    ("Initial Access", "T1078.004", "Valid Accounts: Cloud Accounts"),
    ("Initial Access", "T1195.002", "Supply Chain Compromise: Compromise Software Supply Chain"),
    ("Initial Access", "T1199", "Trusted Relationship"),
    ("Initial Access", "T1566.001", "Phishing: Spearphishing Attachment"),
    # Execution
    ("Execution", "T1059.004", "Command and Scripting Interpreter: Unix Shell"),
    ("Execution", "T1053.003", "Scheduled Task/Job: Cron"),
    ("Execution", "T1204.002", "User Execution: Malicious File"),
    # Persistence
    ("Persistence", "T1098.004", "Account Manipulation: SSH Authorized Keys"),
    ("Persistence", "T1543.002", "Create or Modify System Process: Systemd Service"),
    ("Persistence", "T1546.004", "Event Triggered Execution: Unix Shell Configuration"),
    ("Persistence", "T1554", "Compromise Host Software Binary"),
    # Privilege Escalation
    ("Privilege Escalation", "T1068", "Exploitation for Privilege Escalation"),
    ("Privilege Escalation", "T1548.003", "Abuse Elevation Control Mechanism: Sudo and Sudo Caching"),
    ("Privilege Escalation", "T1611", "Escape to Host"),
    # Defense Evasion
    ("Defense Evasion", "T1027.009", "Obfuscated Files or Information: Embedded Payloads"),
    ("Defense Evasion", "T1070.002", "Indicator Removal: Clear Linux or Mac System Logs"),
    ("Defense Evasion", "T1070.006", "Indicator Removal: Timestomp"),
    ("Defense Evasion", "T1222.002", "File and Directory Permissions Modification: Linux/Mac"),
    ("Defense Evasion", "T1562.001", "Impair Defenses: Disable or Modify Tools"),
    ("Defense Evasion", "T1574.006", "Hijack Execution Flow: Dynamic Linker Hijacking"),
    ("Defense Evasion", "T1036.005", "Masquerading: Match Legitimate Resource Name or Location"),
    # Credential Access
    ("Credential Access", "T1003.008", "OS Credential Dumping: /etc/passwd and /etc/shadow"),
    ("Credential Access", "T1552.001", "Unsecured Credentials: Credentials In Files"),
    ("Credential Access", "T1552.004", "Unsecured Credentials: Private Keys"),
    ("Credential Access", "T1556.003", "Modify Authentication Process: Pluggable Authentication Modules"),
    # Discovery
    ("Discovery", "T1018", "Remote System Discovery"),
    ("Discovery", "T1083", "File and Directory Discovery"),
    ("Discovery", "T1518.001", "Software Discovery: Security Software Discovery"),
    # Lateral Movement
    ("Lateral Movement", "T1021.004", "Remote Services: SSH"),
    ("Lateral Movement", "T1570", "Lateral Tool Transfer"),
    ("Lateral Movement", "T1563.001", "Remote Service Session Hijacking: SSH Hijacking"),
    # Collection
    ("Collection", "T1005", "Data from Local System"),
    ("Collection", "T1056.001", "Input Capture: Keylogging"),
    ("Collection", "T1560.001", "Archive Collected Data: Archive via Utility"),
    # Command and Control
    ("Command and Control", "T1071.001", "Application Layer Protocol: Web Protocols"),
    ("Command and Control", "T1071.004", "Application Layer Protocol: DNS"),
    ("Command and Control", "T1090.003", "Proxy: Multi-hop Proxy"),
    ("Command and Control", "T1573.002", "Encrypted Channel: Asymmetric Cryptography"),
    # Exfiltration
    ("Exfiltration", "T1041", "Exfiltration Over C2 Channel"),
    ("Exfiltration", "T1048.003", "Exfiltration Over Alternative Protocol: Unencrypted"),
    ("Exfiltration", "T1567.002", "Exfiltration Over Web Service: Cloud Storage"),
    # Impact
    ("Impact", "T1485", "Data Destruction"),
    ("Impact", "T1486", "Data Encrypted for Impact"),
    ("Impact", "T1496", "Resource Hijacking"),
    ("Impact", "T1565.001", "Data Manipulation: Stored Data Manipulation"),
]


def sample_menu(rng: random.Random, n: int = MENU_SIZE) -> list[tuple[str, str, str]]:
    """Draw ``n`` techniques from the corpus without replacement."""
    return rng.sample(CORPUS, n)


def format_menu(menu: list[tuple[str, str, str]]) -> str:
    """Group ``menu`` entries by tactic for prompt injection."""
    by_tactic: dict[str, list[str]] = {}
    for tactic, tid, name in menu:
        by_tactic.setdefault(tactic, []).append(f"  - {tid} {name}")
    lines: list[str] = []
    for tactic in sorted(by_tactic):
        lines.append(f"{tactic}:")
        lines.extend(by_tactic[tactic])
    return "\n".join(lines)
