#!/usr/bin/env python3
"""
Investigation Agent Script

This script is invoked by the orchestrator to investigate a security alert.
It runs in its own directory with access to the Wazuh MCP server.

Usage:
    python investigate.py --ticket-id TICKET-001 --signature-id wazuh-rule-5710 --alert-json '{"srcip": "10.0.1.50", ...}'

The agent will:
1. Load knowledge from /workspace/knowledge/signatures/{signature_id}/
2. Query Wazuh MCP for related events
3. Match against known patterns
4. Return structured JSON findings to stdout
"""

import argparse
import json
import sys
from pathlib import Path

# Knowledge base paths
KNOWLEDGE_DIR = Path("/workspace/knowledge")


def load_signature_knowledge(signature_id: str) -> dict:
    """Load knowledge files for a signature."""
    sig_dir = KNOWLEDGE_DIR / "signatures" / signature_id

    if not sig_dir.exists():
        return {"error": f"Unknown signature: {signature_id}"}

    knowledge = {
        "signature_id": signature_id,
        "rule": None,
        "playbook": None,
        "lessons": None,
        "past_tickets": [],
    }

    # Load rule.md
    rule_file = sig_dir / "rule.md"
    if rule_file.exists():
        knowledge["rule"] = rule_file.read_text()

    # Load playbook.md
    playbook_file = sig_dir / "playbook.md"
    if playbook_file.exists():
        knowledge["playbook"] = playbook_file.read_text()

    # Load lessons.md
    lessons_file = sig_dir / "lessons.md"
    if lessons_file.exists():
        knowledge["lessons"] = lessons_file.read_text()

    # Load past tickets
    past_tickets_dir = sig_dir / "past-tickets"
    if past_tickets_dir.exists():
        for ticket_file in past_tickets_dir.glob("*.json"):
            try:
                knowledge["past_tickets"].append(json.loads(ticket_file.read_text()))
            except json.JSONDecodeError:
                pass

    return knowledge


def investigate(ticket_id: str, signature_id: str, alert_data: dict) -> dict:
    """
    Perform investigation and return findings.

    This is a stub implementation. The real implementation will:
    1. Use Claude Code to analyze the alert
    2. Query Wazuh MCP for context
    3. Match against precedents
    """
    # Load knowledge
    knowledge = load_signature_knowledge(signature_id)

    if "error" in knowledge:
        return {
            "matched_ticket": None,
            "matched_tier": None,
            "conditions_met": 0,
            "conditions_total": 0,
            "evidence_available": False,
            "findings": [knowledge["error"]],
            "reasoning": f"Cannot investigate: {knowledge['error']}",
        }

    # Stub: Simple pattern matching for demonstration
    srcip = alert_data.get("srcip", "")
    srcuser = alert_data.get("srcuser", "")

    findings = []
    matched_ticket = None
    matched_tier = None
    conditions_met = 0
    conditions_total = 3

    # Check if IP is internal (RFC1918)
    is_internal = (
        srcip.startswith("10.")
        or srcip.startswith("192.168.")
        or srcip.startswith("172.16.")
        or srcip.startswith("172.17.")
        or srcip.startswith("172.18.")
        or srcip.startswith("172.19.")
        or srcip.startswith("172.2")
        or srcip.startswith("172.30.")
        or srcip.startswith("172.31.")
    )

    if is_internal:
        findings.append(f"Source IP {srcip} is internal (RFC1918)")
        conditions_met += 1
    else:
        findings.append(f"Source IP {srcip} is EXTERNAL")

    # Check username pattern against past tickets
    monitoring_usernames = ["testuser", "probe", "monitor", "healthcheck", "nagios", "zabbix"]
    if srcuser.lower() in monitoring_usernames:
        findings.append(f"Username '{srcuser}' matches monitoring pattern")
        conditions_met += 1
        if is_internal:
            matched_ticket = "SEC-20240115-001"  # monitoring-probe past ticket
            matched_tier = "gold"

    service_patterns = ["svc-", "backup-", "cron-", "ansible-", "deploy-"]
    if any(srcuser.lower().startswith(p) for p in service_patterns):
        findings.append(f"Username '{srcuser}' matches service account pattern")
        conditions_met += 1
        if is_internal:
            matched_ticket = "SEC-20240120-007"  # service-account past ticket
            matched_tier = "gold"

    # Evidence availability (stub: always true for now)
    evidence_available = True
    findings.append("Evidence gathered from alert data")

    # Build reasoning
    if matched_ticket:
        reasoning = f"Alert matches past ticket {matched_ticket}: {', '.join(findings)}"
    elif not is_internal:
        reasoning = "External IP - requires escalation for potential brute force"
        matched_ticket = "SEC-20240118-003"  # brute-force past ticket
        matched_tier = "gold"
    else:
        reasoning = f"Internal IP but no clear pattern match. Findings: {', '.join(findings)}"

    return {
        "matched_ticket": matched_ticket,
        "matched_tier": matched_tier,
        "conditions_met": conditions_met,
        "conditions_total": conditions_total,
        "evidence_available": evidence_available,
        "findings": findings,
        "reasoning": reasoning,
    }


def main():
    parser = argparse.ArgumentParser(description="Investigation Agent")
    parser.add_argument("--ticket-id", required=True, help="Ticket ID")
    parser.add_argument("--signature-id", required=True, help="Signature ID")
    parser.add_argument("--alert-json", required=True, help="Alert data as JSON string")

    args = parser.parse_args()

    try:
        alert_data = json.loads(args.alert_json)
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"Invalid alert JSON: {e}"}), file=sys.stderr)
        sys.exit(1)

    # Run investigation
    findings = investigate(args.ticket_id, args.signature_id, alert_data)

    # Output findings as JSON
    print(json.dumps(findings))


if __name__ == "__main__":
    main()
