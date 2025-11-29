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
KNOWLEDGE_DIR = Path("/workspace/app/knowledge")


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
            "recommendation": "escalate",
            "matched_ticket": None,
            "matched_tier": None,
            "reasoning": f"Cannot investigate: {knowledge['error']}",
            "evidence": {},
        }

    # Stub: Simple pattern matching for demonstration
    srcip = alert_data.get("srcip", "")
    srcuser = alert_data.get("srcuser", "")

    evidence = {}
    matched_ticket = None
    matched_tier = None
    recommendation = "escalate"  # Default safe

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
        evidence["ip_class"] = "internal:rfc1918"
    else:
        evidence["ip_class"] = "external"

    # Check username pattern against past tickets
    monitoring_usernames = ["testuser", "probe", "monitor", "healthcheck", "nagios", "zabbix"]
    service_patterns = ["svc-", "backup-", "cron-", "ansible-", "deploy-"]

    if srcuser.lower() in monitoring_usernames and is_internal:
        matched_ticket = "SEC-2024-001"
        matched_tier = "gold"
        recommendation = "benign"
        evidence["username_pattern"] = "monitoring_probe"
        reasoning = (
            f"Benign - monitoring probe activity. "
            f"Internal IP ({srcip}), monitoring username ({srcuser}). "
            f"Matches pattern from {matched_ticket}."
        )
    elif any(srcuser.lower().startswith(p) for p in service_patterns) and is_internal:
        matched_ticket = "SEC-2024-004"
        matched_tier = "silver"
        recommendation = "benign"
        evidence["username_pattern"] = "service_account"
        reasoning = (
            f"Benign - service account activity. "
            f"Internal IP ({srcip}), service account ({srcuser}). "
            f"Matches pattern from {matched_ticket}."
        )
    elif not is_internal:
        matched_ticket = "SEC-2024-003"
        matched_tier = "gold"
        recommendation = "escalate"
        evidence["threat_indicator"] = "external_ssh_attempt"
        reasoning = (
            f"Escalate - external IP attempting SSH. "
            f"Source {srcip} is external, username '{srcuser}'. "
            f"Similar to brute force pattern in {matched_ticket}."
        )
    else:
        # Internal but no clear pattern
        recommendation = "escalate"
        reasoning = (
            f"Escalate - no matching pattern. "
            f"Internal IP ({srcip}), username ({srcuser}) does not match known benign patterns."
        )

    return {
        "recommendation": recommendation,
        "matched_ticket": matched_ticket,
        "matched_tier": matched_tier,
        "reasoning": reasoning,
        "evidence": evidence,
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
