"""
Orchestrator Manager - Pure manager that invokes Claude Code agent.

Responsibilities:
- Receive ticket (alert data)
- Invoke Claude Code agent with ticket
- Parse structured JSON response
- Calculate confidence score
- Make routing decision
- Log audit trail to stdout
"""

import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from .confidence import calculate_confidence, get_decision
from .models import AgentFindings, InvestigationResult


# Paths
AGENT_DIR = Path("/workspace/agent/investigation")
KNOWLEDGE_DIR = Path("/workspace/knowledge")


def build_agent_prompt(alert_data: dict, signature_id: str) -> str:
    """
    Build the prompt to send to the investigation agent.

    The agent will:
    1. Read the signature knowledge files
    2. Query Wazuh MCP for related events
    3. Match against precedents
    4. Return structured JSON findings
    """
    return f"""You are a security analyst investigating an alert.

## Alert Data
```json
{json.dumps(alert_data, indent=2)}
```

## Signature ID
{signature_id}

## Instructions

1. **Read the signature knowledge** from `/workspace/knowledge/signatures/{signature_id}/`:
   - `rule.md` - Understand the rule
   - `playbook.md` - Follow investigation steps
   - `lessons.md` - Apply lessons learned
   - `past-tickets/` - Reference similar past cases

2. **Read common knowledge** from `/workspace/knowledge/common/`:
   - `lessons/ip-classification.md` - For IP analysis
   - `utilities/wazuh-queries.md` - For query patterns

3. **Gather evidence** using Wazuh MCP to query:
   - Failed attempts from same source IP (last 5 min)
   - Successful logins from same source IP (last 60 sec)
   - Distinct usernames attempted

4. **Match against patterns** in the playbook

5. **Return ONLY a JSON object** (no other text) with this structure:
```json
{{
  "precedent_matched": "prec-5710-001 or null",
  "precedent_tier": "gold or null",
  "conditions_met": 3,
  "conditions_total": 4,
  "evidence_available": true,
  "findings": ["Finding 1", "Finding 2"],
  "reasoning": "Explanation of match/no-match"
}}
```

Return ONLY the JSON object, no markdown code blocks, no explanation.
"""


def invoke_agent(prompt: str, timeout: int = 120) -> str:
    """
    Invoke Claude Code agent as subprocess.

    Args:
        prompt: The investigation prompt
        timeout: Maximum time in seconds

    Returns:
        Agent's response text
    """
    # Run claude from the agent directory so it picks up the .claude config
    result = subprocess.run(
        ["claude", "-p", prompt, "--output-format", "text"],
        cwd=str(AGENT_DIR),
        capture_output=True,
        text=True,
        timeout=timeout,
    )

    if result.returncode != 0:
        raise RuntimeError(f"Agent failed: {result.stderr}")

    return result.stdout


def parse_agent_response(response: str) -> AgentFindings:
    """
    Parse the agent's JSON response into AgentFindings.

    Handles cases where the agent might include extra text.
    """
    # Try to find JSON in the response
    response = response.strip()

    # If response is wrapped in code blocks, extract it
    if "```json" in response:
        start = response.find("```json") + 7
        end = response.find("```", start)
        response = response[start:end].strip()
    elif "```" in response:
        start = response.find("```") + 3
        end = response.find("```", start)
        response = response[start:end].strip()

    # Try to find JSON object
    if response.startswith("{"):
        # Find the matching closing brace
        brace_count = 0
        end_idx = 0
        for i, char in enumerate(response):
            if char == "{":
                brace_count += 1
            elif char == "}":
                brace_count -= 1
                if brace_count == 0:
                    end_idx = i + 1
                    break
        response = response[:end_idx]

    try:
        data = json.loads(response)
        return AgentFindings.from_json(data)
    except json.JSONDecodeError as e:
        # Return empty findings if parsing fails
        return AgentFindings(
            reasoning=f"Failed to parse agent response: {e}. Raw: {response[:200]}"
        )


def process_ticket(
    ticket_id: str,
    signature_id: str,
    alert_data: dict,
    asset_criticality: str = "standard",
    reproduction_result: Optional[str] = None,
) -> InvestigationResult:
    """
    Process a security ticket through the investigation pipeline.

    This is the main entry point for the orchestrator.

    Args:
        ticket_id: Unique ticket identifier
        signature_id: The alert signature (e.g., "wazuh-rule-5710")
        alert_data: Raw alert data from SIEM
        asset_criticality: "standard", "elevated", or "critical"
        reproduction_result: "confirmed", "refuted", or None

    Returns:
        InvestigationResult with decision and audit trail
    """
    started_at = datetime.utcnow()

    try:
        # 1. Build prompt for agent
        prompt = build_agent_prompt(alert_data, signature_id)

        # 2. Invoke agent
        response = invoke_agent(prompt)

        # 3. Parse response
        findings = parse_agent_response(response)

        # 4. Calculate confidence
        confidence = calculate_confidence(
            precedent_tier=findings.precedent_tier,
            conditions_met=findings.conditions_met,
            conditions_total=findings.conditions_total,
            evidence_available=findings.evidence_available,
            reproduction_result=reproduction_result,
            asset_criticality=asset_criticality,
        )

        # 5. Make decision
        decision = get_decision(confidence, findings.precedent_matched is not None)

        # 6. Determine disposition
        if decision == "auto_close":
            disposition = "benign"
        elif decision == "escalate":
            disposition = "escalated"
        else:
            disposition = None  # Reproduce doesn't have final disposition yet

        result = InvestigationResult(
            ticket_id=ticket_id,
            signature_id=signature_id,
            alert_data=alert_data,
            findings=findings,
            confidence_score=confidence,
            decision=decision,
            disposition=disposition,
            started_at=started_at,
            completed_at=datetime.utcnow(),
        )

    except Exception as e:
        # Return error result
        result = InvestigationResult(
            ticket_id=ticket_id,
            signature_id=signature_id,
            alert_data=alert_data,
            findings=AgentFindings(),
            confidence_score=0.0,
            decision="escalate",
            disposition="error",
            started_at=started_at,
            completed_at=datetime.utcnow(),
            error=str(e),
        )

    # 7. Log audit trail to stdout
    print(result.to_json(), file=sys.stdout)

    return result


def process_ticket_mock(
    ticket_id: str,
    signature_id: str,
    alert_data: dict,
    mock_findings: AgentFindings,
    asset_criticality: str = "standard",
    reproduction_result: Optional[str] = None,
) -> InvestigationResult:
    """
    Process a ticket with mock agent findings (for testing).

    Same as process_ticket but skips agent invocation.
    """
    started_at = datetime.utcnow()

    # Calculate confidence
    confidence = calculate_confidence(
        precedent_tier=mock_findings.precedent_tier,
        conditions_met=mock_findings.conditions_met,
        conditions_total=mock_findings.conditions_total,
        evidence_available=mock_findings.evidence_available,
        reproduction_result=reproduction_result,
        asset_criticality=asset_criticality,
    )

    # Make decision
    decision = get_decision(confidence, mock_findings.precedent_matched is not None)

    # Determine disposition
    if decision == "auto_close":
        disposition = "benign"
    elif decision == "escalate":
        disposition = "escalated"
    else:
        disposition = None

    result = InvestigationResult(
        ticket_id=ticket_id,
        signature_id=signature_id,
        alert_data=alert_data,
        findings=mock_findings,
        confidence_score=confidence,
        decision=decision,
        disposition=disposition,
        started_at=started_at,
        completed_at=datetime.utcnow(),
    )

    # Log audit trail
    print(result.to_json(), file=sys.stdout)

    return result


# Self-test when run directly
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Orchestrator Manager")
    parser.add_argument("--test", action="store_true", help="Run mock test")
    args = parser.parse_args()

    if args.test:
        print("Running mock test...\n")

        # Test with mock findings (internal IP, monitoring probe pattern)
        mock_findings = AgentFindings(
            precedent_matched="prec-5710-001",
            precedent_tier="gold",
            conditions_met=3,
            conditions_total=3,
            evidence_available=True,
            findings=[
                "Source IP 10.0.1.50 is internal (RFC1918)",
                "Username 'testuser' matches monitoring pattern",
                "Single attempt, no repetition",
            ],
            reasoning="Matches monitoring probe precedent: internal IP, monitoring username, single attempt",
        )

        result = process_ticket_mock(
            ticket_id="TEST-001",
            signature_id="wazuh-rule-5710",
            alert_data={
                "srcip": "10.0.1.50",
                "srcuser": "testuser",
                "agent": "web-server-01",
            },
            mock_findings=mock_findings,
        )

        print(f"\nDecision: {result.decision}")
        print(f"Confidence: {result.confidence_score:.2f}")
        print(f"Disposition: {result.disposition}")
