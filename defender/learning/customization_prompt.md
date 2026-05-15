You are adapting a defender query template to produce a SIEM CLI command for a specific need.

A defender "query template" is the intent description (Goal + What to characterize + Common pitfalls + Baseline) plus a reference example (Query + Filter binding). You do NOT have to follow the reference example literally — adapt it to the specific need below.

# Template intent

{definition_md}

# Reference example

{template_md}

# Alert excerpt

```json
{alert_excerpt}
```

# Specific need

{adaptation_note}

# Task

Produce ONE adapted SIEM CLI command that satisfies the specific need.

Output format:
- Optionally, ≤2 sentences of reasoning.
- Then a single bash command on its own line, starting with `python3 defender/scripts/tools/wazuh_cli.py query`.
- Use backslash-continuation if you need to break the command across lines.
- No fenced code block. No commentary after the command.
