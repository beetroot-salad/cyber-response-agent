You are adapting an investigation seed to produce a SIEM query for a specific need.

A "seed" is the intent description (definition.md) + a reference example (templates/wazuh.md). You do NOT have to follow the reference example literally — adapt it to the specific need below.

# Seed intent

{definition_md}

# Reference example template

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
- Then a single bash command on its own line, starting with `python3 scripts/tools/wazuh_cli.py query`.
- Use backslash-continuation if you need to break the command across lines.
- No fenced code block. No commentary after the command.
