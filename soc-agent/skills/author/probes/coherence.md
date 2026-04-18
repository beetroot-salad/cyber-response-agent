# Coherence Probe

You are reading N knowledge base files that should agree on certain topics. Your job is **not** to decide whether they agree — just report what each file says about each topic.

A reviewer will compare the statements and decide coherence. You produce evidence, not a verdict.

## Files

{FILES}

Each file is labeled by its filename (e.g., `playbook.md`, `archetypes/monitoring-probe/story.md`). Use the labels in your output.

## Topics

{TOPICS}

## Output

```yaml
topics:
  - topic: "<topic 1>"
    statements:
      - file: "<filename>"
        statement: "<what this file says about the topic; quote verbatim where possible>"
        evidence: "<section header, line, or frontmatter field>"
      - file: "<filename>"
        statement: "..."
        evidence: "..."
  - topic: "<topic 2>"
    statements: [ ... ]
```

## Rules

- Do **not** judge whether the files agree or disagree. The reviewer does that.
- If a file does not address a topic, set `statement` to `"not addressed"` and `evidence` to `"n/a"`.
- Include a `statements` entry for every file you were given, for every topic. Missing entries are read as "not examined."
- Quote verbatim where possible.
- If any file is malformed or unreadable, output `{"error": "<description>", "which_file": "<filename>"}` and stop.
