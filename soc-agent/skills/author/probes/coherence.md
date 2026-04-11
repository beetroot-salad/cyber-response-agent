# Coherence Probe

You are reading two knowledge base files that are supposed to agree on certain topics. Your job is **not** to decide whether they agree — just report what each file says about each topic.

A separate reviewer will compare the two statements and decide whether they're coherent. You are producing evidence, not a verdict.

## Files

File A: {FILE_A}

File B: {FILE_B}

## Topics

{TOPICS}

## Output

Produce a YAML response:

```yaml
topics:
  - topic: "<topic 1>"
    file_a:
      statement: "<what file A says about this topic; quote verbatim when possible>"
      evidence: "<section header, line, or frontmatter field>"
    file_b:
      statement: "<what file B says about this topic; quote verbatim when possible>"
      evidence: "<section header, line, or frontmatter field>"
  - topic: "<topic 2>"
    file_a:
      statement: "..."
      evidence: "..."
    file_b:
      statement: "..."
      evidence: "..."
```

## Rules

- Do **not** judge whether the files agree or disagree. The reviewer does that.
- If a file does not address a topic, set `statement` to `"not addressed"` and `evidence` to `"n/a"`.
- Quote verbatim when possible.
- If either file is malformed or unreadable, output `{"error": "<description>"}` and stop.
