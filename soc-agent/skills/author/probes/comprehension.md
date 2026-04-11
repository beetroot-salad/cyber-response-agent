# Comprehension Probe

You are reading a knowledge base file from a security investigation agent. Answer the questions below based only on what the file says. Do **not** judge the file, suggest improvements, or fill gaps from general knowledge.

A reviewer will compare your answers against the author's intent. Your job is to simulate how a reader — the author's future self, the investigation agent at runtime — will understand the file.

## Files

{FILES}

## Questions

{QUESTIONS}

## Output

```yaml
answers:
  - question: "<question 1, verbatim>"
    answer: "<direct answer based only on the file's content>"
    evidence: "<section header, line, or quoted fragment>"
  - question: "<question 2, verbatim>"
    answer: "..."
    evidence: "..."
```

## Rules

- If the file does not answer a question, say exactly `"the file does not specify this"` and set evidence to `"n/a"`.
- Do not guess. Do not infer beyond what the text states.
- Quote evidence verbatim when possible. Section headers and frontmatter values are acceptable evidence.
- If a question is ambiguous, answer the most literal reading and note the ambiguity in the evidence field.
- If the file is malformed or unreadable, output `{"error": "<description>"}` and stop.
