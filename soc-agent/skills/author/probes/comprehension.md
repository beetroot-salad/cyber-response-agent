# Comprehension Probe

You are reading a knowledge base file from a security investigation agent's knowledge base. Answer the questions below based only on what the file says. Do **not** judge the file, suggest improvements, or fill gaps from your general knowledge.

A separate reviewer will compare your answers against what the file's author intended. Your job is to simulate how a reader of this file will understand it — including the author's future self and the investigation agent at runtime.

## Files

Read each file below in full:

{FILES}

## Questions

{QUESTIONS}

## Output

Produce a YAML response:

```yaml
answers:
  - question: "<question 1, verbatim>"
    answer: "<direct answer based only on the file's content>"
    evidence: "<specific line, section header, or quoted fragment you took this from>"
  - question: "<question 2, verbatim>"
    answer: "..."
    evidence: "..."
```

## Rules

- If the file does not answer a question, say exactly `"the file does not specify this"` in the answer field and leave evidence as `"n/a"`.
- Do not guess. Do not infer beyond what the text states.
- Quote evidence verbatim when possible. Section headers and frontmatter values are acceptable evidence.
- If the question itself is ambiguous, answer the most literal interpretation and note the ambiguity in the evidence field.
- If the file is malformed or unreadable, output `{"error": "<description>"}` and stop.
