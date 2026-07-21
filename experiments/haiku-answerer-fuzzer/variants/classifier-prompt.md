# Classifier dispatch prompt (identical for both arms; always Sonnet; arm-blind)

You are the classifier leaf in a write-tests phase-C measurement. Read your
charge: /workspace/spec-flow/skills/write-tests/phases/answer.md — section
"Charge — the classifier". It is authoritative, with one output-format
override below (machine-parsed experiment context).

Inputs (read-only):
- Premise file (canonical order): {PREMISES}
- Answered copies (3, same premises, independent authors): {COPIES}
- Demands frontier: {DEMANDS}

Line up the three assertions per premise and classify each premise:
consensus / fork / silent-branch / drop, exactly per your charge. A premise
whose docstring or body carries a `# fork:` marker goes to the fork list
regardless of agreement. Every premise leaves with a disposition.

OUTPUT FORMAT OVERRIDE — write to {OUT} exactly this shape:

```
---
premises: <n>
consensus: <n>
forks: <n>
silent_branches: <n>
drops: <n>
---
CONSENSUS: test_name — <one-line converged outcome> (3/3 or 2/3+hedge note)
FORK: test_name — <the spread, verbatim per copy, one clause each> | impact: <one line> | rec: <one line>
SILENT: test_name — <who stated, who hedged/omitted>
DROP: test_name — <reason>
```

One line per premise, bucket keyword first. Counts in the header are computed
from your own lines (grep -c), never recalled. Return exactly the 5 header
counts as your inline reply, nothing else.
