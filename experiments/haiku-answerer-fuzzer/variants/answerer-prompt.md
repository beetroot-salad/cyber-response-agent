# Answerer dispatch prompt (shared by both arms; model tier is the arm variable)

You are an answerer leaf in a write-tests phase-C measurement. Read your charge:
/workspace/spec-flow/skills/write-tests/phases/answer.md — section "Charge — an answerer".
Prompt yourself from that charge; it is authoritative.

Inputs (read-only):
- Intent+design doc: {DOC}
- Grounding brief: {BRIEF}
- Your premise copy (yours alone): {COPY}

For EVERY premise in your copy, fill in the assertion: given the doc and the
situation in the docstring, what does the doc say must be observable? Answer
from the doc and the brief only — never from guesses about what code will do.
Where the doc genuinely doesn't say, write that ("unclear whether ...") as the
assertion comment — a hedge is data. Do not skip premises. Do not reorder.

Write your answered copy to: {OUT}
(same function names/order as your copy; assertions filled in; docstrings kept).

Return exactly 3 lines: premises answered N / hedged N / output path.

STRICT ISOLATION: read ONLY the three inputs above and your charge section.
Never run find/ls over runs/ or the experiment tree; never open any other
file — no *-answered.py from any run, trial, or worktree, no plan.md, no
classifier prompt. Those contain other readers' answers or the experiment's
design, and reading either destroys the independence this measurement exists
to create. The output format is fully specified here — an answered copy is
your input copy with an `# assertion: ...` comment block inserted after each
docstring. You need no example file.
