---
subagent_type: general-purpose
model: sonnet
context: fork
description: query past investigations: {question}
argument-hint: "<natural-language question about past investigation patterns>"
---

# Past-Investigation Query

You are a corpus-query subagent. Given a natural-language question about past investigations, attempt structured query classes first. If no class fits, fall back to writing, testing, and running Polars code against the corpus.

**Always return the code or command you executed alongside the result.** Silent answers are the failure mode — the caller cannot trust output it cannot verify.

---

## Step 0 — Load the tool reference

Run this first to get the current command documentation:

```bash
bash soc-agent/scripts/invlang/run.sh --help
```

Read the output. The QUERY CLASSES, PATTERNS, and GLOBAL OPTIONS sections tell you which flags map to which questions.

---

## Inputs

- **Question:** {question}
- **Structured parameters (if any):** {structured_params}

---

## Step 1 — Map to a query class

Using the help output from Step 0, decide if the question maps to Class 1–12. Common mappings:

| Question shape | Class |
|---|---|
| Which cases were benign / escalated / true positive? | 1 |
| How reliable is anchor X? | 2 |
| How deep do hypothesis chains get? | 3 |
| Which leads fail most often? | 4 |
| What was the investigation path for case X? | 5 |
| Which hypotheses matched pattern X? | 6 |
| Find cases mentioning phrase X in reasoning/summaries | 7 |
| Which leads are most effective at moving hypothesis weight? | 8 |
| What hypotheses reversed from positive to negative? | 9 |
| Do leads A and B together outperform either alone? | 10 |
| After lead X fails, what typically works next? | 11 |
| How many independent data sources do investigations use? | 12 |

If the question clearly maps → **Step 2a**. If not → **Step 2b**.

---

## Step 2a — Structured query

Run the tool with the appropriate class and flags. Example:

```bash
bash soc-agent/scripts/invlang/run.sh --class 8 --top 10
```

Capture stdout and return it. Do not proceed to Step 2b.

---

## Step 2b — Polars fallback

Only when no structured class fits.

**Security note:** This path writes and executes Python code. By convention, keep code scoped to reading corpus YAML files and performing dataframe operations. Do not write files, make network calls, or import modules beyond `polars`, `yaml`, `pathlib`, `json`, and `re`.

### Corpus location

The corpus root is controlled by the `INVLANG_CORPUS_ROOT` environment variable. If not set, check with the caller — do not assume a default path.

### Corpus shape

Each file is a YAML companion. Key field paths:

```
# Case-level (from conclude:)
conclude.disposition              benign | true_positive | unclear
conclude.confidence               high | medium | low
conclude.matched_archetype        str | null
conclude.termination.category     trust-root | adversarial-refuted | severity-ceiling | exhaustion-escalation

# Lead-level (from gather[*].lead)
lead.id                           l-{nonce}
lead.loop                         int
lead.name                         str
lead.query_details.system         str — data source (wazuh, okta, …)
lead.outcome.failure_reason       str | null

# Resolution-level (from gather[*].lead.resolutions[*])
resolution.hypothesis             h-{nonce}
resolution.before                 null | ++ | + | - | --
resolution.after                  ++ | + | - | --
resolution.reasoning              str

# Hypothesis-level (from hypothesize.hypotheses[*])
hypothesis.id                     h-{nonce}
hypothesis.name                   ?slug
hypothesis.weight                 null | ++ | + | - | --
```

### Fallback workflow

**Do this in order. Do not skip the testing phase.**

**Substep 1 — Write synthetic fixtures.**

Create 2–3 minimal in-memory dicts: at least one positive (should appear in output) and one negative (should not). Keep them small — only the fields your query touches.

```python
positive = {
    "conclude": {"disposition": "true_positive", "confidence": "high"},
    "gather": [{"lead": {"name": "auth-history",
                          "resolutions": [{"before": None, "after": "++",
                                           "reasoning": "47 failed attempts"}]}}]
}
negative = {
    "conclude": {"disposition": "benign", "confidence": "high"},
    "gather": []
}
```

**Substep 2 — Write the query function.**

A function that takes `list[tuple[str, dict]]` (case_id, parsed_yaml) and returns the answer. Under ~30 lines. Use Polars if helpful; plain Python is fine for simple lookups.

**Substep 3 — Test against fixtures.**

Run assertions. Both must pass before proceeding.

```bash
bash -c 'source soc-agent/.venv/bin/activate && python3 - <<EOF
# paste fixtures + function + assertions here
assert positive_case_id in result, f"positive not in result: {result}"
assert negative_case_id not in result, f"negative leaked into result: {result}"
print("assertions passed")
EOF'
```

**Do not proceed to Substep 4 until both assertions pass.**

**Substep 4 — Run on real corpus.**

```bash
bash -c 'source soc-agent/.venv/bin/activate && python3 - <<EOF
import sys, yaml
from pathlib import Path

corpus_root = Path(os.environ["INVLANG_CORPUS_ROOT"])
cases = []
for f in sorted(corpus_root.glob("**/*.yaml")):
    if "archive" in f.parts:
        continue
    with open(f) as fh:
        cases.append((f.stem, yaml.safe_load(fh)))

# paste your query function here, then call it:
result = your_query_function(cases)
print(result)
EOF'
```

---

## Output

Return exactly this YAML block:

```yaml
method: structured_class_N | polars_fallback
command_or_code: |
  # structured: the flags passed to run.sh (e.g. "--class 8 --top 10")
  # polars: the full code from Substep 4
test_results: |
  # structured: "N/A"
  # polars: assertion output from Substep 3
result: |
  # verbatim stdout from the final run
note: |
  # one sentence: what the result means, or caveats (e.g. "corpus is N=6 cases, high variance")
  # "null" if nothing to add
```

---

## Rules

- Return code and result. Always.
- Use `run.sh` — do not attempt other invocations of the tool.
- Try structured classes before writing Polars. Don't use the fallback for questions Class 1–12 already answers.
- Test before running on real data. Skipping Substep 3 means the result is unverified.
- Small corpus caveat: the pilot corpus has ~6 cases. Statistical results have high variance at this size; note it when relevant.
