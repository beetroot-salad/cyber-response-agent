# HYPOTHESIZE error analysis

Error-analysis pass on past HYPOTHESIZE YAML outputs to surface real
failure modes ahead of state-machine migration judge design.

## 1. Corpus summary

- **Runs analyzed:** 29 investigation.md files that emit a structured
  `hypothesize:` block (the full set discovered under `/workspace/runs`).
- **HYPOTHESIZE blocks extracted:** 41 (some runs emit multiple loops).
- **Blocks with populated YAML companion:** 28. The other 13 are loop-N
  headers with only markdown commentary (typically loops 2+ where the
  subagent decided no new hypothesis fork was needed; these are an
  invlang-compliance choice, not a failure mode).
- **Analysis scope:** all 28 YAML-bearing blocks were inspected. No
  sampling was needed — the corpus is small enough to review
  exhaustively.

Signature distribution of the 28 YAML-bearing blocks:

| Signature | YAML blocks | Notes |
|---|---|---|
| wazuh-rule-5710 (SSH invalid user) | 19 | Dominant; monitoring-probe scenarios |
| wazuh-rule-100001 (container shell) | 8 | Container/runc mechanism fork |
| wazuh-rule-100110 (high-entropy DNS) | 1 | DGA/tunneling fork |
| wazuh-rule-550 (file integrity) | 0 | All runs screen-matched and fast-pathed past HYPOTHESIZE |

The rule-550 zero is itself notable: rule-550's screen-to-escalate
fast-path is bypassing HYPOTHESIZE entirely in the observed corpus, so
judge design has no rule-550 prior.

## 2. Failure-mode frequency table

Counted over the 28 YAML-bearing blocks. Severity is the author's call,
judged by "does this failure silently produce a wrong CONCLUDE?"
(high = yes, medium = degrades precision or audit quality, low = stylistic).

| # | Failure mode | Count | % of blocks | Severity |
|---|---|---:|---:|---|
| 1 | Sibling non-discrimination (parallel predictions, no shared forked observable) | 1 | 4% | high |
| 2 | Missing seed vs playbook | 0 (clear) | 0% | high when present |
| 3 | Compound prediction (multiple claims joined with AND/OR/;) | 12 | 43% | high |
| 4 | Legitimacy/intent packed into classification name | 22 | 79% | medium |
| 5 | Parallel sanctioned/unsanctioned pair (same mechanism) | 13 | 46% | high |
| 6 | Over-lean (≥3 predictions on one hypothesis) | 1 | 4% | low |
| 7 | Narrative umbrella classification name | 11 | 39% | medium |
| 9 | Empty `story:` | skipped per spec (only 1 block uses story, never empty) | — | — |
| 10 | Lead selection not justified against playbook | 0 | 0% | low |

### Closed by schema — not a behavioural failure mode

**FM8 — refutation doesn't cite predictions.** Struck from the table
above (#932). It read 28/28 = 100%, and that number measured the
schema, not the agent: at the time of the pass the emitted invlang had
no field for the link, so every block failed a check nothing could
pass. Ranking a measurement artifact above FM4 (79%) and FM5 (46%),
which are behavioural, put the wrong row at the top of the table and
misdirects the next PLAN prompt change.

The absence is closed. The `refuts` row carries the link as a
first-class column — `:H h-NNN.refuts [id|refutes|claim]`
(`defender/SKILL.md` §PLAN) — and the validator resolves it: a
`refutes` cell naming a `p*`/`ap*` the declaring hypothesis does not
declare is refused (`_check_refutation_scope`, spec rule #5's
declaring-side half), and a `--` citing an `r*` settles the predictions
that `r*` names (`_settled_predictions`). The column is populated on
every hypothesis in every recent run.

## 3. Exemplars

### FM1 — Sibling non-discrimination (1 instance)

- `runs/20260417-065057-rule5710/.../investigation.md` loop 1
  (h-001 `?misconfigured-monitoring`, h-002 `?authorized-adversarial-eval`,
  h-003 `?internal-credential-guessing`). **Both h-001 p1 and h-002 p1
  assert "only monitoring-pattern usernames in the burst"**; both p2
  assert "only cron/ssh processes running — no attack tooling." The
  predicted observables are identical on the discriminating data source.
  The three hypotheses differ on *intent* but not on any prediction that
  the selected lead could read differently. A single run of the lead
  cannot collapse this fork.

### FM3 — Compound prediction (12 instances)

Canonical example (task-spec-matching):

- `runs/20260418-044255-rule5710/.../investigation.md` loop 1 h-001 p1:
  `"SIEM shows ≤2 rule-5710 events from 172.22.0.10 in 5-min pre-alert
  window; all usernames are monitoring-pattern; no auth-success event
  within 60s of alert"` — three independent claims. If only one conjunct
  fails (e.g. the username test passes but count = 3), assessment
  routing is ambiguous: does `--` fire on the whole prediction, or does
  the lead emit two partial assessments?
- `runs/20260418-044255-rule5710/.../investigation.md` loop 1 h-002 p1:
  `"≥5 events OR usernames include non-monitoring-pattern"` —
  disjunctive; refutation requires both conjuncts false, which the
  `refutation_shape` does not spell out.
- `runs/20260418-064543-rule100110/.../investigation.md` loop 2 h-002
  p1: `"fixed-length 16-char identifiers OR variable-length encoded
  chunks; no repetition indicates encoding"` — the h-002 r1 then
  self-acknowledges the ambiguity ("fixed session token matching p1's
  first branch is ambiguous"). The subagent noticed the compound was
  un-refutable and wrote around it instead of splitting.

### FM4 — Legitimacy/intent packed into classification (22 instances, pervasive)

- `runs/20260417-062302-rule5710/...` loop 1 — classifications
  `identity:monitoring-infrastructure` vs `identity:adversarial`.
  Same mechanism (upstream identity driving SSH probes); legitimacy
  is the entire distinction and should be a `legitimacy_contract`
  attribute on one hypothesis.
- `runs/20260417-065057-rule5710/...` loop 1 — `misconfigured-cron-job`,
  `authorized-eval-script`, `credential-guessing-tool`. All three encode
  intent (authorized/misconfigured/malicious). The real mechanism in
  each case is "cron-scheduled script on monitoring-host."
- `runs/20260419-074823-rule100001/...` loop 1 h-003 — classification
  `?adversary-controlled` is pure intent, no mechanism. The playbook
  mechanisms are `image-entrypoint`/`runtime-process`/`underlying-host`;
  this hypothesis doesn't land on any of them.

### FM5 — Parallel sanctioned/unsanctioned pair (13 instances)

- `runs/20260417-161358-rule5710/...` loop 1 — h-001 `?misconfigured-
  monitoring` vs h-002 `?compromised-monitoring-host`. Both attach the
  same upstream (a process on 172.22.0.10 generating SSH), differing
  only on authorization. Discriminator is an anchor check, which is
  exactly what a `legitimacy_contract` is for.
- `runs/20260418-035446-rule5710/...` loop 1 — `?legitimate-automation`
  vs `?credential-guessing`: both attach to the source-host identity,
  predictions are mirror-images on anchor presence/absence.
- `runs/20260418-165330-rule5710/...` loop 1 — `?misbehaving-probe` vs
  `?compromised-monitoring-host`: same upstream process mechanism,
  legitimacy is the only split.

### FM6 — Over-lean, 3+ predictions (1 instance)

- `runs/20260417-113747-rule5710/...` loop 1 h-001 `?legitimate-
  automation` — 3 predictions: attempt count, no-success window, and
  host-operational-state (`cron service + openssh-client`). The third
  prediction also duplicates an anchor check. This is the only block
  that strictly violates the 2-prediction cap.

### FM7 — Narrative umbrella classification (11 instances)

- `?compromise-followup` appears in 8 blocks (rule5710 runs:
  20260417-062302, 20260417-081839, 20260417-103641, 20260417-135616,
  20260418-035446, 20260418-054504, 20260418-130931, 20260418-145914).
  Its prediction is always the same — "a `5501`/`5715` auth-success
  from the same srcip appears within 60s" — which is really a
  composition-rule check, not a mechanism hypothesis.
- `?post-exploit-interactive` (rule100001 runs 20260417-090412,
  20260417-171206) — playbook-defined archetype name, but the name
  aggregates "any adversarial use of `?runtime-process` mechanism"
  under one umbrella.
- `?reverse-shell-post-exploit` (run 20260418-041739 loop 2) — umbrella
  classification for co-firing 100002; mechanism is not specified.

### FM8 — Refutation doesn't cite predictions (28 / 28) — closed, see §2

Structural, and the denominator was the schema. The invlang as emitted
at the time of this pass did not include a `refutes_predictions: [pN]`
field on any `refutation_shape` entry; entries carried only `id` and
`claim`. In most blocks the reader can map an r1 to a p1 by proximity,
but the link was never explicit. Example of the asymmetry causing
analysis pain:

- `runs/20260418-064543-rule100110/...` loop 2 h-002 r1 "subdomains
  identical across sessions…" — the text itself says "matching p1's
  first branch is ambiguous", acknowledging the link but not encoding
  it. A judge cannot mechanically check refutation adequacy.

The field exists now — the `refutes` column on `:H h-NNN.refuts` — and
a judge can. See §2 "Closed by schema".

### FM10 — Lead selection not justified (0 clear instances)

All 28 blocks select leads that are in-playbook (authentication-history,
approved-monitoring-sources, container-baseline, correlated-falco-events,
process-lineage, scheduled-jobs, shell-context) or in
`knowledge/common-investigation/leads/`. No violations found.

## 4. Cross-cutting observations

1. **The FM4/FM5 pair dominates the rule-5710 corpus.** Across 19
   rule-5710 YAML blocks, 13 (68%) pair a "legitimate-*" hypothesis
   with a "compromised/credential-guessing/adversarial-*" hypothesis
   that share a mechanism and differ only on authority. The invlang
   v2.8 `legitimacy_contract` primitive exists *precisely* to collapse
   these, and exactly one block uses it correctly to carry the
   authorization split within one hypothesis
   (`runs/20260419-045735-rule5710/...` loop 1). The discipline is not
   landing in practice on rule-5710.

2. **`?compromise-followup` is load-bearing and load-wrong.** Nearly
   every rule-5710 block includes a third hypothesis named some variant
   of `?compromise-followup`, `?compromise-chain`, or
   `?post-failure-success`. Its prediction is always "an auth-success
   from the same srcip appears within 60s." This is not a hypothesis
   about the current alert — it is a composition-rule check on a
   *subsequent* event. It shouldn't be a hypothesis at all; it should
   be an escalation-precondition that runs unconditionally. Its
   presence as a peer hypothesis distorts the frontier and makes
   sibling counts look larger than they are.

3. **Legitimacy-packed names even when a `legitimacy_contract` is
   present.** Two blocks
   (`runs/20260419-095700-rule5710/...`, `runs/20260419-102244-rule5710/...`)
   correctly carry `legitimacy_contract` on a single hypothesis — but
   still name the hypothesis `?authorized-monitoring-probe` /
   `?internal-monitoring-host-probe`. The contract does the work; the
   name duplicates and biases the weight history before the anchor
   resolves. The mechanism discipline ("`?monitoring-probe` carries
   `lc1: authorized?`") is not internalized even when the structure is.

4. **Predictions frequently restate pitfalls.** Several blocks write a
   prediction that rephrases its paired pitfall (e.g.
   `runs/20260418-054504-rule5710/...` loop 1 h-001 p1 predicts "tight
   time cluster ≤10s" and the pitfall then says "tight clustering alone
   is not authoritative"). This reads as the subagent noticing the
   prediction is weak at the moment of writing. The pitfall is
   effectively a self-audit that didn't feed back into revising the
   prediction.

5. **`story:` field is unvalidated terrain.** Only 1 of 28 YAML blocks
   uses the `story:` field (`runs/20260419-123912-rule5710/...` loop 1,
   both hypotheses). Per-task instruction, FM9 (empty/generic story)
   is skipped from the counts — but the field is essentially dormant
   across the corpus. Two implications for judge design: (a) there is
   no corpus evidence that `story:` is being used either well or
   poorly, and (b) the one block that does use it is one of the
   cleanest structurally (distinct mechanisms, proper contracts, good
   pitfalls). Needs a targeted prompt to generate more data before
   judge rules can be written.

## 5. Judge-design implications

Per failure mode with meaningful frequency:

- **FM1 Sibling non-discrimination (4%, high severity)** — (b) Haiku
  judge question. Structural rule is hard because "do these predictions
  name a shared forked observable?" requires semantic reading of the
  `claim` strings. A judge prompt asking "name an observation whose
  predicted value differs between these two hypotheses — quote the
  predictions" lands cleanly.

- **FM3 Compound prediction (43%, high)** — (b) judge or eval-rubric
  question, **not** (a) a structural validator rule. This entry
  originally prescribed a regex over `claim` — "`;`, `AND`, `and`,
  `OR`, `or`, `,`-with-clause-separator, or `>`" — as a PreToolUse
  block, and that prescription was measured and refused (#932; see
  `docs/decisions/defender-invlang-enforcement-ramp.md`). Two reasons.
  First the corpus: over every ```invlang document in the tree the
  regex fires on 35% of prediction rows (33/95) and 48% of refutation
  rows (26/54), and among the documents it refuses are the runtime
  authoring skill's own teaching block, both shipped worked examples,
  and both shipped e2e goldens. Much of that is the word "and" joining
  one observable's parts — "short-lived and not a package manager" is
  one process characterization, not two claims. Second the semantics,
  on the refutation half: a refutation scoped to `p1,p2` negates a
  conjunction, so De Morgan makes "¬p1 or ¬p2" the *correct* rendering,
  and the regex reads the correct rendering as the defect. Compound
  claims are real and they sit in the **predictions**; the `refuts` row
  is where you see them, not where they are. The detector belongs where
  `predict-eval-rubric.md` already puts it — a scored dimension over
  hand-labelled cases with a calibration step — not on a write gate.

- **FM4 Legitimacy packed in classification (79%, medium)** — (c)
  subagent-prompt tightening, with (a) structural backstop. The
  subagent prompt should ship a whitelist of mechanism stems
  (`monitoring-probe`, `scheduled-job`, `reverse-shell`,
  `runtime-process`, `image-entrypoint`, `underlying-host`, etc.) and
  forbid a regex-detectable set of legitimacy prefixes (`authorized-`,
  `unauthorized-`, `legitimate-`, `malicious-`, `adversarial-`,
  `sanctioned-`, `compromised-`). *(#932: the "(a) structural backstop"
  half is withdrawn. A forbidden-prefix regex over model-authored names
  is the exact test spec rules #36 and #32 were struck for — #36's v2.14
  token list produced false rejections of correctly-graded routings and
  v2.16 deleted it. The whitelist in the prompt is the live ask; the
  validator regex is not.)*

- **FM5 Parallel sanctioned/unsanctioned pair (46%, high)** — (b)
  Haiku judge question, because "same mechanism, differs only on
  authority" is semantic. Prompt: "for each pair of sibling
  hypotheses, identify the upstream mechanism attached; if two
  siblings attach the same mechanism and their predictions are
  mirror-images on an authority/anchor check, flag." Downstream
  remediation is structural (one hypothesis + legitimacy_contract) so
  the judge output is actionable.

- **FM6 Over-lean (4%, low)** — (a) structural validator rule. Count
  `predictions[]` length; block if > 2. Near-zero cost.

- **FM7 Narrative umbrella (39%, medium)** — (c) subagent-prompt
  tightening, focused on `?compromise-followup`. The prompt should
  explicitly forbid peer-hypothesis escalation-precondition checks and
  instruct the subagent to put auth-success correlation in an
  unconditional GATHER lead. For umbrella names more broadly, same
  whitelist/blacklist mechanism as FM4.

- **FM8 No prediction-refutation link — shipped, not outstanding.** The
  `refutes` column landed on `:H h-NNN.refuts`, the validator resolves
  each cited `p*`/`ap*` against the declaring hypothesis
  (`_check_refutation_scope`), a cited `r*` settles the predictions it
  names on the ANALYZE side (`_settled_predictions`), and the emitting
  prompt populates it in every recent run. Nothing here is a live ask.
  The one clause never shipped — "validator enforces non-empty" — fires
  on nothing: every hypothesis with predictions in the tree already
  writes at least one `refuts` row, so the gate would be dead code.

- **FM2 Missing seed** and **FM10 lead-not-in-playbook** are
  unrepresented in the corpus; defer until we see a failing case.

- **FM9 Empty story** — defer; corpus lacks signal. Prompt
  intervention to encourage story use should precede judge design.

---

## Top-3 summary (for the user)

The three highest-impact failure modes are **compound predictions**
(43% of blocks, including the canonical "≤2 events AND monitoring-
pattern AND no auth-success" form — best caught by a structural
validator rule on `claim` strings), **parallel sanctioned/unsanctioned
hypothesis pairs** (46%, where two hypotheses share a mechanism and
differ only on authority — best caught by a Haiku judge, then
collapsed into one hypothesis with a `legitimacy_contract`), and
**legitimacy/intent packed into classification names** (79%, pervasive;
tackled by a mechanism-stem whitelist in the subagent prompt — the
forbidden-prefix regex this paragraph also proposed for the validator
is the same lexical shape that spec rules #32 and #36 were struck for,
and is not a live ask).

*(Amended #932. The original fourth finding here — "every single block
omits the `refutes_predictions: [pN]` link", called the most surprising
result and a one-day fix — was measuring the absence of a schema field,
not agent behaviour. The field shipped; see §2 "Closed by schema". The
three above are the findings.)*
