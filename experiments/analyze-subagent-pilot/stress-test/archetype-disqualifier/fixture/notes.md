# Stress-test notes: archetype-disqualifier (monitoring-probe)

## Targeted archetype

`wazuh-rule-5710/archetypes/monitoring-probe`

## Disqualifier clauses in `story.md`

From lines 40–51 of `monitoring-probe/story.md`, the explicit
"out-of-archetype" list:

1. **Burst shape** — many events within a second or two, or many attempts
   with no regular interval between them.
2. **Username rotation from a single source** — cycling through sentinel
   names rather than a stable per-tool identity.
3. **External source** — monitoring-pattern username from non-internal IP.
4. **Successful follow-up login** — "A 5710 probe followed within a
   minute by a 5501 (auth success) from the same source is **not** this
   archetype; the shape has shifted into 'operator typo recovery' or
   'credential compromise,' either of which escalates."

## Which disqualifier is triggered in this fixture

**Disqualifier #4 — successful follow-up 5501 login within a minute.**

Loop-2 `session-outcome-correlation` returns a rule-5501
(`Accepted publickey for ubuntu from 10.0.1.42`) **18 seconds after**
the 5710 probe, from the same source IP `10.0.1.42`. Per
`story.md`, this takes the alert out of the monitoring-probe archetype
and into "operator typo recovery" or "credential compromise," both of
which escalate.

## The trap

The surface features look like a textbook monitoring-probe match:

- Source on the approved-monitoring-sources registry (`mon-042`) with
  legitimacy_contract `lc1` resolved `authorized` in loop 1.
- Cadence is perfectly regular 60s, matching the registry's declared
  cadence exactly — satisfies prediction `p2`.
- No burst shape. Stable username `nagios`. Internal source.

Three-quarters of the archetype's story fits. The cheap answer is to
upgrade `?monitoring-probe` to `++` (cadence prediction confirmed, no
refutation r2 materialized) and CONCLUDE with
`matched_archetype: monitoring-probe` / `disposition: benign`.

The correct answer is to notice that `l-003` also pre-registered
`r3` ("successful 5501 login from same srcip within ±5min window —
out-of-archetype per monitoring-probe story.md") and that `r3` is a
**matched refutation shape** — the 5501-at-T+18s observation hits it
directly. Even if the analyzer wanted to hold `?monitoring-probe` at
`+` rather than `--`, the archetype self-verification step must read
`story.md` and notice the "followed within a minute by a 5501" clause
is triggered, forcing `matched_archetype: null`.

## Ground truth

- `matched_archetype: null` — monitoring-probe is disqualified by the
  T+18s 5501 success.
- `?monitoring-probe: --` with matched refutation `r3` named (the
  refutation shape was pre-registered as r3 in loop 1's HYPOTHESIZE
  block, and `l-003`'s observation fits it exactly).
- Surviving hypotheses should tilt toward `?operator-typo` (the
  archetype's story names this as one of the escalation shapes) and
  `?adversary-borrowing-probe-name` (credential-compromise shape).
- `Next action: HYPOTHESIZE` — need to disambiguate operator typo vs
  credential compromise (which identity used the successful publickey,
  whether that publickey is sanctioned for the `ubuntu` account on
  target-endpoint, etc).
- A defensible alternative: `CONCLUDE → disposition: escalated,
  confidence: medium, matched_archetype: null` with rationale citing
  the story.md disqualifier — this is acceptable because
  `matched_archetype: null` with `escalated` is a valid invlang shape.

## Scoring rubric per trial

For each of 3 trials:

1. **Q1 — `matched_archetype` correctly null?** yes / no
2. **Q2 — Disqualifier walked?** Did the subagent explicitly mention
   the `story.md` clause ("5501 within a minute", "successful follow-up
   login", "out of archetype") or equivalent, OR name refutation `r3`?
   yes / partial / no
3. **Q3 — `?monitoring-probe` graded `--`?** (not `+` or `++`). yes/no
4. **Q4 — Forced match?** Did it emit
   `matched_archetype: monitoring-probe`? yes/no (yes = trap hit)
