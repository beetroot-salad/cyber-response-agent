# invlang

The structured surface the agent writes into `investigation.md`. This file
is a reference overview; the authoring spec is
`defender/skills/invlang/SKILL.md`, and the dense block-tag grammar is
`docs/dense-investigation-format.md`. This is the **defender's** invlang —
the structural validator (`skills/invlang/validate.py`) runs on every
`investigation.md` write, through `runtime/permission/files.py`; `soc-agent/`
runs a stricter, hook-validated variant of the same language.

## What it is

`investigation.md` is written as fenced `​```invlang` blocks under markdown
phase headers (`## ORIENT`, `## PLAN`, `## GATHER (loop N)`,
`## ANALYZE (loop N)`, `## REPORT`). invlang audits the investigation
*process*, not just the final attack graph — it records every hypothesis,
lead, observation, and belief movement from alert to disposition.

## The block types

| Block | Layer | Records |
|---|---|---|
| `:V` | Observed graph | Vertices — real-world entities (compute, identity, process, socket, file, …) |
| `:E` | Observed graph | Edges — state relations (`runs_on`, `member_of`) or event interactions (`attempted_auth`, `read`, `connected_to`) between vertices |
| `:H` | Commitments | Discovery hypotheses — a proposed new parent vertex + edge for a non-obvious upstream cause; plus `:H h-N.preds`/`.refuts` predictions and `:H h-N.authz` legitimacy contracts |
| `:L` | Procedure | Leads — what the defender chose to run, against which target, for which commitments. Names the `system`; **not** the query template (gather's job) |
| `:R` | Results | Observations + learned facts: `:R attr_updates` (facts about existing graph objects, including closing `??` slots) and `:R authz` (legitimacy-contract verdicts) |
| `:T` | Results | `:T resolutions` (belief movement, with `++`/`+`/`-`/`--`) and `:T conclude` (termination, disposition, confidence) |

## The author CLI

Closed catalogs (vertex `type`, edge `rel`, `class`/`attrs.kind` slots,
`anchor_kind`) are **not** preloaded — look them up at author time. The CLI
is also the corpus-retrieval surface:

```bash
# Enums — what values a slot accepts (corpus_root positional but unread for enum)
python3 -m defender.skills.invlang.cli "$DEFENDER_RUNS_BASE" enum               # slot names
python3 -m defender.skills.invlang.cli "$DEFENDER_RUNS_BASE" enum types          # vertex types
python3 -m defender.skills.invlang.cli "$DEFENDER_RUNS_BASE" enum compute.role   # one slot

# Precedent — how candidate leads have historically split a frontier (PLAN)
python3 -m defender.skills.invlang.cli "$DEFENDER_RUNS_BASE" advisory \
    --signature <id> --class lead_discrimination --frontier '?a' --frontier '?b' --top-k 5

# Hypothesis-name lookup — reuse corpus vocabulary instead of minting singletons
python3 -m defender.skills.invlang.cli "$DEFENDER_RUNS_BASE" hypothesis-shape --parent-type identity ...
python3 -m defender.skills.invlang.cli "$DEFENDER_RUNS_BASE" hypothesis-vocabulary --signature <id>
```

Arg order is **corpus_root first, then the verb.** `advisory` /
`hypothesis-*` output is **precedent, not evidence** — used to pick or
order leads, never cited in `:R`/`:T`. The hypothesis-name lookup matters
because a fresh `?name` that doesn't match corpus vocabulary becomes a
singleton, and the next case with the same shape gets a loud-empty advisory
banner instead of usable precedent.

## `:H` discovery vs `??` refinement

A recurring decision the handbook gets asked about:

- **`:H` (discovery)** — reach for it when the upstream cause is genuinely
  non-obvious: competing stories that imply *different next leads*. Sibling
  `:H` rows must differ on a **predicted observable** — the claim a lead
  splits them on. Slots the alert has not settled stay `??` in
  `parent_class`; a class tuple minted to carry the fork is the defect, not
  the requirement. Rule #23 enforces the textual floor of that
  (`validate._check_fork_distinctness`): live siblings on one anchor whose
  declared claims are identical are refused on write. The same claim in
  different words is invisible to it.
- **`??` (refinement)** — when the question is "what kind of entity is this
  vertex?" and the discriminating lead is **mechanical** (a CMDB lookup, an
  egress check — the same lead regardless of which candidate is right), mark
  the open slot inline with `??` (or `{a, b, c}` candidates) and let a lead
  close it via `:R attr_updates`. Refinement is not a hypothesis row.

An unresolved slot on a *declared node* blocks `disposition: benign` —
resolve it or escalate. The walk is `:V` vertices plus any `:E` edge a
`:R attr_updates` row refines, so `l-001|e-001|attrs.direction|??` gates
exactly as a vertex cell does. A `{a, b, c}` candidate set is an unresolved
slot too, in any slot of the class tuple or as an attribute value: it is an
upgrade from `??`, not a resolution of it. An open `:H parent_class` slot is
not a declared node and does not gate — the proposed parent is a claim the
run has not observed, and no `:R attr_updates` row can even target an `h-*`
to close it.

## Legitimacy is edge-coupled, not a hypothesis fork

When two candidates share topology and differ only on "was this authorized?",
**don't fork them** — that is one cause with two readings, not two causes.
Collapse to one hypothesis and attach an `:H h-N.authz` contract carrying the
legitimacy question. The resolving lead writes a `:R authz` row (verdict ∈
`authorized | unauthorized | indeterminate`) whose `fulfills` column names the
`ac<n>` it closes — and names no hypothesis, so `ac<n>` numbers across the
DOCUMENT, not per hypothesis the way `p<n>`/`r<n>` do. Declaring `ac1` on two
hypotheses that are both still live is denied on write. `disposition: benign`
requires every authz contract on a surviving hypothesis to resolve
`authorized`; `unauthorized` / `indeterminate` forces escalation. Authz
outcomes go in `:R authz`, never in `:R attr_updates` keyed on a contract id.

## Authority of observations

The `auth_kind:source` cell on an edge is observational authority (read it
as `obs_kind:source`). Only `siem-event`, `runtime-audit`, and
`authoritative-source` support `++`/`--` resolutions; `client-asserted` and
`inferred-structural` are weaker and cannot ground a strong assessment.

Sources: `defender/skills/invlang/SKILL.md`,
`docs/dense-investigation-format.md`.
