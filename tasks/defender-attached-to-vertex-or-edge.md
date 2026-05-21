---
title: Accept :H attached_to as vertex OR edge (defender invlang)
status: todo
groups: defender, invlang, schema
---

## Context

Today the schema treats `:H attached_to` as a vertex id (per worked
example in `defender/skills/invlang/SKILL.md`). The parser stores it
under the key `attached_to_vertex` and does no type check. Empirically
the defender agent **consistently writes an edge id** instead — three
runs against `gtest-01-auth` (wazuh-rule-5710), three runs with
`attached_to=e-001`. The drift is stable; the framing is coherent.

Both readings make semantic sense:

- **Vertex-attached** — "what kind of entity is v-N?" Competing claims
  about a vertex's class. Fits alerts about *things* (file changed,
  process spawned, account created).
- **Edge-attached** — "what actor produced e-N?" Competing claims
  about the upstream of an interaction. Fits alerts about
  *interactions* (failed auth, network connection, API call).

Decision (from PR #224 review discussion): **accept both forms.** The
agent's framing tracks the alert shape; forcing it to attach to a
vertex when the alert *is* an interaction obscures the actual fork.
Both already fork naturally on `parent_type`/`parent_class` (the
proposed upstream).

## What to change

### 1. Parser (`defender/skills/invlang/parser.py`)

- Rename the canonical key `attached_to_vertex` → `attached_to`. Drop
  the `_vertex` suffix since the value may also be an edge id.
  Optionally derive `attached_to_kind: "vertex" | "edge"` from the id
  prefix (`v-*` → vertex, `e-*` → edge) for downstream consumers that
  need to branch.
- No validation in this PR (defender's parser is permissive
  pre-MVP). The future validator will reject dangling refs (see §4).

Existing references in the parser (grep for `attached_to_vertex`):
- `parser.py:393` — the projection in `_hypothesis_record`.

### 2. Query helper (`defender/skills/invlang/queries.py`)

`hypothesis_shape_match`'s `attached_to_type` filter currently
resolves `v-*` ids through `prologue.vertices` to get the vertex's
`type`. Extend to resolve `e-*` ids through `prologue.edges` plus
lead-scoped `observations.edges` to get the edge's `rel`:

```python
# Build both lookup tables.
v_type = {v["id"]: v.get("type", "") for v in c.prologue.get("vertices", [])
          if isinstance(v, dict) and v.get("id")}
e_rel = {e["id"]: e.get("relation", "") for e in c.prologue.get("edges", [])
         if isinstance(e, dict) and e.get("id")}
for lead in c.leads:
    obs = (lead.get("outcome") or {}).get("observations") or {}
    for e in obs.get("edges", []) or []:
        if isinstance(e, dict) and e.get("id"):
            e_rel[e["id"]] = e.get("relation", "")

# Resolution: branch on id prefix.
attached_id = h.get("attached_to", "")
if attached_id.startswith("v-"):
    h_attached_to_type = v_type.get(attached_id, "")
elif attached_id.startswith("e-"):
    h_attached_to_type = e_rel.get(attached_id, "")
else:
    h_attached_to_type = ""
```

Filter behavior stays a single union: `--attached-to-type compute`
matches vertex-attached hypotheses where v-N has type=compute;
`--attached-to-type attempted_auth` matches edge-attached hypotheses
where e-N has rel=attempted_auth. Vertex types and edge rels are
disjoint vocabularies so the filter works without ambiguity.

### 3. SKILL.md (`defender/skills/invlang/SKILL.md`)

The current worked example uses a vertex (`v-001`). Add a second
example using an edge (`e-001`), with one sentence pairing each form
to its alert shape:

> **Vertex-attached** when the hypothesis competes on what kind of
> entity v-N is. **Edge-attached** when the hypothesis competes on what
> actor produced the interaction e-N. The alert shape usually points at
> one — `?file-modified-by-X` attaches to the file; `?ssh-from-X`
> attaches to the auth edge.

Update the `:H` row-grammar prose accordingly. The §Classification
grammar table doesn't need changes (it documents `class`, not
`attached_to`).

### 4. Future validator (out of scope here; tracked in
`tasks/defender-controlled-vocab-catalog.md`)

- `attached_to` must reference an existing `v-*` id in
  `prologue.vertices` OR an existing `e-*` id in `prologue.edges` or
  any lead's `observations.edges`. Reject dangling refs.
- Optionally: reject mixed id-spaces (a `v-*` value that resolves to
  an edge id, or vice versa).

## Tests to add

In `defender/tests/test_invlang_queries.py`:

1. `test_hypothesis_shape_match_edge_attached_resolves_via_prologue_edges`
   — companion with an edge-attached hypothesis (`attached_to=e-001`),
   prologue.edges has e-001 with rel=attempted_auth. Filter
   `attached_to_type="attempted_auth"` returns the hit.

2. `test_hypothesis_shape_match_edge_attached_resolves_via_observation_edges`
   — same but the edge lives in a lead's observation block, not the
   prologue.

3. `test_hypothesis_shape_match_attached_to_type_is_union` — mixed
   corpus, one vertex-attached + one edge-attached, both forks visible
   under their respective `attached_to_type` filters.

In `defender/tests/test_invlang_parser.py`:

1. `test_hypothesis_attached_to_accepts_edge_id` — parse a companion
   with `attached_to=e-001`, assert the canonical key is `attached_to`
   (not `attached_to_vertex`), and (if implemented) `attached_to_kind`
   resolves correctly.

## Existing references to update

Search-and-replace `attached_to_vertex` → `attached_to` across:

```bash
grep -rln "attached_to_vertex" defender/ | grep -v __pycache__
```

Likely hits:
- `defender/skills/invlang/parser.py`
- `defender/skills/invlang/queries.py` (in `hypothesis_shape_match`)
- `defender/tests/test_invlang_*.py` (any existing tests touching the field)

## Empirical evidence (for context)

Three defender runs against `defender/fixtures/gtest-01-auth/` (rule-5710):

| run | `attached_to` value | parser stored |
|---|---|---|
| `pr224-discipline-check` | `e-001` | `attached_to_vertex: e-001` (misnomer) |
| `pr224-shape-only` | `e-001` | same |
| `pr224-with-learn` | `e-001` | same |

Run dirs (transient, may be cleaned):
- `/tmp/defender-runs/pr224-discipline-check/`
- `/tmp/defender-runs/pr224-shape-only/`
- `/tmp/defender-runs/pr224-with-learn/`

PR #224 review notes (search the discussion for "attached_to") explain
the framing in more depth.

## Acceptance criteria

- Parser canonical key is `attached_to` (not `attached_to_vertex`).
- `hypothesis_shape_match --attached-to-type` works for both
  vertex-attached and edge-attached hypotheses (single filter, union
  semantics on disjoint vocabularies).
- `skills/invlang/SKILL.md` documents both forms with worked examples.
- New tests pass; all existing invlang tests still pass.
- No agent-side prompt changes required — the agent already writes
  edge-attached naturally. (If a future run shows the agent over-using
  the edge form when vertex would be clearer, tighten with a
  one-sentence guide rule.)

## Out of scope

- Validator enforcement (tracked separately).
- Soc-agent invlang — this is a defender-only change. The soc-agent
  schema has its own validator rules; coordinating across both is a
  separate conversation if/when defender ships.
