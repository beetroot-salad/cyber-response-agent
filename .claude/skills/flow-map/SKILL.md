---
name: flow-map
description: Extract a trustworthy, source-traceable flow chart of a specified code flow in the defender codebase, rendered as Mermaid. Combines a deterministic Python/orchestration seed with haiku workers for the semantic dispatch edges a parser cannot resolve. Use when you want to understand "how does X work" (a subagent, the learning loop, a hook chain) and need the map to be verifiable against the real code, not vibes.
---

# flow-map

Builds a flow chart of a **specified** code flow by combining a deterministic
extractor (the cheap, exact 80%) with haiku workers (the semantic 20% a parser
can't resolve), then verifies the result against the source. Every node and edge
carries a `path:line` ref and a `confidence` tag, so the map is auditable and
diffs cleanly when the code changes.

Personal dev skill, **defender-scoped** (it encodes this repo's dispatch
idioms). Not shipped with the defender plugin.

## When to use

- "How does the gather subagent / learning loop / hook chain work?"
- You're unsure the code matches your mental model (declare → Claude implements
  → drift) and want a map you can trust, with line refs to click through.
- You want to detect drift: regenerate `graph.json`, `git diff` it.

## Core idea (read before invoking)

Two layers, one schema (`flowmap/model.py`):

| layer | resolved by | examples |
|-------|-------------|----------|
| **deterministic seed** | scripts, no LLM | intra-module `calls` (ast); `_run_claude(CONST)` → `agent-prompt`; `subprocess([CONST])` → `script`; cross-module dispatch (`__import__(param)`, aliased imports) via call-site dataflow; `settings.json` hook wiring |
| **haiku glue** | claude -p (haiku) | is a `skills/X/SKILL.md` mention a real **dispatch** or a doc **reference**? — the semantic call a regex gets wrong |

Invariants that make it trustworthy:
- **Scripts own node identity** (canonical `path:line`-derived ids). Haiku may
  only accept/reject seeded candidates, never invent a node.
- **Nothing is silently dropped.** What the seed can't resolve becomes a
  `Gap` (machine-readable). The way to close a gap is to extend the seed with a
  **deterministic** resolver (see `resolve.py`) — never a hand-edited diagram or
  a brittle regex.
- **Every edge is tagged** `confidence: deterministic|llm` + `via` + `ref`, so
  llm-resolved edges are visually distinct and can later be promoted to
  deterministic resolvers without changing the schema.

## Usage

Run from the skill dir. `--root` is the repo root; `--entry` the seed function.
**Prefer `build`** — it is the only path that guarantees the graph you get has
been verified.

```bash
cd .claude/skills/flow-map

# Build = seed -> resolve -> VERIFY (integral) -> render. Structural checks
# always run and gate the build. (no LLM, no cost unless differential opted in)
python3 flowmap.py build \
  /workspace/defender-v2-tree/defender/learning/loop.py \
  --root /workspace/defender-v2-tree --entry run_one --out graph.json --mermaid

# Extraction only (no verification) — for inspecting the raw graph / gaps
python3 flowmap.py seed <module.py> --root <repo> --entry <fn> --mermaid
python3 flowmap.py seed <module.py> --root <repo> --entry <fn> --no-resolve

# Re-derive + structurally validate an already-built graph (exit 1 on drift)
python3 flowmap.py validate <module.py> --root <repo> --entry <fn>
```

`build` exit codes: **0** clean · **1** structural failure (hard gate) · **2**
differential disagreement (advisory — the graph is still emitted, with the
fidelity gap recorded on it).

### Verification is integral, not a separate step

`build` always runs the **structural** tier (`flowmap/validate.py`: refs,
edges, call-consistency, golden) on the graph it just produced — there is no way
to emit an unverified graph from `build`.

The **differential** tier (`flowmap/verify.py`) is the only PAID part: two haiku
tracers per load-bearing sub-flow — one reads the raw source, one reads the
constructed subgraph — reporting a `surrogate-fidelity` gap when they disagree
(the high-value drift signal). It is **off by default** and opt-in:

```bash
FLOWMAP_DIFFERENTIAL=1 python3 flowmap.py build <module.py> --root <repo> --entry <fn>
python3 flowmap.py build ... --differential       # force on  (overrides env)
python3 flowmap.py build ... --no-differential    # force off (overrides env)
```

`build` auto-selects up to `--subflows` (default 2) load-bearing sub-flows
deterministically (entry first, then functions with the most dispatch/subprocess
edges). Structural failure short-circuits the differential — a non-faithful
graph has nothing to be a surrogate of.

## Cost discipline

- `seed` / `validate` / cross-module `resolve`: **deterministic, zero tokens**.
- haiku dispatch classification: one cheap call, batched over all candidates.
- differential verifier: opt-in only (env var / explicit flag).

## Modules

| file | role |
|------|------|
| `flowmap/model.py` | schema: `Node`/`Edge`/`Gap`/`Graph`, dedup rules, JSON round-trip |
| `flowmap/seed.py` | deterministic Python call + dispatch extraction (ast + const resolution) |
| `flowmap/resolve.py` | gap-closure: cross-module dispatch (`__import__`, aliased imports) via call-site dataflow |
| `flowmap/orchestration.py` | hook wiring (settings.json) + dispatch-candidate minting |
| `flowmap/haiku.py` | haiku worker: classify dispatch-vs-reference candidates |
| `flowmap/verify.py` | structural gate (free) + differential verifier (opt-in) + sub-flow selector |
| `flowmap/validate.py` | 4-check end-to-end trust lock (refs, edges, call-consistency, golden) |
| `flowmap/render.py` | Graph → Mermaid |
| `flowmap.py` | CLI: `build` (integral verify), `seed`, `validate` |

## Tests

```bash
cd .claude/skills/flow-map && python3 -m pytest
```
Zero live model calls — the recorded haiku verdict is replayed via monkeypatch;
tracers are injected. Golden tests run against the real defender tree and skip
if absent (override with `FLOWMAP_DEFENDER_ROOT`). They double as drift
detectors: if the defender's dispatch wiring changes, the golden assertions fail
and tell you exactly where.

## Status

Proven on the defender: deterministic seed validates end-to-end; the `__import__`
curator-dispatch gap promotes to deterministic edges; haiku resolves the
cross-substrate `skills/X/SKILL.md` dispatch-vs-reference distinction (8/8 vs
hand-labeled ground truth, including the line-402 trap). Not yet built: a single
`map`/`explain` command that fuses the python + orchestration graphs from a
natural-language question and renders at a question-implied altitude (next step).
