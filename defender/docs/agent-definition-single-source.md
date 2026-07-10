# The agent definition: one source of truth for an agent's tools + permissions

**Status:** design — implemented (step two: #545 / PR #546; step three: #551 / PR #555,
which made `bind` the sole policy seam and retired the parallel factory path — see
[[agent-definition-consolidation-step-three.md]]). **Decision:** collapse the two
capability carriers (`AgentSpec` at build time, `AgentPolicy` on `deps`) plus the
scattered model/effort constants into a single per-agent **`AgentDefinition`** that
*both* the build site and the permission gate read. Authorship stays per-agent (the
`[[agent-role-primitive]]` convention); an agent's definition may be **split across
separate files** — prompt / permissions / config — within its own dir, collected
into one registry for lookup. Forcing function is **#538** (a genuinely tool-free
build for the pure-prediction stages, oracle + verify-forward).

Builds on **#493** (the single `build_agent_core` site), **#512 / #517 / #522 /
#526** (per-agent `bash_allow` + read confinement as policy-*data*), **#536**
(required `policy` on the deps base), and the two-engine capability surface in
`agent-harness-construction-design.md` (#480). The permissions half is reconciled
with **#535** (the gather+main read-confinement slice), which reshapes it. The real
read/write boundary is OS sandboxing (**#540**); this gate is defense-in-depth that
holds before/without the sandbox and stays as belt-and-suspenders after.

## The problem: capability is smeared across two carriers and two mechanisms

"What can this agent do" is answered today by two objects with different lifecycles,
plus a third scatter for model/effort:

| Facet | Where it's decided | How it's enforced |
|---|---|---|
| write_file / edit_file | `AgentSpec.writers` (build-time, `driver.py`) | **non-registration** — the tool never exists |
| bash / read_file / adapters / raw / roots | `AgentPolicy` (on `deps`, runtime, `permission/policy.py`) | **always registered, then gated** by `decide_bash` / `decide_read` |
| model + effort | `learning/core/config.py` env constants (learning) or `resolve_main_model` / `gather_model` (runtime) | consumed at build via `AgentSpec` |

Two symptoms follow:

1. **Two enforcement mechanisms for one concept.** Writers are gated by *absence*;
   bash/read by *runtime deny*. `register_tools` (`tools.py:309`) *always* registers
   `bash` + `read_file`, then conditionally adds the writers iff `writers`. So the
   `{bash, read_file}` half of "which tools exist" is expressed **nowhere** — it is
   hardcoded. #538 is the direct symptom: the pure-prediction stages want *structural
   absence* of the read/bash pair, and that lane only exists for writers.

2. **No object binds an agent's tools to its permissions.** `AgentPolicy` is
   constructed at six scattered sites (`permission/policies/{main,gather}.py`;
   `pipeline/judge/engine_pydantic.py`, `pipeline/actor_engine.py`,
   `pipeline/oracle_engine.py`, `author/verify_forward/engine.py`) and stamped onto
   `deps` via `_for_run` / `for_scope`. The build site never sees the policy; the gate
   never sees the spec. They co-occur only at the per-stage call site.

## The reframe: `deps` is a mechanical carrier; the definition is the source of truth

`AgentDeps` (`tools.py:93`) holds `run_dir`, `defender_dir`, `run_id`, `salt`,
`policy` (by value), and a `role` ClassVar. It is PydanticAI's per-`.run()`
dependency-injection payload — the runtime context threaded into every tool call and
the gate via `RunContext.deps`. It *carries* the policy but does not *define* it, and
it does not carry the build settings (model/effort/registration) at all. That is the
correct role for `deps`, and it stays.

The design turns on one invariant the code already respects:

> **Tool *presence* is always static; only a tool's *permission detail* is ever
> run-scoped.** Whether `read_file` exists for an agent never depends on the run —
> only its *roots* do (the judge's comparison dir, the actor's confine, and — after
> #535 — main/gather's `RunPaths`-derived roots). So **registration** derives from
> static presence; **gating** derives from resolved detail. One definition feeds both.

## The shape

```python
# STATIC — the single per-agent source of truth (authored in the agent's own dir).
@dataclass(frozen=True)
class AgentDefinition:
    role:        AgentRole
    model:       Callable[[], str]         # thunk: keeps env / --model override live
    effort:      str | None
    tools:       ToolSet = ToolSet()       # presence + static capability
    corpus_dirs: tuple[str, ...] = ()      # relative names: "lessons", "skills", "examples"
    read_shapes: tuple[ReadShape, ...] = ()  # the ~6 tight filename grammars (#535)
    deny_reason: str = _DEFAULT_DENY_REASON

@dataclass(frozen=True)
class ToolSet:
    read:  bool = False                    # register read_file? (confined to resolved roots)
    bash:  BashGrammar | None = None       # None → unregistered; else the static program grammar
    write: bool = False                    # write_file + edit_file (gate = run_dir containment)

@dataclass(frozen=True)
class BashGrammar:                         # STATIC: which programs; which operand slots anchor
    shims:            tuple[str, ...] = ()  # defender-lessons, defender-invlang, cd
    viewers:          tuple[str, ...] = ()  # cat, grep, tail, wc, find, ls, sed
    adapters:         bool = False          # gather: structural adapter routing
    adapter_sql_pipe: bool = False          # gather: adapter | defender-sql
    operand_gated:    bool = False          # judge: cat's file operands path-gated at resolve()
    raw_reads:        bool = False          # judge: declared (no adapters bit to imply it)
```

Two things fall out. `AgentSpec.writers` becomes `tools.write`, and writes need **no
policy field** — their only gate is `run_dir` containment (`decide_write`), which is
structural, so the presence bit *is* the write capability. And `AgentPolicy` becomes
the resolved runtime projection of `tools` + roots — a *derived artifact*, not an
authored one.

**One resolution seam.** `bind` replaces the six `_xxx_policy` factories and the
`for_scope` / `for_run` deps constructors:

```python
def bind(defn: AgentDefinition, run_dir: Path, *, scope: RunScope = RunScope()) -> AgentDeps:
    roots  = resolve_roots(run_dir, defn.corpus_dirs, scope)   # RunPaths + corpus + judge/actor extras
    policy = compile_policy(defn.tools, defn.read_shapes, roots, defn.deny_reason)  # anchored allowlist + read roots
    return AgentDeps(run_dir=run_dir, defender_dir=PATHS.defender_dir,
                     run_id=run_dir.name, salt=uuid4().hex, policy=policy)
```

`compile_policy` emits today's `AgentPolicy` as the gate's internal type, so
`decide_bash` / `decide_read` do **not** change in step one. `build_agent_core` takes
the `AgentDefinition` and registers exactly the present tools (`AgentSpec` and the
always-on `register_tools` branch delete).

**Authorship stays per-agent, split by concern is acceptable.** Each agent's module
exports its `AgentDefinition` (co-located with its `prompt.md` + deps subtype), and a
thin collector aggregates them: `AGENTS = {d.role: d for d in (MAIN_DEF, GATHER_DEF,
…)}`. The prompt, the permissions (the `ToolSet` / `BashGrammar`), and the config
(model/effort) may live in **separate files** in the agent's dir — the collector is
the single lookup surface, not the single authoring file. This honors
`[[agent-role-primitive]]` ("config in the agent's own dir; no per-role gate
methods") while giving one place to read every agent's tools + permissions.

The six agents, in this shape:

| Agent | `tools` | Roots source |
|---|---|---|
| main | `read=True`, `bash=BashGrammar(shims, viewers)`, `write=True` | `RunPaths` + corpus (per-run after #535) |
| gather | `read=True`, `bash=BashGrammar(viewers, adapters=True, adapter_sql_pipe=True)` | `RunPaths` + corpus (per-run after #535) |
| judge | `read=True`, `bash=BashGrammar(operand_gated=True, raw_reads=True)` | + comparison dir (via `scope`) |
| actor | `read=True`, `bash=BashGrammar()` | + confine + pinned scripts (via `scope`) |
| **oracle** | **`ToolSet()`** — nothing | — |
| **verify** | **`ToolSet()`** — nothing | — |

## Reconciliation with #535 (the permissions half)

#535's settled design reshapes the policy for gather + main. It does **not** touch
oracle/verify (they have no bash lane), so it is orthogonal to #538's tool-free part
but load-bearing for the consolidation. Four points shape the `AgentDefinition`:

1. **main/gather become per-run.** `run_dir` threads into their policy construction,
   exactly like the judge's already does. After #535, four of six agents are
   run-scoped; only oracle/verify are truly static. The `bind` seam becomes the norm,
   not the exception.
2. **One roots set, two surfaces.** The #512/#535 thesis is that the `read_file` tool
   (`decide_read`) and the bash lane must confine to the *same* roots. So roots are a
   single resolved set; the tool uses `resolve()`-containment, the bash lane uses
   tight anchored grammars (a regex can't `resolve()`). Do not specify read-roots and
   bash-anchoring independently.
3. **Roots are derived, not literal.** From `RunPaths` + a short corpus-dirs list
   (`lessons/`, `skills/<sys>/`, `examples/`, `gather_summaries/`) so they can't drift
   from the layout (`[[defender-paths-primitive]]`). Hence `corpus_dirs` (relative) in
   the definition; `bind` resolves absolutes.
4. **`viewer_patterns()` / operand-extraction retire for gather/main.** `cat` is the sole
   file-reader; `jq` / `defender-sql` only consume a pipe. The judge keeps a `resolve()`-based
   operand gate (`operand_gated`), now pointed at `cat` rather than `jq` — its `gather_raw`
   reaches it only through `read_roots`, which the textual anchors cannot express. So
   `BashGrammar` is a declarative program grammar that `bind` compiles against the roots —
   not raw pre-compiled patterns.

## Deliverables + sequencing

**#538 is two separable deliverables, and #535 blocks only one:**

- **Tool-free predictors (ship now, standalone).** oracle + verify → `ToolSet()`:
  register nothing, drop `ORACLE_REQUEST_LIMIT` / `VERIFY_REQUEST_LIMIT` from 6 to 1
  (no tool can be called, so the only reason for headroom above 1 is gone), and flip
  the toolset-pinning tests (`test_oracle_pydantic_engine.py:140`,
  `test_actor_pydantic_engine.py:218`, `test_harness_b_construction.py`) so the
  pure-prediction build pins an *empty* toolset. Orthogonal to #535; carries the
  security value.
- **`AgentDefinition` consolidation (land with / after #535).** #535 already moves
  main/gather to per-run policies and deletes the global-viewer surface — exactly the
  special cases the consolidation otherwise has to preserve. Consolidating before #535
  means unifying a structure that is about to change underneath it.

## Why the predictors are tool-free (not just "unused, so remove")

Both stages are handed a **deliberately narrowed** slice of the world; a registered
`read_file` is an escape hatch that lets the model re-widen it. This holds *without*
assuming the model chooses to cheat — the point is not to leave the barrier open.

- **oracle** is a gray-box projector. `redact_exemplar` (`pipeline/oracle/sample.py`)
  reduces each `gather_raw` payload to a **value-scrubbed skeleton**; `sanitize_wtc`
  strips concrete timestamps; the `goal` is withheld. The docstring is explicit:
  *"leaking the defender's real result would contaminate the projected-vs-actual
  compare."* The payload *is* handed to it (as a skeleton, assembled in Python) — it
  needs no tool to get it, and reading real values would **break** the compare, not
  help it.
- **verify-forward** is a *conditional* predictor: it is handed the full transcript,
  the lesson, and the **target disposition itself** (`forward.md`'s "CASE GROUND-TRUTH
  DISPOSITION"), and asked "would this lesson still land on X?" The transcript is the
  faithful ground; nothing readable makes the conditional more faithful. A genuinely
  more faithful check would be a full agent re-run — which this deliberately is not (a
  cheap single-call same-case proxy). The only artifacts a tool reaches that aren't
  inlined are answer-bearing: `source_refs.yaml` (`normalized_disposition`, **not** on
  the read denylist) and `report.md`'s frontmatter. Reading them is answer-peeking,
  not fidelity. Sharpest in the **benign direction**, where `expected_disposition`
  hands the verifier the *corrected* target (`benign`) while `source_refs.yaml` still
  holds the *recorded* (`malicious`) call — a stray read there **contradicts** the
  check.

## Open questions / follow-ups

- **Run-scoped carriage.** `RunScope` value + `_fold_scope` function (keeps
  `AgentDefinition` a flat data literal) vs. a `scope_resolver` callable field vs.
  per-agent subtypes. Leaning `RunScope` + `resolve_roots`, confining the
  "judge/actor/main/gather are dynamic" knowledge to one function. Note the symmetry
  that justifies it: main's `--model` override is an invocation-scoped input on the
  *build* side exactly as roots are on the *gate* side — one "bind to this invocation"
  concept covers both (hence `model` as a thunk).
- **Gate reads `AgentPolicy` vs. reads `ToolSet`/caps directly.** Step one keeps
  `AgentPolicy` as the gate's resolved type (`compile_policy` projects into it) so the
  gate + its tests don't move and #538's tool-free part ships as a side effect. Fold
  `AgentPolicy` into the caps as a later clean-up.
- **Judge off `jq`-over-files** (#535 follow-up) — **DONE.** The judge runs
  `cat {file} | defender-sql '<SQL>'` / `read_file`. `_jq_input_files` + the jq option
  grammar deleted; `jq_operand_gated` became `operand_gated`, retargeted from `jq` (whose
  argv opens files via `-f`/`-L`/`--slurpfile`/`--rawfile`/`--argfile` and short-bundle arg
  consumption, needing ~60 lines to decide "which files does this open?") to `cat` (no
  arg-taking flag, ~10 lines). `raw_reads` moved from *inferred* to *declared* on
  `BashGrammar`: the judge has neither `adapters` nor `adapter_sql_pipe` to imply it, and
  the `defender-sql` shim is not the `adapter_sql_pipe` route.
- **#540** — OS-sandbox the run as the real boundary; once it lands, operand-anchoring
  can relax to a pure program allowlist and the tight `read_shapes` grammars simplify.
