# `bind` as the sole policy seam — AgentDefinition consolidation step three (#551)

**Status:** design — approved (ycochav). **Decision:** finish the migration #545/#546
started: make `bind` / `compile_policy` the *single* production deps + policy source
for all seven roles, retire the parallel factory path, and lift the per-role branches
in `bind` to data. This is the deletion payoff #545 deferred when PR #546 narrowed its
task 1 and wired only 2 of 7 roles.

Follows [[agent-definition-single-source.md]] (#538 — the primitive layer) and its
step two (#545 / PR #546 — `bind`/`compile_policy` shipped, MAIN + GATHER rerouted,
`read_shapes` added). Surfaced by the #546 xhigh review. Sibling issues #547 (host-side
run_dir symlink hardening) and #548 (OS sandbox) are adjacent layers, explicitly out of
scope here — this is the **in-process deps/policy seam only**.

## Where step two left it

`bind` is proven *capable* of producing all seven roles — the `parity_*` tests assert
`bind(X).policy == factory_X(...)` field-for-field (`test_bind_wiring_545.py:166-219`).
But production only *calls* it for two:

- **MAIN** → `bind(MAIN_DEF, run_dir, salt=salt)` (`driver.py:479`)
- **GATHER** → `bind(GATHER_DEF, deps.run_dir, salt=deps.salt)` (`tools_gather.py:333`)

The other five still build their own deps via each stage's `for_scope`/`for_run` →
`_for_run(run_dir, <factory_policy>)`. Each is exactly one production call site:

| Role | Site | Factory |
|---|---|---|
| JUDGE | `judge/engine_pydantic.py:173` | `JudgeDeps.for_scope` → `_judge_policy` |
| ACTOR | `actor_engine.py:150` | `ActorDeps.for_scope` → `_actor_policy` |
| ORACLE | `oracle_engine.py:120` | `OracleDeps.for_run` → `_ORACLE_POLICY` |
| VERIFIER | `verify_forward/engine.py:150` | `VerifierDeps.for_run` → `_VERIFY_POLICY` |
| LEAD_AUTHOR | `lead_author_engine.py:173` | `LeadAuthorDeps.for_run` → `_lead_author_policy` |

Consequently **nothing was deleted** — every factory is a live production path, the
#546 diff was net +171 production lines, and the consolidation's payoff (one source of
truth, no drift-by-parity-test) is outstanding. All five `*_DEF` constants already exist
and are registered in `AGENTS` (`agents.py:29`); they are simply never bound.

## Two principles (everything below is derived, not enumerated)

The open decisions the issue lists collapse under two principles plus common sense.
State them once; derive the rest.

1. **One source of truth for policy.** `bind` / `compile_policy` is it. No second policy
   builder is kept alive as parallel production code "kept honest" by a parity test. A
   convenience wrapper is allowed *only* if it delegates to `bind` (an alias is not a
   second source; a re-implementation is).

2. **Tests represent needs; they do not justify themselves.** A test whose only job is
   to guard the parallel path during migration is *scaffolding* — it is deleted when the
   parallel path is, not preserved. What stays (and grows) is the **behavioral** gate
   suite: `decide_bash` / `decide_read` / `decide_write` decisions, which represent the
   durable need. `test_reader_patterns_kept_as_api` does not get a vote on whether a
   factory survives.

3. **Common sense:** no dead parameters, no inert guards, no advertised-but-off defense.
   A signature that promises behavior the code does not deliver is a lie — thread it or
   delete it.

## Derived decisions

### D1 — All seven roles obtain `AgentDeps` via `bind`

Replace each `_for_run(run_dir, <factory>)` site with `bind(<ROLE>_DEF, …)`, translating
each stage's bespoke scope into the unified `RunScope` (documented as their superset at
`agent_definition.py:126`):

| Role | bind form | Scope threaded |
|---|---|---|
| JUDGE | `bind(JUDGE_DEF, run_dir, scope=RunScope(add_dirs=…, ticket_cli=…))` | add_dirs, ticket_cli |
| ACTOR | `bind(ACTOR_DEF, run_dir, scope=RunScope(scripts=…, read_confine=…))` | scripts, read_confine |
| ORACLE | `bind(ORACLE_DEF, run_dir)` | — |
| VERIFIER | `bind(VERIFY_DEF, source_run_dir)` | — |
| LEAD_AUTHOR | `bind(LEAD_AUTHOR_DEF, run_dir, repo_root=repo_root)` | repo_root (kwarg) |

The stages mint a fresh salt (bind's `salt=None` default), unchanged. JUDGE folds
`_ToolScope`'s `add_dir` list→tuple normalization into the call site; ACTOR folds
`_ActorScope` into `RunScope`. The `for_scope`/`for_run` front doors are removed (their
callers now call `bind`), not left as dead wrappers.

### D2 — Write scope becomes data: `write_shapes`, the twin of `read_shapes`

`AgentDefinition` grows `write_shapes: tuple[Callable[[Path, Path], tuple[Pattern]]]`,
resolved by `compile_policy` against the run's roots exactly as `read_shapes` is — the
symmetric completion of what #545 built for reads. Each writer declares its shape:

- **MAIN_DEF** → the run-dir subtree (`build_write_allow(roots.run_dir)`)
- **LEAD_AUTHOR_DEF** → `<roots.defender_dir>/skills/**.md` + the scoped `rm`-of-drafts
  bash grant

`compile_policy` then emits `write_allow` (and the lead-author `rm` pattern) **uniformly**
for every role. This is precisely #545 decision 2 ("compile_policy grows the worktree-
anchored write scope") before the impl diverged to a fork.

Consequence: **the `LEAD_AUTHOR` early-return in `bind` (`agent_definition.py:323-338`)
is deleted.** Lead-author flows through the same `resolve_roots` → `compile_policy` spine
as every other role. The now-live `LEAD_AUTHOR → LeadAuthorDeps` arm in `_deps_class`
(`:296`, dead today because the early-return preempts it) becomes the real dispatch.

### D3 — `defender_dir` threaded through `resolve_roots`

`resolve_roots` gains a `defender_dir: Path = PATHS.defender_dir` parameter instead of
hardcoding `PATHS.defender_dir` (`:187`). This is the **same mechanism** D2's lead-author
de-fork needs (a worktree tree anchoring the write scope) and it simultaneously closes
the MAIN/GATHER latent split the #546 review flagged:

- **LEAD_AUTHOR**: `bind` derives `defender_dir = repo_root / "defender"` and passes it
  through — no bespoke arm.
- **MAIN/GATHER**: `run_investigation`'s `defender_dir` param is already live on the
  *prompt* side (`build_agent`/`_user_prompt`); routing it into the gate anchor too
  removes the inconsistency where the prompt describes tree X while the gate validates
  `PATHS`. This is not speculative capability — it makes an existing param honest. Every
  caller passes a `PATHS`-equal value today, so it is behavior-preserving; it stops being
  a silent "gate validates the wrong tree" for any future worktree/temp-tree run.

One "thread the caller's tree root through `resolve_roots`" concept covers both D2 and D3.

**Both anchors, not one (found by the #551 executable-spec pass).** `bind` produces the
policy *and* the `AgentDeps`, and the runtime gate reads `deps.defender_dir` (not the policy)
for read/write containment. `bind`'s `_for_run(run_dir, policy, salt=salt)` tail passes **no**
`defender_dir`, so `deps.defender_dir` defaults to `PATHS` for every non-lead-author role.
Threading `defender_dir` into `resolve_roots` **alone** therefore anchors the *policy* on the
worktree while the *deps field* stays `PATHS` — a split that denies every worktree corpus
read/write (a total brick, invisible to canonical-`PATHS` fixtures). So `bind` must thread
`defender_dir` into **both** `resolve_roots` and `_for_run`; `deps.defender_dir` and the policy
anchor are one tree. (`ResolvedRoots.corpus_roots` is a dead field — computed but never consumed
by `compile_policy` — so it is *not* a second anchor to worry about; `_for_run` is.)

**Resolved forks (from the write-tests step-7 pass, ycochav):** (Q1) keep `_judge_policy`/
`_actor_policy` as `compile_policy`'s pattern helpers — only their `for_scope` front-doors are
deleted; (Q2) full data-drive — a `requires_explicit_tree` data bit + unify the lead-author
worktree into the `defender_dir` param (drop `repo_root`), so no `if role is X` branch remains;
(Q3) `compile_policy` asserts `write=True ⟺ write_shapes` non-empty; (Q4) `bind` hardens its root
inputs (relative/degenerate roots and a lead-author main-checkout tree are unbuildable).

### D4 — Actor confine precondition as data, not a role branch

Replace `if defn.role is AgentRole.ACTOR and not scope.read_confine: raise`
(`agent_definition.py:339`) with a declarative `requires_confine: bool = False` bit on
`AgentDefinition` (set on `ACTOR_DEF`), checked generically in `bind`. The fail-loud is
correct and preserved (an empty confine widens the actor to the whole `defender_dir` —
the #512 gray-box leak); only its altitude changes. `_ActorScope` already half-owns this
via its required kw-only `read_confine` field — the data bit is the `RunScope`-side twin.

After D2/D4 **no `if defn.role is AgentRole.X` branch remains in `bind`.**

### D5 — The parallel factory path retires

Under principle 1, split by kind:

- `_ORACLE_POLICY` / `_VERIFY_POLICY` are deny-all constants — they already equal what
  `compile_policy` emits for an empty `ToolSet()`. They fold away.
- `_lead_author_policy`'s logic moves into `compile_policy` via D2's `write_shapes` + the
  `rm` grant. Deleted.
- `_judge_policy` / `_actor_policy`: `compile_policy._bash_allow` (`:218-223`) already
  *reuses* their `.bash_allow`, so they cannot be naively deleted. Reduce them to
  **pattern-builders** (`_judge_bash_patterns` / the actor's `_script_pattern`) reachable
  by `compile_policy`; the full-`AgentPolicy` constructors go. The remaining fields
  (`read_confine`, `raw_reads`, `deny_reason`) are already data on the def / scope.
- `main_policy` / `gather_policy` / `policy_for`: demoted to **one-line aliases that call
  `bind`** (`policy_for(agent, run_dir, defender_dir) → bind(<DEF>, run_dir, …).policy`).
  Twelve gate-test files consume `policy_for` as an ergonomic policy handle (a real need);
  an alias serves it without being a second source. `reader_patterns_for` stays (production
  — `_bash_allow` calls it); the unparametrized `reader_patterns` follows `main_policy`/
  `gather_policy` if it loses its last caller.

### D6 — Wire the `write ⊆ read` guard

Both writer call sites pass the run roots: `decide_write(p, content,
run_dir=deps.run_dir, defender_dir=deps.defender_dir, policy=deps.policy)`
(`tools.py:304`, `:356`). `deps` already carries both. This activates the dormant
defense-in-depth (`files.py:217`) — a no-op for every real writer (MAIN writes ⊆ run_dir
⊆ reads; LEAD_AUTHOR writes ⊆ skills ⊆ defender_dir reads), so behavior-preserving.
Advertised-but-inert is the one unacceptable state (principle 3).

### D7 — `jq_operand_gated` stays, out of scope (corrected framing)

Not a wart to delete. Allowing `jq` by operand *is* whitelisting `jq` on paths:
`_jq_reads_within_roots` calls the same `read_allowed_path` routine `decide_read` uses, so
the judge's bash lane and read tool already confine to one roots set through one mechanism
— which is #535's stated "one roots set, two surfaces" end-state, not a legacy holdout.
It flows through `compile_policy` cleanly as data (`agent_definition.py:252/256/259`) with
no role branch, so it is *already* declarative and untouched by #551. The live design
question it raises — unify all viewers under operand `resolve()`-gating vs. textual
anchored-regex (the #379 parser-parity stance) — is a separate call under the judge-off-
`jq` follow-up, not this issue.

## Test fate (principle 2, made concrete)

- **Delete with the factories:** the `parity_*` tests (`test_bind_wiring_545.py:166-219`)
  — scaffolding with no RHS once the factories are gone; the tautological
  `test_parity_lead_author_nine_fields:211` (bind *calls* `_lead_author_policy`) among
  them. Same for the factory-side cross-parity in `test_agent_deps_construction.py`.
- **Keep (they represent the need):** the behavioral gate tests —
  `test_lead_author_write_anchored_worktree` / `test_lead_author_rm_scope_preserved`
  (drive `decide_write`/`decide_bash`), the `read_shapes` read↔bash parity tests, the
  actor-confine fail-loud, salt carriage.
- **Add:**
  - **Symlinked-root read gate.** Every #545 fixture is canonical (`tmp_path`/`PATHS`
    already `resolve()`d), so the read-gate `.resolve()` mismatch (fixed in #546) has no
    guarding fixture. Add a symlinked run base (`link → real`) driving `decide_read` of a
    run-dir file, asserting `read == cat` parity. (Do **not** re-fix the mismatch — #546
    already did; add the fixture the PR lacked.)
  - **Non-`PATHS` `defender_dir`** for MAIN/GATHER (now that D3 threads it): a worktree
    `defender_dir` anchors the gate on the caller's tree, not `PATHS`.
  - **De-tautologized lead-author write scope**: `bind`'s output compared against an
    independently-constructed expectation (or simply the behavioral `decide_write` tests
    above, which never referenced the builder).

## Acceptance criteria

- All seven production deps sites obtain `AgentDeps` via `bind`; a grep for
  `_for_run(` / `for_scope(` / `for_run(` outside `bind` and the tests returns nothing in
  the stage modules.
- No `if defn.role is AgentRole.X` branch in `bind`; per-role preconditions/policies are
  data on `AgentDefinition` / `RunScope`.
- The parallel factory constructors are deleted or demoted to bind-aliases — no
  field-for-field parity test guards two live production policy sources.
- `defender_dir` threaded through `resolve_roots`; the `write ⊆ read` guard wired; no dead
  param, no inert guard.
- New symlinked-root read-gate test green; no tautological parity test remains.

## Non-goals

- Re-fixing the `read_shapes` `.resolve()` mismatch (landed in #546).
- The judge-off-`jq` migration / removing `jq_operand_gated` (separate #535 follow-up).
- OS-sandboxing the run (#548) or host-side run_dir scrubbing (#547) — adjacent layers.
