# Phase F — gate mechanically, then reconcile (step 9)

## Topology

- Sequential dispatches with single-writer outputs. Reader findings route through §7, never straight into the diff.
- **Mechanical-gate leaf** (Sonnet, high effort — the toolchain computes the findings): inputs = the suite, the spec_graph. Output: `90-mechanical.md`, including the questions for the blind reader. It may repair test-level defects (the integrator ran the same tools, so repairs should be rare — record each; a pattern of them is a finding on phase E).
- **Blind reader** (Sonnet, high effort — the isolation is the instrument): inputs = the tests and the generated questions **only** — never the intent doc, and the dispatch prompt must not paraphrase it. Output: `91-blind.md`.
- **Cold reconciler** (Opus, xhigh effort, fresh — never the orchestrator, never a phase-E leaf): inputs = the full frontier chain *including `91-blind.md`*, the artifact, the working diff. Output: `92-reconciliation.md`. It runs after the blind reader so the blind findings have a reader: in one measured run nothing downstream consumed them.
- **At most one repair.** Test-level findings go to one repair leaf (the integrator's charge, fresh; output `94-repair.md`), then the mechanical gate re-runs. Findings needing a ruling go to §7 first. A second reconciler pass runs only when the first found something material (a ruling, a blocking defect) — later rounds in the measured runs were mostly minor.

## Charge — the mechanical-gate leaf

Read **references/rules.md**, "Suite verification". Reject or repair any test that fails these — they are what makes a test bind, not style. Repair test-level defects in place; anything judgment-shaped is a finding for §7.

**Run the toolchain first** — every command below is on your PATH (the plugin ships `spec-graph`); each exits 0 clean, 1 with findings, 2 when it could not look (a 2 is itself a finding, never a pass):

```
spec-graph lint <artifact>                      # formal slots vs schema.md's closed vocabularies
spec-graph gate <artifact>                      # R0 formal half + R1–R5/R7 triggers vs the recorded gate
spec-graph binds <artifact>                     # prose ⊄ binds + unexercised seams + dangling pointers
spec-graph claims <artifact>                    # probe instruments + spend-point citations
spec-graph calls <suite-dir>                    # AST: every test reaches the target (or --target)
spec-graph nullstub <suite-dir> --python <interp>   # null-stub discrimination, classified per test
spec-graph frontiers <frontiers-dir>            # frontier shape over the whole chain
```

Run the suite only through these commands or by its own files — never the project's full suite, and never a background run polled from a sleep loop (author.md, "Run only this suite's files").

Then work the residue the tools name and the checks only you can run:

`spec-graph actors` is deliberately absent here: before implementation, the branch has no production-code diff for that checker to follow. Confirm the graph and `handoff.deferred` record the planned execution-context census; write-code-from-spec §3 runs the mechanical check once real code exists.

- **Null-stub triage.** `nullstub` generates the stub, runs the suite, and classifies: a `NULLSTUB-PASS` is vacuous unless you record it per-test with its class (structure / reuse / parity) in `handoff.nullstub_passes` — prefer strengthening the test so it fails; a `NON-ASSERT` rides machinery instead of failing on its own demand-specific assertion — repair it to reach its assert; a `BROKEN`/collection entry proves only that the file is broken. Scan the classified failures for many tests failing on the SAME assertion line or message — a shared same-file helper's assert certifies as discrimination for every test that funnels through it, but it is one test's discrimination and everyone else's ride; rules.md's own-demand-specific-assertion requirement is still yours to verify, no tool checks it. The stub lives in a temp dir and is never committed. The target's own import failing in the *real* (un-stubbed) suite is the expected red; do not repair it by committing skeleton source.
- **Beyond `calls`' reach:** no test asserts only against a value its own body computed — the expected side of every assertion traces to the demand or a fixture, never to a re-implementation of the target's logic. And no assertion depends on an `nl:` prose slot's wording — `nl:` is for humans, and `lint` lints the artifact, never the suite.
- **Assertions sit at observable seams; fakes inject faults, not policy.** Reject a fake that classifies or decides (any branching beyond returning its spec'd fault) and any assertion that reaches into internals.
- **Discharge is by demand or waiver, never by a claim.** `gate` and `binds` verify the pointers resolve; you verify the semantics: a probe does not discharge a test — a tolerance that was *probed* and never *pinned* ships untested. If it was probed, it earns a demand. Every fake's fault content cites the claim that observed it; a claim left `unprobed` is a finding for §7, not a pass; a claim only the not-yet-written target can settle is `deferred` and enumerated in the handoff. The ledger lives IN the artifact — a side file leaves every citation dangling. (The `binds_waivers`/`exercise_waivers`/`actor_waivers` maps cannot carry `cites`, so their citations are yours to check by hand.)
- **No assertion contradicts the ledger.** Scan every test's expected-side literals against the refuted and stale-marked claims: a test asserting content a refutation corrects has pinned the bug green — repair the test to pin the correction, and never resolve the contradiction by weakening the refutation. Neither the null stub (the assertion is true against today's real code) nor conservation (it maps demands to tests, not assertions to claims) can catch this class.
- **Every negative has its paired positive control**, and binds (or explicitly waives) each of its actor's out-edges.
- **Waiver hygiene for the code-census checks.** `binds`' unexercised-seam finding means the demand claims a wiring and the test checks a shape — drive `A` and assert the observable outcome, or record an `exercise_waivers:` entry; `actors`' unmodelled driver means an execution context the graph never saw — model it as an actor, or `actor_waivers:` an out-of-scope one, but never silence a subprocess re-exec driver to go green. The input-partition slice (a guard's invalid domain modelled as one bucket) is NOT graph-mechanizable — it wants property-based / mutation testing at impl time (write-code-from-spec §3).

For the blind reader, generate pointed questions from **both sides** — one per intent obligation, asked in the obligation's own surface-general terms ("can an input vanish with no visible trace?"), and one per test ("which obligation needs this?") — then diff the reader's answers against the doc. An obligation the tests can't answer is **undischarged intent**; a test no obligation explains is **invented scope or a silently-resolved fork**.

Digest: checks passed, repairs, findings for the human, null-stub passes.

## Charge — the blind reader

You receive a test suite and a list of questions; you have not seen the design and must not seek it — your ignorance is the instrument, and an anchored reader confirms instead of measures. Answer every question from the tests alone. "Unanswerable" is a first-class verdict, not a failure — say it plainly when the tests don't determine an answer. Then one open-ended cold read: state the intent this suite implies, as if reverse-engineering its spec — this backstops the questions neither side generated.

Digest: questions, answered, unanswerable, findings.

## Charge — the cold reconciler

Read the run's artifact trail — the frontier chain from `10-brief.md` through `88-author-digest.md`, the ledger, the gate record — against the working tests + spec_graph diff, and answer one question: *does the spec conserve everything this run learned?* Spend your judgment where no later net reaches. The adversarial implementer (write-code-from-spec §2) holds the *stated-intent* lane — an exploit that greens the suite while violating a written obligation is its game, so **composition** (two facts individually pinned, jointly an escape) and **altitude** (a demand pinned at a different grain than its premise asked) are its sweep now: flag them when they stare at you (a finding here costs one §7 round; the adversary's costs a post-spec kickback), but do not sweep those lanes. What the adversary structurally cannot attack is learning that never became a stated clause, and that is your charge: **a `no-consequence` dismissal that looks load-bearing** (conservation confirms the fact was dispositioned; only judgment catches a wrong call), and **a consequence the run absorbed silently** — a probed fact whose implication surfaces in no demand, claim, or dismissal; a resolution applied narrower than the human's words. You read hot on purpose — the mirror of finalize's deliberate cold read: one checks the artifact without the rationale, you check the rationale all made it into the artifact.

**Walk the trail by name — this is the run's conservation check.** Every judged premise resolves to a demand's test, a §7 record, or a `handoff.drops` entry with its reason; every flagged brief fact to a premise, claim, or `no-consequence` note; every §7 ruling, tension, and outside-the-threat-model drop to the tests or demands it changed; every probe result to the answer it confirmed or overturned. In the measured runs this walk — not any count — is what found the real drops: a fact the brief raised and nobody dispositioned, a ruling pinned nowhere. Then read `91-blind.md`: each blind finding is a weak or unexplained test to confirm or dismiss against the doc — the blind reader cannot tell a deliberate ruling from invented scope, so dismiss those that restate a §7 ruling, and carry the rest. Execute a probe wherever a finding turns on what the tests actually do (the blocking defect one run shipped to this phase — 13 tests contradicting a ruling through a shared fixture — was found only by running it).

Digest: findings (material first), trail items checked, blind findings carried and dismissed.
