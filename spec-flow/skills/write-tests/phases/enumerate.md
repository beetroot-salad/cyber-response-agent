# Phase B — enumerate situations (step 3)

Five parallel leaves: four lensed enumerators (Sonnet) and one unlensed **strong author** (frontier model — do not economize here; a blind A/B found the cross-cutting, grounding-dependent faults capability-dominated: the lenses miss them at any skill quality, and only a frontier backstop recovers them reliably). Each dispatch names its lens as a parameter; each writes its own frontier `30-premises-<lens>.md` (the strong author writes `30-premises-author.md`). Inputs: this contract, the intent+design doc, `10-brief.md`, `20-demands.yaml`. **Never launch before `10-brief.md` is complete** — ungrounded, a lens invents scary-sounding inputs that map to nothing; anchored to the brief, it enumerates faults the surface actually admits.

## The charge (all five)

The design is silent about most of what can go wrong; enumeration supplies the missing situations. The catalog is a fault taxonomy, not a happy-path list: dependency errors (transient, permanent, timeout, malformed response), bad input (empty, missing, malformed, duplicate), partial failure, ordering, re-run / idempotency, output-side I/O failure.

Take an **actively adversarial** posture — find the input, ordering, or path that slips past the obvious implementation — and enumerate against the **intent section as well as the design**: a design that narrowed a surface-general obligation to three enumerated surfaces is exactly where the fourth surface never enters the space.

Work the **language lane only**, and write **the premise, not its answer.** Emit **premise stubs — a test signature + a docstring stating the *situation* only, no intended outcome and no body** — in intent-space. The outcome is the next phase's to measure; a lens that writes the outcome has pre-answered its own question and destroyed the measurement.

```python
def test_transient_enrich_error():
    """one enrich() call fails transiently while its siblings succeed — what must be observable?"""
    # fork: skip-and-continue vs abort-the-batch — this outcome is a known decision
```

A premise that names a mechanism-level fact — an exception class, a primitive's return shape, what existing code does — has left its lane: strip the fact into a **probe obligation** listed in your frontier and keep the situation. The one exception: a fact that belongs to the *not-yet-written target* (how it signals failure, what it returns) has no probe to run — that is demand #0's territory or a human fork, never a probe obligation. The fault menu is reality's to supply (phase E), not yours to guess. When a premise's outcome is a known judgment call, mark it `# fork:` so phase C routes it to the human regardless of how the answerers land — a silently-chosen branch otherwise leaves no trace it was ever a choice.

## The lenses (one each, independence from perspective)

Identical prompts converge on the same blind spots; independence comes from perspective, not sampling. Three lenses are near-universal: **dependency**, **input surface**, and **lifecycle/state**. The fourth slot goes to the design's danger zone: **adversarial input**, **environment/resource**, or **concurrency** — the profile's `conventions.dangerLens` names the project's standing default; the orchestrator passes the chosen lens and takes the default unless *this* change's danger zone is plainly elsewhere.

## The strong author (unlensed, frontier model)

You are the net under the unknown-unknown region — the complement of both the lenses and the gate rules: the graph rules compute the *known* pit shapes; you cover the unknown ones and the misclassified seams. You are also explicitly charged with the brief's edges: hunt for elements the grounding pass may have missed — a co-writer, a consumer, a surface the brief looks thin on — because an element absent from the graph is invisible to every rule, and this derivation is the only net under that hole. List every suspected brief gap in your frontier's `red_flags`.

## Frontier

Each leaf's frontier carries the premise stubs plus header inventory `{premises: n, probe_obligations: n, forks_flagged: n}`, `inputs` echoing the brief's `flagged_facts` count (state which facts fed a premise of yours — phase F's conservation walks this edge), and `red_flags` for anything that smelled like a design hole while enumerating.
