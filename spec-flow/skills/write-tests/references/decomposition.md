# Decomposition — cutting a task into subagent dispatches

**Status: working guidance, validated retrospectively against real decomposed work; the real test is
live use.** The tests below distinguished sound cuts from lossy ones on past arcs and forced two
corrections (the *frozen-means-grounded* referent rule; the execution-context census as a separate
check). This is a decision procedure, not a proven algorithm.

When a task is too large to hold in one focused context, cut it into pieces that each run as a
**separate subagent dispatch** — a fresh context handed only that piece's dossier — and reconcile
their results in the parent. The gain is not throughput, it is **focus**: a subagent carrying only
what its piece depends on reasons without the contamination of the rest of the task, and can run on a
cheaper model. Running the pieces sequentially in one growing context is the anti-pattern this exists
to replace — it re-accumulates exactly the contamination the cut was meant to shed.

A bad cut is worse than one big context. It splits a correctness property across two dispatches so
each returns green while the whole is broken (composition failure), or it fans out over a list you
never proved complete so the clean pieces certify the gap (enumeration failure). This doc is how to
know a cut is sound *before* you dispatch it.

No cutting algorithm exists — the seams are discovered, not given, and finding them is most of the
design work. What follows is a decision procedure: a criterion for *where*, two tests for *whether a
leaf is dispatchable*, a check for *what the demand tests can't see*, and two diagnostics that point
at the piece you haven't cut yet.

## The criterion — information hiding on the stable/volatile axis

Cut so each dispatch encapsulates one decision that is **likely to change**, behind an interface
derived from what is **stable**. For a feature with clear product intent but an unconverged technical
design you already know which is which: the product intent is stable, the technical design is
volatile. So the seams fall where a volatile technical decision meets a stable contract — put each
unknown behind an interface the intent pins.

Consequence: **you cannot cut space before you cut time.** You can't dispatch against interfaces that
don't exist yet, and for a weak-design feature they don't. The first cut is temporal — spike the
volatile decisions until each *visible* seam becomes a *verifiable* one (below), freeze the
interfaces, and only then fan the build out into dispatches.

## The unit is a dispatch, not a step

Each leaf is one subagent call. Its **dossier** is everything its correctness depends on and nothing
else. The parent does not do leaf work — it holds the seams, dispatches the leaves, and reconciles
their outputs. The instant the parent starts doing a leaf itself, its own context is contaminated and
the decomposition has bought nothing: keep the orchestrator thin.

## The two tests — a leaf is dispatchable iff both hold

Both are stated in **acceptance criteria** (demands), so both are checkable, not felt.

### Local (per dispatch): closed dossier ⟺ boundary-checkable output

A leaf is dispatchable iff you can write its acceptance criteria **now**, citing only an *external,
pre-existing, grounded* referent — a stable product contract, a frozen interface, or a probe of
existing reality — and **never** a sibling dispatch's output or an internal snapshot of the intended
solution.

These are two faces of one property. *Cites only external referents* means the dossier is **closed**
— the subagent needs nothing from its siblings, so it fits its context and reasons without cross-talk.
*Acceptance writable now* means the output is **checkable at its boundary** — the parent (or a
verifier subagent) can grade it without loading the siblings. A leaf that fails either is not really
separable; the coupling you had to pull in is the coupling you failed to sever.

Two qualifiers on the referent, because a referent can be self-consistent and still wrong:

- **Not a context-dependent proxy.** A referent that resolves to different things in different
  execution contexts is a trap — the leaf verifies green in the context you tested and false-positives
  elsewhere. "Is my referent the real thing, or a proxy that happens to equal it here?" is part of the
  test, not a footnote.
- **A frozen interface that wraps an external system is a proxy until a probe grounds it — its
  *failure* semantics above all.** A written, frozen contract can be cited honestly and still be wrong
  about the real system it abstracts (an assumed exception the real tool never raises; an assumed
  return the real tool never gives). A frozen interface is a referent's *shape*, not its *behaviour*;
  the behaviour is a probe against the real system (a `behavior`/`primitive` ledger claim, rules.md).
  **"Frozen" must mean grounded, not merely written down** — this is the sharp edge of
  cut-time-before-space.

### Global (the partition): the dispatches' demands compose

The union of the leaves' acceptance criteria plus the seam contracts must reconstruct the **whole
task's** acceptance. The parent owns this reconciliation. Practical form: read only the dispatch
dossiers and their returned outputs — can you rebuild the whole's acceptance? If not, the cut is
lossy; it validates something weaker than the task.

This catches the **enumeration gap** always (a missing dispatch makes the union fall short), and
**composition-blindness when the spanning invariant is a stated demand** (reconstructing the whole
forces that invariant to be owned by some leaf or seam). What it does **not** catch is
composition-blindness whose invariant is *not a stated demand* but a **hidden dependency of a leaf's
verification** — an environmental or execution-context fact the leaf's check silently rests on. Both
demand tests enumerate from demands, so an invariant owned by no demand is invisible to both.

Corollary: a fan-out over an enumerated list ("dispatch one per each of these N sites") is only as
sound as your proof that N is complete. Probe the list before you dispatch (a `census` claim,
rules.md); a fan-out over an unproven list makes the clean dispatches certify the gap.

## The blind spot — the execution-context check the demand tests can't replace

The two tests above are a **demand-space** partition check. They cannot cover a correctness property
that lives in an **adjacent execution context owned by no demand** — a subprocess re-exec that
relocates an anchor the code trusts, a harness or CLI that re-runs a dispatched module against a
different tree or environment. That slice is what the execution-context census (`check_actors`, step
9) exists for: it derives *from the code* every context that runs a cut module and flags any not
modeled. So the complete check is **three** parts, not two: the two demand-space tests, plus **every
execution context that runs a cut module is modeled or explicitly waived.** Do not let a green
demand-union stand in for the census; they cover different slices, and the expensive bug lives in the
one the demands can't see.

A limit on the census itself: some execution-context invariants can be re-derived by sweeping a
durable surface (orphaned files can be listed), but others cannot be enumerated at all (the live
processes a run should have cleaned up). Where no census is possible, the invariant must be made
unbreakable **by construction** — retain the handle, act at the single exit — rather than reconciled
after the fact.

## Two diagnostics — which model, and where's the hard part

Neither judges a cut; both point at the piece you haven't cut well.

- **Dossier / effort size.** A dispatch whose dossier is much larger than its siblings' is either a
  mis-cut (secretly several dispatches) or an irreducible concentration of difficulty. Do **not**
  force evenness — forcing it splits the coupled core across an invariant. Read the lump the other
  way: it is usually the design-risk core, the piece that needed a spike. Uneven size is a *finder for
  the hard part.*
- **Model tier.** This one is literal: the tier you can dispatch each leaf on. A good cut drains the
  uncertainty into a few leaves (dispatch those on the frontier model) and lets the rest run cheap. If
  *every* leaf still needs the frontier model, you split the work but not the uncertainty — you cut in
  the wrong place. The assignable tier is both a readout of cut quality and the payoff you were after.

## Two modes of dispatch — don't confuse them

- **Reliability decomposition** fans out N subagents on the **same** target, each with a different
  lens (perspective, adversarial angle), and the parent reconciles their findings. The cut is in the
  *observer*, not the work; the value is diversity; reach for it when the risk is "we'll miss
  something." Use it *early*, while the design is unconverged.
- **Throughput decomposition** fans out N subagents on **different** components, and the parent
  integrates their outputs. The cut is in the *work*; the value is independence and cheaper models; it
  pays only once the interfaces are frozen — where **frozen means grounded against reality, not merely
  written down** (an interface wrapping an external system is not frozen until a probe has run its real
  behaviour, failure semantics first). Use it *late*, after the spikes.

Running throughput decomposition early — dispatching the build before the design converges, or over an
interface written but never grounded — is where the composition and enumeration failures live.

## The readiness signal

The design phase is done, and the build is safe to fan out into dispatches, at the moment **every
logical seam has become writable-as-verification**: every leaf's demands can be written citing only
*grounded* external referents (none a context-dependent proxy, none a frozen-but-unprobed interface),
their union reconstructs the whole's demands, and every execution context that runs a cut module is
modeled or waived. The trap to remember: "writable-as-verification" fires green for a seam whose
interface is written but ungrounded, so it cannot by itself tell frozen from grounded — the
reality-probe supplies that, and until it has run the seam is not ready. Until then, the
un-dispatchable seams *are* the remaining design work, and the spikes aim there.
