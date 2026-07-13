# Decomposition — where and how to cut a large task

**Status: hypothesis, partially validated.** Retro-graded against the AgentDefinition consolidation
arc (#538→#545→#551→#555): the two demand-space tests below caught real on-arc defects (a tautological
parity test; the salt-coherence seam) — but the grade also **falsified** the claim that the global
test subsumes all composition-blindness. A composition bug whose invariant lives in an *adjacent
execution context* owned by no demand (#562, `PATHS` relocating under subprocess re-exec) passes both
tests while the whole breaks. The two tests are a sound *demand-space* partition check; they are **not**
a substitute for the execution-context census (`check_actors`, SKILL.md step 9) — see "The blind spot"
below. Not yet referenced from SKILL.md.

When a design is too large to spec in one clean pass, cut it into several — but a bad cut is worse
than a big pass: it splits a correctness property across two contexts so each half looks green while
the whole is broken (the composition failure), or it fans out over a list you never proved complete
so the clean pieces *certify* the gap (the enumeration failure). This doc is how to know a cut is
sound *before* you commit to it.

There is no cutting algorithm — the seams are discovered, not given, and finding them is most of the
design work. What follows is a decision procedure: a criterion for *where*, two tests for *whether*,
and two diagnostics that point at the part you haven't cut yet.

## The criterion — information hiding on the stable/volatile axis

Cut so each subtask encapsulates one decision that is **likely to change**, behind an interface
derived from what is **stable** (Parnas, 1972). For a feature with clear product intent but an
unconverged technical design, you already know which is which: the product intent is stable, the
technical design is volatile. So the seams fall exactly where a volatile technical decision meets a
product-stable contract — put each unknown (the storage model, the concurrency model, the delivery
path) in its own box behind an interface the product intent already pins.

Consequence: **you cannot cut space before you cut time.** You can't decompose along interfaces that
don't exist yet, and for a weak-design feature they don't. The first cut is temporal — spike the
volatile decisions until each *visible* seam becomes a *verifiable* one (below), freeze the
interfaces, and only then fan out the build.

## The two tests

A cut is sound iff both hold. Both are stated in **acceptance criteria** — in this repo, demands —
so both are checkable, not felt.

### Local (per seam): logical separation ⟺ verifiable against a meaningful external referent

A seam is real iff you can write the subtask's acceptance criteria **now**, citing only an *external,
pre-existing* referent — the product acceptance criteria, a frozen interface contract, or a probe of
existing reality ("Probed claims", rules.md) — and **never** a sibling subtask's output or an
internal snapshot of the intended solution.

One qualifier the retro-grade forced: a probe of existing reality is a valid referent only if it is
not a **context-dependent proxy.** A referent like a `PATHS`-style anchor that *resolves to different
things in different execution contexts* is exactly the trap — the leaf verifies green in the context
you tested and false-positives elsewhere (this is #562). "Is my referent the real thing, or a proxy
that happens to equal it here?" is part of the local test, not a footnote to it.

This is an equivalence, and the referent clause is the hinge. Cutting a function at "line 50" is
*technically* verifiable against an intermediate state dump — but that dump has no standalone
meaning; it is derived from the very solution you are pretending to decompose, so the seam is
arbitrary. A referent with standalone meaning ("returns the parsed AST", "the manifest lists every
non-underscore lesson") **is** a logical boundary. So: verifiable-against-a-meaningful-referent and
logical-separation are the same property, and the test for it is — *can you write the leaf's demands
without naming another leaf.*

If you can see the separation but cannot yet write its verification, that seam is a logical boundary
whose contract is undefined — i.e. **undone design.** The distance between the seams you can see and
the seams you can verify is a precise meter of design remaining; a spike's job is to close it.

### Global (the partition): the demands compose

The union of the leaves' acceptance criteria plus the seam contracts must reproduce the **whole
task's** acceptance criteria: `⋃ leaf-demands ∪ seam-demands ≡ whole-demands`.

This test always catches the **enumeration gap**: if a leaf is missing, the union falls short of the
whole. And it catches **composition-blindness when the spanning invariant is itself a stated demand**
— reproducing the whole's acceptance forces that invariant to be owned by some leaf or seam (the
salt-coherence seam is the worked case: one persisted salt is a security demand of the deps factory,
so reconstruction forces it into a seam demand). The practical form is reconstruction: **read only
the subtasks' specs; can you rebuild the whole's acceptance criteria?** If not, the cut is lossy.

What it does **not** catch — the correction the retro-grade forced — is composition-blindness whose
invariant is *not a stated demand* but a **hidden dependency of a demand's verification**: an
environmental or execution-context fact the test silently rests on. #562's guard owned its demand
(`d7`, "main-checkout authoring unbuildable") and still broke, because the demand's *check* assumed
`PATHS == the real main checkout`, an invariant no demand states and reconstruction never surfaces.
Both tests here enumerate from **demands**, so an invariant owned by no demand is invisible to both.

Corollary: an enumeration the cut fans out over ("handle each of these N callers") is only as sound
as your proof that N is complete. Probe the list first (a `census` claim, rules.md); a fan-out over
an unproven list makes the clean pieces certify the gap.

### The blind spot — and the third test you already run

The two tests above are a **demand-space** partition check. They do not, and provably cannot,
cover a correctness property that lives in an **adjacent execution context owned by no demand** — a
subprocess re-exec that relocates an anchor the guards trust, a CLI/harness/eval entrypoint that
re-runs a changed module on a different tree. That slice is exactly what `check_actors` (SKILL.md
step 9, "The artifact") exists for: it derives *from the code* every execution context that drives a
changed module and flags any the graph's `actors` don't model. So the complete decomposition check is
**three** parts, not two: the two demand-space tests here, plus **every execution context that runs a
cut module is modeled as an actor or explicitly waived.** The team learned this on the very arc that
motivates this doc — #562 was caught only by authoring `check_actors` inside the same PR, and it is
still tracked as an open census hole. Do not let the demand-union test's green stand in for the
census; they cover different slices, and the expensive bug lives in the one the demands can't see.

## Two diagnostics — readouts, not gates

Neither judges a cut; both point you at the part you haven't cut well.

- **Effort profile.** A leaf that is much larger than its siblings is either a mis-cut (secretly
  several leaves) or an irreducible concentration of difficulty. Do **not** force evenness — forcing
  it splits the coupled core across an invariant. Read the lump the other way: it is usually the
  design-risk core, the thing that needed a spike. Uneven effort is a *finder for the hard part.*
- **Assignable model tier.** A good cut drains the uncertainty into a few leaves and leaves the rest
  runnable on a cheap model. If *every* leaf still needs the frontier model, you split the work but
  not the uncertainty — you cut in the wrong place. The tier you can assign is a readout of cut
  quality.

## Two modes — don't confuse them

- **Reliability decomposition** cuts by *perspective* and keeps the target whole: N lenses on one
  artifact (the enumerator fan-out, a judge panel). The cut is in the observer; the value is
  diversity; reach for it when the risk is "we'll miss something." Use it *early*, while the design
  is unconverged.
- **Throughput decomposition** cuts by *component* and splits the work: the Parnas modularity
  question. The cut is in the work; the value is independence and cheaper models; it only pays once
  the interfaces are frozen. Use it *late*, after the spikes.

Running throughput decomposition early — splitting the build before the design converges — is where
the composition and enumeration failures live.

## The readiness signal

The design phase is done, and the build is safe to fan out, at the moment **every logical seam has
become writable-as-verification** — i.e. every leaf's demands can be written citing only external
referents (none of them a context-dependent proxy), their union reconstructs the whole's demands, and
every execution context that runs a cut module is modeled or waived. Until then, the un-verifiable
seams *are* the remaining design work, and the spikes aim there.
