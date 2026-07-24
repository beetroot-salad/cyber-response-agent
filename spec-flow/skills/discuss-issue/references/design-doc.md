# Closing with the design doc

You reach here as the discussion settles — but first check *which way* it settled. Won't-fix, or already resolved by a later merge, ends in a short disposition in chat, not in the doc below. Only when the issue is genuinely heading to implementation do you compile what was decided into **one issue comment**: the intent+design doc write-tests consumes.

Write it for the agent that reads it cold, not for the user — the user's version was the conversation. The value is conservation: the typing survives into the spec stage, and a flat prose summary loses exactly what the downstream checks stand on. Scale it to the issue — a one-line fix earns a short doc.

## The doc — intent, design, claims

- **Intent** — the observable obligations the system owes, stakeholder-indexed ("my resources are reachable by me and nobody else" — user; "every action is attributable" — operator), plus **explicit non-obligations**: an examined no stops a rejected reading re-entering later as an assumption. Each obligation names what would observe it failing — the oracle settled in the discussion, carried here so write-tests inherits it instead of re-inventing one; an obligation nothing can observe failing is a fork for the human, not a demand. State obligations surface-general and let the design enumerate, visibly — an obligation quietly narrowed to the surfaces someone happened to list is how the missed case never enters the space.
- **Design** — the mechanisms chosen, each naming the obligation(s) it discharges. High level is fine. A mechanism serving no obligation is invented scope or an unstated premise made visible — surface it, don't smuggle it. A sentence that is neither obligation nor mechanism is background; mark it as such.
- **Deep dives, only when they fire.** *Security* — when the change touches an asset: enumerate obligations from the assets (finite, censusable), never from attacks (unbounded); state them as negative universals, and note for the spec that discharge means guard-plus-positive-control, a path census, or safe-by-construction — prose adversarial review does not discharge them. *Scale* — when a hot path or fan-out is in play: typed claims about load and growth, benchmarks deferred honestly rather than mechanization pretended. A dive that doesn't fire is one recorded line ("security: no asset touched") — a considered no, not silence.

## The sweep — probe the doc's claims before it posts

Every sentence rests on something already being true of the system. Ask of each: **what must already hold for this to make sense?** Per-sentence — noticing is recall, and recall failing is how known traps ship. Then settle each assumption with the one instrument that can, and record it:

- **referential** — the named symbol / path / flag exists as described; code structure (who calls what, which branch exists). Probe: read, import, or stat it, cited `file:line` — for who-defines a symbol, **symbol-refs** `--defs` resolves it across imports.
- **behavior** — what existing code or a dependency does on an input: the bug story, a default, an exception taxonomy. Probe: a throwaway run over the input types the boundary admits (`probe_kind: executed`) — never priors, never docs alone, never a read.
- **census** — "these are all the writers / callers / occurrences." Probe: the search, recorded so it replays — the full hit list, or counts plus the members the doc acts on; when the census is over a *symbol*, **symbol-refs** resolves the reference set past grep's lexical floor.
- **reachability** — "X cannot reach Y", "this value is constrained." Probe: try to break it. A survivor is *unrefuted*, never confirmed.

Record the results in a fenced-YAML `claims:` block in the comment — entries `{id, kind, claim, probe, probe_kind, observed, verdict}`, `probe_kind` one of `executed | read | search` (the instrument actually used — `behavior` demands `executed`, `referential` is content with `read`, `census` is `search`), `verdict` one of `holds | refuted | unrefuted | unprobed | deferred` (reachability's ceiling is `unrefuted`, never a coined "confirmed") — the shape write-tests' ledger inherits verbatim, `probe_kind` included so an inherited claim carries its instrument, not just its verdict. A refuted assumption is frequently the discussion's single most valuable finding: fix the doc before it posts, and say what changed.

## The review — a cold read before it posts

When the design carries a real fork or a fired deep-dive, hand the compiled doc to a fresh subagent at high effort before posting. It reads **cold** — the issue, the doc, and the code, not the discussion that produced them — so it reconstructs intent independently and catches what the author can't: the gap the author no longer sees because they already believe the design. A trivial doc — no fork, no dive — skips it on one recorded line ("review: skipped, no fork"). Charter:

- **Conservation** — every obligation has a mechanism that actually discharges it, in full. An obligation with no mechanism, or one only partly covered (the stateless-token design that can't honor "revoke, effective now"), is a finding.
- **Invented scope** — every mechanism serves a stated obligation. One that serves none is an unstated premise; surface it rather than let it ride.
- **Narrowing** — a surface-general obligation discharged only on an enumerated subset. Name the surface the enumeration dropped.
- **Claims** — every is-claim carries a probe whose `probe_kind` matches its kind, in the `claims:` block: a `behavior` claim recorded `probe_kind: read` is a finding, like one left `unprobed`.
- **Firing** — the security/scale dive fired where the change warrants it, and a skipped dive is a recorded no, not a silence.

Reconcile each finding, don't apply it blind — the cold reader can't tell a deliberate exclusion from a narrowing bug, and will flag both. Either it's a real gap and you fix the design, or it's a decision the doc left implicit and you record it as an explicit non-obligation — that recording *is* the fix, and it hands back the context the reviewer was denied. Re-sweep anything a fix touched, then post. A clean review is worth one line in the doc.

---

Post the doc as the issue comment. The occurrence census and the probed claims especially belong there: everything downstream builds on the recorded verdicts, not on whoever re-derives them next.
