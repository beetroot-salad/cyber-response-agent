---
name: discuss-issue
description: "Explain a GitHub issue in plain terms, check it against the current codebase, and surface the open questions that need answering before anyone designs or implements. When the discussion converges toward implementation, close by posting one intent+design comment — stakeholder-indexed obligations, the mechanisms that discharge them, and probed claims about existing reality — the ground the spec stage builds on. Use when a bare issue report needs to be understood and grounded in the real code."
argument-hint: "[issue number]"
effort: medium
---

# Discuss issue

Take a bare issue and do three things, in chat: **explain** it in plain terms, **check** it against the current codebase, and **surface** the open questions. When the discussion converges toward implementation there is a fourth: **compile** what was settled into one issue comment — the intent+design doc that write-tests consumes. Scale everything to the issue: a simple fix earns a short doc; a discussion that ends in "won't fix" ends in chat.

Start by loading the issue. If an issue number was passed, load that: `gh issue view <n> --comments`. Otherwise take it from the conversation, or work from the file path or pasted text you were given. Read the comments — some of this may already be settled, so don't rehash it.

## Explain it in plain terms

Say what the problem actually is, where in the code it lives, and why it surfaces — plainly, the way you'd explain it to a colleague who knows the system but hasn't seen this issue. Spend the words on *this* problem and its mechanism, not on what the system is; define any project-specific term you lean on. If you can't explain the mechanism without hand-waving, you don't understand it yet — go read the code until you can.

## Check it against the codebase

The issue is a starting point, not a source of truth. Read the code it touches and confirm the report holds up: verify the factual claims — issues routinely assert "X works like Y" from stale memory — and flag anything that conflicts with current code, citing `file:line`. When the surface is broad, hand the reading to an Explore subagent, but keep it in its lane: **a reader answers discovery and narrative questions; enumerable or executable questions become claims** (the sweep below) whose answers come from a tool run, not from the reader's impression. A discussion built on a false premise is wasted — this is what keeps it honest.

## Surface the open questions

Name what genuinely has to be decided: the ambiguities, the missing pieces, the forks where more than one fix is plausible. For each, say what's unclear and, where you have one, your read on it. Skip the questions the codebase or an existing convention already answers — state the answer and move on. Angles that often pay (prompts, not a checklist):

- **Worth doing?** — is the problem real and worth solving now, or is "won't fix" / "not yet" the honest answer?
- **Root cause** — is the reported symptom the real problem, or a downstream effect of a deeper cause that's the better thing to fix?
- **The hard part** — what makes this non-trivial? The constraint in tension, the invariant that's easy to break. This is usually where the real forks live.
- **Scope** — what's in, what's an explicit non-goal, and whether two problems are wearing one issue.
- **The same pattern elsewhere** — once the mechanism is clear, census its other occurrences before the scope freezes: the sites an issue names are where the author happened to look — a sample, not a census. Define "the same" at the issue's own altitude, derive the occurrences from the code with a tool, and give each an explicit in-or-out verdict — one the issue missed is a finding, an exclusion is a decision worth recording, and one that looks already handled is a claim to check against the issue's own bar, not a reason to leave it out.
- **Completeness** — what else is missing to act on it: the motivation, the done criteria, the dependencies or prior art.

## Close with the doc — intent, design, claims

When the issue is heading to implementation, compile the settled discussion into **one issue comment** with typed sections. The typing is what every downstream check stands on — a flat prose summary loses it:

- **Intent** — the observable obligations the system owes, stakeholder-indexed ("my resources are reachable by me and nobody else" — user; "every action is attributable" — operator), plus **explicit non-obligations**: an examined no stops a rejected reading re-entering as an assumption. State obligations surface-general and let the design do the enumerating, visibly — a design that quietly narrows an obligation to the surfaces it happened to enumerate is how the missed case never enters the space.
- **Design** — the mechanisms chosen, each naming the obligation(s) it discharges. High level is fine. A mechanism serving no obligation is invented scope or an unstated premise made visible — surface it, don't smuggle it. A sentence that is neither obligation nor mechanism is background, and is marked as such.
- **Deep dives, only when they fire.** *Security*: when the change touches an asset — enumerate obligations from the assets (finite, censusable, human-checkable), never from attacks (unbounded); state them as negative universals, and note for the spec that discharge means guard-plus-positive-control, a path census, or safe-by-construction — prose adversarial review demonstrably does not discharge them. *Scale*: when a hot path or fan-out is in play — typed claims about load and growth, benchmarks deferred honestly rather than mechanization pretended.

### The sweep — verify the doc before it posts

Every sentence of the doc gets a fourth question: **what must already be true of the existing system for this sentence to make sense?** Extract the assumptions per-sentence — noticing is recall, and recall failing is how known traps ship — then settle each with the one instrument that can:

- **referential** — the named symbol / path / flag exists as described. Probe: read, import, or stat it.
- **behavioral** — what existing code or a dependency actually does: the bug story that motivates the change, a default, an exception taxonomy. Probe: a throwaway run — never priors, and never docs alone.
- **census** — "these are all the writers / callers / occurrences." Probe: the search, recorded with its full hit list.
- **reachability** — "X cannot reach Y", "this value is constrained." Probe: try to break it. A survivor is *unrefuted*, never confirmed.

Record the results in a `claims:` block in the comment — entries `{id, kind, claim, probe, observed, verdict}`, the same shape as the spec_graph ledger, so write-tests inherits them verbatim. A refuted assumption is frequently the discussion's single most valuable finding: fix the doc before it posts, and say what changed.

---

Then talk it through with the user if they want — the doc is the exit artifact when work will proceed, not a gate on the conversation. The occurrence census and the claims especially belong in the issue: the spec and the implementation downstream build on the recorded verdicts, not on whoever re-derives them next.
