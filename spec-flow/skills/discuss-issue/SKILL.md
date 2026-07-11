---
name: discuss-issue
description: "Explain a GitHub issue in plain terms, check it against the current codebase, and surface the open questions that need answering before anyone designs or implements. Use when a bare issue report needs to be understood and grounded in the real code."
argument-hint: "[issue number]"
---

# Discuss issue

Take a bare issue and do three things, in chat: **explain** it in plain terms, **check** it against the current codebase, and **surface** the open questions. The goal is a shared, grounded understanding of the problem — not a finished design.

Start by loading the issue. If an issue number was passed, load that: `gh issue view <n> --comments`. Otherwise take it from the conversation, or work from the file path or pasted text you were given. Read the comments — some of this may already be settled, so don't rehash it.

The three moves below aren't a rigid sequence or a template for the output. Think through all of them; write up what's load-bearing.

## Explain it in plain terms

Say what the problem actually is, where in the code it lives, and why it surfaces — plainly, the way you'd explain it to a colleague who knows the system but hasn't seen this issue. Spend the words on *this* problem and its mechanism, not on what the system is. Define any project-specific term you lean on.

If you can't explain the mechanism without hand-waving, you don't understand it yet — go read the code until you can.

## Check it against the codebase

The issue is a starting point, not a source of truth. Read the code it touches and confirm the report holds up:
- Verify the factual claims. Issues routinely assert "X works like Y" from stale memory; grep and read the named files, and flag anything that conflicts with current code, citing `file:line`. When the surface is broad, hand the verification to an Explore subagent.
- Note where the issue is out of step with how the code actually works now, and correct the picture.

A discussion built on a false premise is wasted — this is what keeps it honest.

## Surface the open questions

Name what genuinely has to be decided before anyone can act: the ambiguities, the missing pieces, the forks where more than one fix is plausible. For each, say what's unclear and, where you have one, your read on it. Skip the questions the codebase or an existing convention already answers — state the answer and move on.

A few angles often turn up something worth discussing. Pull on the ones that apply and ignore the rest — they're prompts, not a checklist:
- **Worth doing?** — is the problem real and worth solving now, or is "won't fix" / "not yet" the honest answer?
- **Root cause** — is the reported symptom the real problem, or a downstream effect of a deeper cause that's the better thing to fix?
- **The hard part** — what makes this non-trivial? The constraint in tension, the invariant that's easy to break, the case that resists a clean fix. This is usually where the real forks live.
- **Scope** — what's in, what's an explicit non-goal, and whether two problems are wearing one issue.
- **Completeness** — what's missing to act on it: the motivation, the done criteria, the dependencies or prior art.

Keep it to the questions that matter. The point is to illuminate what's still open, not to resolve everything or design past it.

---

Then talk it through with the user if they want — no fixed template, no required artifact. If the discussion settles into something worth keeping, offer to fold it back into the issue or a short note.
