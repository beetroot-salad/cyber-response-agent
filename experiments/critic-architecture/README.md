# Critic-architecture experiment

Two-agent debate variant of the investigate loop: a **defender** triages, a **critic** attacks the load-bearing assumption with an adversarial prior. Question the experiment answers: does this surface leads/dispositions the existing single-agent loop misses, often enough to justify the cost?

## Architecture under test

```
alert → DEFENDER (commits to disposition + load-bearing assumption)
          │
          ▼
        CRITIC (one of three verdicts):
          • CRITIQUE  → emit a lead with predicted observable consequence
          • CONCEDE   → defender's disposition stands
          • ESCALATE  → consequence is real but untestable here → escalate
```

The critic owns the stop. Defender does not get to silently close. This is deliberate — defender rationalization is exactly what this architecture exists to interrupt.

## Rules

### Defender
- Commit to one disposition. No "could be either."
- Self-identify the single load-bearing assumption (the one whose failure would flip the call).
- Reason from the alert text. Don't fabricate environment facts.

### Critic — falsifiability gate

Every critique must specify an **observable consequence** — a concrete artifact, log line, field value, or system state that would exist *in this environment* if the attack hypothesis were live. The gate is consequence, not prior art.

Admitted:
- Documented technique with predicted artifact (e.g. T1550.001 → `SSH_AUTH_SOCK` set on bastion sshd session).
- Novel/unnamed mechanism with predicted artifact (e.g. "if a kernel module is suppressing auth log entries, the entry count from the bastion will diverge from the upstream syslog collector by ≥1").

Rejected:
- "Sophisticated actor could…" with no predicted artifact.
- Tests that require boiling the ocean ("audit the entire kernel," "wait for the C2 beacon").
- Critiques whose only consequence is "the attacker would hide everything" — non-falsifiable by construction.

If the critic has a real worry but no testable consequence in *this* environment, the verdict is **ESCALATE**, not CRITIQUE. ESCALATE is the safety valve that keeps the gate from collapsing into either (a) prior-art-only paranoia or (b) silent dismissal of legitimate uncertainty.

### Stopping
- CONCEDE terminates with defender's call.
- CRITIQUE produces a lead; the lead is run; defender re-triages with the lead's evidence.
- ESCALATE terminates with disposition=escalate.
- Single round in MVP. If lead changes nothing, defender's call stands. (Multi-round is a follow-up question, not for this experiment.)

## Scoring rubric

For each trial, score the critic on:

| Dimension | 0 | 1 | 2 |
|---|---|---|---|
| **Sharpness** | attacks a non-load-bearing claim | attacks a real assumption but tangentially | attacks the actual load-bearing assumption |
| **Specificity** | hand-wave | named mechanism, vague test | named mechanism + concrete observable |
| **Grounding** | invents environment facts | uses only alert facts | uses alert facts + correctly bounded environment inference |
| **Novelty vs single-agent** | restates a hypothesis the defender already considered | adds a hypothesis defender missed but is in `?adversary-controlled-*` template | adds a hypothesis no single-agent loop would generate |

And on the verdict choice:

| Trial label | Expected verdict | Failure mode if wrong |
|---|---|---|
| true-benign with strong precedent | CONCEDE | paranoia generator |
| true-malicious with subtle tell | CRITIQUE | architecture adds nothing |
| ambiguous | CRITIQUE or ESCALATE | over- or under-confidence |
| novel attack, no playbook | ESCALATE | false confidence in either direction |

Headline metric: **fraction of trials where critic produces a lead the defender did not propose AND the lead's prediction matches ground truth direction.** That's the single number that says "this architecture earns its complexity."

Secondary: false-paranoia rate on true-benign fixtures.

## Layout

```
fixtures/    one .json per synthetic alert + ground-truth label
prompts/     defender.md, critic.md
results/     {fixture_id}-trial-{n}.md  — full transcripts + grading
```

## How to run a trial

Spawn two `general-purpose` subagents in sequence. Defender first with `prompts/defender.md` + the fixture. Critic next with `prompts/critic.md` + the fixture + defender's output. Capture both transcripts and grade against the rubric in `results/`.

Manual orchestration is fine until the rubric stabilizes — premature automation freezes the prompts.

## Relationship to existing architecture

The current investigate loop already supports adversarial hypotheses via `?adversary-controlled-*` in PREDICT. The critic is a *different* hypothesis-generator that fires once on the defender's strongest claim with an explicit attacker prior. The experiment's central question is whether that separation produces hypotheses the single-agent PREDICT misses — or whether it just renames machinery that already exists.

The invlang lead schema (`docs/investigation-language.md`) is reused as-is for the critic's emitted lead. The critic does not need a new on-disk vocabulary; it produces leads exactly as PREDICT does.

## Open questions (not for this experiment)

- Critic memory shape (claim-shape → counter-archetype catalog).
- Multi-round termination if first lead is inconclusive.
- Whether the critic should also self-modify (probably yes, asymmetrically — see conversation log).
- Cost-vs-value at production scale.
