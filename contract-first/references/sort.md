# Sorting findings

You sort one batch of findings into groups by cause and give each group one verdict, before anyone revises, repairs or asks the human anything. Answering findings one by one handles the instances a reviewer or attacker happened to see and leaves their cause in place, so the next round finds the next instance. Your job is to decide each cause once, and to ask of every group: is there a change that dissolves these rather than patches them, and which is cleaner?

Every stage uses this procedure. You run as a fresh agent that produced neither the work nor the review; an author sorting its own review tends to keep its design and patch around it. A batch too thin to show a cause can skip sorting.

You receive the batch of findings, the current design and decisions, the project's principles document and project rules, and the artifacts the findings cite. You do not receive the author's reasoning. On a finalize run you get no design rationale either, only the names of the design's accepted trade-offs, so that the last reader stays cold. Read-only: return verdicts, never edit tests, code or the design.

## 1. Check each finding is real

Drop a finding, and say why, when any of these hold:

- **No deployment path.** It doesn't name how the condition arises where this system runs, from an input or actor the design or threat model admits.
- **No honest mistake.** The code or test it describes is not something anyone would plausibly write or rely on: a variant built only to slip past this suite, or a reading of the design no competent reader would take.
- **It asks for tolerance the principles reject.** It requires the code to accept, repair or classify a condition the principles say should simply be refused. That suggests the design promised too much; report it as a design finding, not a hole to close.
- **Already decided.** It falls inside an accepted trade-off or a recorded human decision, with no new evidence that it arises in deployment or costs more than recorded.

## 2. Group by what made them possible

Group the surviving findings by **the design choice or cause that let them exist**: a model, an owner, a flow, a rule. Not by file, test, reviewer or lens. When two findings share a cause, they are one group, however different they look. A group is answered by one decision.

## 3. Give each group one verdict

- **Dissolve.** A change to the model, owner, flow or rule removes the whole group: one owner, one location, one shape. Often it restates a rule written as a list of cases as its goal. Describe the change, the findings it removes, its cost, and **the open decisions it would itself create**. A dissolve can overreach and open more choices than it settles; the stage's independent review reads it before it reaches the human.
- **Local fix.** A fix at the owning place is genuinely the cleaner answer. A local bug can deserve a local fix; dissolving is not an excuse to expand scope.
- **Close.** The design is right and the tests miss the group. Name the **one** test that closes it: one whose input is the whole class, generated or defined only by membership. Never a list of the members found.
- **Accept.** A deliberate trade-off: real, but not worth closing here. Say what closing it would cost and why it isn't worth it. Once the human agrees, it goes into the design's **accepted trade-offs**.

Choose between dissolve and local fix by which leaves less code and fewer special cases, counting migration and operational cost, not by which has the smaller diff. Two kinds of finding route without a verdict: a **code bug** (the code violates the settled design) goes to whoever owns the code, and a **factual question** goes to a probe, because the human doesn't decide what existing code does.

## Return

Per group: its cause in one sentence, the findings it covers, the verdict, and what it needs: the change and the decisions it opens for a dissolve, the fix for a local fix, the single test for a close, the cost of closing for an accept. Then the routed findings, then the dropped ones, each with its reason. Keep it short: the human sees groups with a recommendation, never one question per finding.

## Cache

One entry per line: `<skill>[/<file>] §<section> <rule> | ctx: <tags> | <application>`. Each applies a rule above to the context its tags name. If it disagrees with its rule, or its context has changed, recompute it from the rule, which wins; judge an uncovered case from the rule. Project-specific entries use the same format in the project's `.claude/contract-first-cache.md`: grep it for `references/sort`.

- references/sort §opening sorter | ctx: models=claude-5 | Opus at high effort.
- references/sort §opening too-thin | ctx: past-runs | one or two findings.
- references/sort §opening why-not-the-author | ctx: past-runs | across six long design histories the author sorted its own reviews and proposed a dissolving change twice, once only after the same class came back three rounds running; the human asked for the dissolving change 74 times in a month.
- references/sort §2 typical-causes | ctx: past-runs | an input checked field by field instead of parsed once, at one boundary, into one shape; a fact with two owners, or a decision taken in two places; a guard that lists cases (exception types, spellings, encodings) where the design means a whole class; a promise over a class of values or surfaces, pinned with hand-picked members.
- references/sort §3 dissolve-overreach | ctx: past-runs | on #1135 a dissolving move created most of the next round's open decisions.
- references/sort §3 one-test-over-the-class | ctx: python | a property or generated-input test; a test-defined exception type; arbitrary bytes; any malformed record.
