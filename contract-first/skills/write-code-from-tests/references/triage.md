# The triage charge

You sort one batch of attack findings into families and give each family a verdict, before anyone repairs a test. Repairing exploit by exploit closes the instances an attacker happened to sample and leaves the family open; the next round samples the next instance. Your job is to stop that loop by deciding each family once.

You receive the current design and decisions, the project's principles document, the attack ledgers and exploit patches, the contract map, and the implementation commit. You do not receive the implementer's reasoning. Read-only: return verdicts, never edit tests, code or the design.

## 1. Check each finding is real

Drop a finding, and say why, when any of these hold:

- **No deployment path.** It doesn't name how the condition arises where this system runs, from an input or actor the design or threat model admits. A condition only an actor or environment the threat model excludes could produce is out.
- **No honest mistake.** No competent implementer would plausibly write the variant: it special-cases test inputs or is built only to slip past this suite. Such exploits show the suite can be gamed, not that it misses a bug anyone would ship.
- **It asks for tolerance the principles reject.** The finding requires the code to accept, repair or classify a condition that the principles say should simply be refused. That is a sign the design or contract promised too much, which you report as a design finding, not a hole to close.

## 2. Group by what made them possible

Group the surviving findings by **the design choice that let them exist**, not by file, test or attacker lens. A family is answered by one decision. When two findings share a cause, they are one family, however different their exploits look.

## 3. Give each family one verdict

- **Dissolve.** A design change makes the whole family impossible: one owner, one location, one shape. Usually this restates a rule the design wrote as its cases, as its goal and principle instead, with the cases moved to the design's cache of applications. This is an amendment; describe the change, the findings it removes, and its cost. The human rules on it.
- **Accept.** The family is a deliberate trade-off: real, but not worth closing here. Say what it would cost to close and why it isn't worth it. Once the human agrees, it is recorded in the design's **accepted trade-offs**, and attackers may not cite it again.
- **Close.** The design is right and the suite misses the family. Name the **one** test that closes the whole family: one whose input is the whole class, generated or defined only by membership. Never a list of the members the attackers found.
- **Code bug.** The exploit fails on the honest code too, or the honest code itself violates the design. It goes to the implementer.

## Return

Per family: its cause in one sentence, the findings it covers, the verdict, and for *Close* the single test to write, for *Dissolve* the amendment, for *Accept* the cost of closing. Then the dropped findings, each with its reason. Keep it short; the human reads the dissolve and accept verdicts.

## Cache

One entry per line: `<skill>[/<file>] §<section> <rule> | ctx: <tags> | <application>`. Each applies a rule above to the context its tags name. If it disagrees with its rule, or its context has changed, recompute it from the rule, which wins; judge an uncovered case from the rule. Project-specific entries use the same format in the project's `.claude/contract-first-cache.md`: grep it for this skill's name.

- write-code-from-tests/triage §2 typical-causes | ctx: past-runs | an input checked field by field instead of parsed once, at one boundary, into one shape; a fact with two owners, or a decision taken in two places; a guard that lists cases (exception types, spellings, encodings) where the design means a whole class; a promise over a class of values or surfaces, pinned with hand-picked members.
- write-code-from-tests/triage §3 one-test-over-the-class | ctx: python | a property or generated-input test; a test-defined exception type; arbitrary bytes; any malformed record.
