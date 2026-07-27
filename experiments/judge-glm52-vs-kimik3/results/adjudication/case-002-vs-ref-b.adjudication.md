## The correct outcome

`refuted`. The story has two load-bearing legs: (a) the source is a corporate-owned *scanning tool*, (b) the sweep is a *scheduled, recurring authorized* posture assessment. Both are addressed by collected evidence. CMDB resolves 172.18.0.16 to `office-ws-1`, a dev workstation owned by dev.dana with no trust edges to canary-1; change-mgmt returns zero tickets for canary-1. The oracle projection matters here and neither judge uses it well: the story writes **no delta** to l-003, l-002, l-004, l-005, or l-006 — it lights only l-001, and there only with baseline-shaped noise. So the story does not get to add a scanner registration, a role change, or a standing-authorization record anywhere. It has to survive against the actuals as-is, and the actuals say dev workstation, no ticket.

The behavioral shape also cuts against it, and neither judge engages: 96 attempts against **`root` only**, in 3 minutes, 48 password / 48 other — on a host where CMDB says root is not a declared account. A fleet-wide posture sweep of "every reachable SSH endpoint" does not look like single-account credential hammering at one target. `refuted` is right; the defender's `inconclusive` ceiling was also right, because an ad-hoc unauthorized tool run by dev.dana remains open — but "unauthorized ad-hoc" is not the actor's story.

## Grounding

Both judges quote a `coverage_manifest` not reproduced in this packet. They corroborate each other on its existence and on the l-004 two-step pivot (A's `cmdb.hostname-by-ip` 404, B's `elastic.ip-to-host-search` ok), and both are consistent with the log, so I don't treat either as fabricating.

One clear misattribution, in B: *"l-001's actuals (96 failures from one source, root-targeted, multi-method) match the scanner signature exactly."* The log states l-001 **returned abnormally (tool retries exhausted)**; the 96-event data came from l-002. B attributes its central evidentiary claim to a lead that failed, and attaches no citation to it. That sentence is the pivot of B's entire `survived` call.

A's weak spot is smaller: the l-006 finding asserts "roughly sixty fim-checksum queries on guessed filenames `00-root.conf` through `99-permitrootlogin.conf`" but the single attached citation is a `sha256sum: ... Is a directory` error, which shows the lead checksummed the directory — not the enumeration range. The specifics outrun the quote.

## Findings quality

A: two of three entries are `disposition-confirmed` — praise, not defects. The one real finding (l-006 burned the query budget guessing config filenames instead of listing the directory) is specific, correctly anchored, and transferable. A's environment observation that the CMDB index is keyed by hostname, so a bare IP 404 is a lookup artifact rather than evidence of an unregistered source, is the single most reusable artifact either judge produced.

B's finding 2 is the better *defect*: the defender did conflate CMDB host role with running-process identity, and did read the concurrent nginx hits as "broader probing" without a lead that separated scanner traffic from reconnaissance. That is a real analytic gap A never surfaces. But it licenses "lower the confidence," not "flip to survived."

B's finding 1 fails on grounding in a way that matters for a training label: it faults the defender for not querying a scanner-registration / security-operations-schedule system, when nothing in the evidence establishes such a system exists — and the oracle projection shows the story produces no record in any queried lead. B then converts that unavailability into support for the story. Absence of refutation from a system nobody has is not evidence of authorization.

## Calibration

A calls `refuted` and explicitly names what stays open (owner-run ad-hoc tooling), which is the honest shape of this case. B calls `survived` confidently on a story whose two authorization legs are both contradicted by collected evidence, and never addresses root-only targeting. Under this rubric B's label is the more damaging error: it would score this as a false positive and teach a downstream agent that an unregistered workstation hammering root with no change ticket may be routine.

Both are flawed. A pads with praise entries and over-specifies one citation; B lands the sharper critique of the defender's reasoning and then spends it on the wrong verdict.

VERDICT: A — B pins its `survived` call on evidence it misattributes to a failed lead (l-001) and on an authorization system the evidence never shows exists, while A reaches the correct `refuted` with citations that hold.
