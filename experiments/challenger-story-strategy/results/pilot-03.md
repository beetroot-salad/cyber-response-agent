# Pilot 03 — three fixes applied

Same fixture and shared-seed design as pilot 02. Fixes: the tail asks for what the account
needs **that the data does not show either way**; the fold may not drop or re-cite an
`unsettled` item a check raised; loose is bounded to the account alone.

## Unsettled requirements — the metric the gate actually consumes

| arm | requirements | **unsettled** | calls | in-tok | cost | wall |
|---|---|---|---|---|---|---|
| lens | 15 | **14** | 12 | 64K | $0.14 | 284s |
| loose | 4 | 3 | 3 | 106K | $0.18 | 676s |
| seed | 3 | 2 | 1 | 33K | $0.05 | 213s |

Pilot 02, same arms, same fixture: **0, 0, 0.** The tail spec was the whole defect.

## The fold fix worked, and it worked the hard way

Round 2's lens checks found a flat contradiction — the container's oldest process is ~29
minutes old, so the account's 14-hour July-27 campaign cannot have happened inside it — and
the fold silently dropped it. Told to resolve contradictions in the mechanism rather than
acknowledge them, round 3's fold **changed the mechanism**: the container restarted at 06:09,
and the adversary's modifications persist across the restart through a volume or the image.
It also absorbed the `sshd -D -R` second daemon (197 events the defender folded into "habitual
UDP traffic" without reading the command line) as post-restart re-exec.

That is a mechanism revision under evidential pressure, which is what this arm was supposed
to be for and did not do in either earlier round.

## The quality signal: it now self-declares what a judge previously had to catch

Three of the specific errors the blind judge found in pilot 01 appear in pilot 03's tail as
**self-declared unsettled assumptions** rather than as asserted facts:

- "All 1,660 accepted SSH logins used the root account" — the judge caught this as an
  overreach; that lead's columns carry neither user nor auth method.
- "All accepted SSH logins used publickey authentication" — same.
- "172.18.0.9 is an unauthorized lateral movement destination" — the judge caught this as a
  category error, since that CMDB holds no IP field at all.

An account that knows which of its own load-bearing claims are unchecked is the thing the gate
needs; catching them downstream with a judge is strictly worse.

The two strongest entries are the case's real discriminators: whether `79.177.137.245` is
attacker infrastructure rather than an admin IP (threat intel returned `unknown`), and whether
`scheduler.py` differs from its image version (nobody read the file).

Some padding is present — "dev-ws-1 is the only container", "container ID ffbff1299702 is the
container the account calls dev-ws-1". Fourteen is more than this case has real discriminators,
and the fold's "you may not drop any" instruction is the likely cause. Worth a ranking or a cap
rather than a looser instruction, since the instruction is what made the arm work.

## Cost, corrected intuition

Call count is the wrong cost model. Lens issues 4x the calls of loose and costs less, because
each per-lead check carries one payload where every loose pass resends all 112K chars. Lens is
also 2.4x faster in wall time, entirely because the checks are independent and run concurrently
— serially it would be 723s.

Caveats: tokens estimated from characters (payload JSON tokenizes worse, so this is a floor),
and no prompt caching applied. Caching would narrow loose's disadvantage, not widen it — lens's
calls share little context and would cache poorly.

**Budget line for #774:** a gate firing costs roughly $0.15 and 3–5 minutes on top of the
investigation.

## Next

1. Blind-judge pilot 03's three stories on consistency-at-disposition, as the reframed
   objective demands — the counts above are structural, not a quality verdict.
2. Cap or rank the unsettled list; test whether the top-N are the discriminating ones.
3. Then scale across fixtures, with lens as the arm to beat.
