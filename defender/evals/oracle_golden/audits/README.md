# Judge calibration artifacts

The judge runs at score time, so the score is non-deterministic and the judge itself has
to be measured before anything it says is evidence. These are those measurements:
`audit_judge.py --repeats N --out audits/label-calibration_<tag>.json`.

One file per judge tag. A tag is `judge-<model>-<effort>_<sha8 over BOTH prompts>`, so
editing either prompt invalidates the calibration and requires a fresh sweep — the same
discipline `held_out_ledger.yaml` applies to held-out results, and
`test_judge.py::test_the_committed_calibration_was_produced_by_the_prompts_in_the_tree`
enforces it.

## `judge-claude-opus-5-high_47d6044a` — 2026-07-26

The gate for #711 step 2: does the label pass reproduce the 18 hand-derived leads of the
four seed cases, and how much does it disagree with itself?

| | |
|---|---|
| decided leads agreeing with the hand labels | **17/17** |
| class divergences | **0** |
| abstentions | 1/18 |
| mean self-agreement over 5 repeats | 0.978 |
| cost | $6.78 |

Every decided lead landed on the hand label, and 17 of 18 were unanimous across all five
repeats. The judge is deterministic where it is confident and wobbles only where the
telemetry is genuinely marginal, which is the shape you want — the alternative, a
confident answer everywhere, is what a judge fitted to this set would look like.

### The open item: `case-003-suppression-devws/l-001`

The one abstention. Hand label `0` (→ `absent`); the judge answered `undecidable /
insufficient-baseline` on three of five repeats and `absent` on the other two.

Its reasoning is not a misreading. The lead's single query returned zero rows over the
10-minute operation window; of its three controls, `C-7d` was levered down (`window_live:
false`, no payload), `C-14d` returned exactly one row — a 6-event `svc.config-mgmt`
service login — and `C-21d` returned nothing. So routine sshd auth on `dev-ws-1` is
intermittent at hour scale, and the judge declined to separate "this envelope went quiet"
from "this envelope is usually quiet anyway".

**This is a statement about the instrument, not about the judge.** The judge named what
would settle it: a live control at the observed window's own duration and time of day, or
a live 7-day control in place of the levered-down 2026-07-18 one. Getting either requires
a lever-up — every capture environment here is a levered-down snapshot — so the
adjudication is **open**, and it is deliberately not closed by editing the prompt. A
judge tuned until it agrees with this set calibrates nothing.

Two things worth noting about which side is probably right. The hand label is defensible:
`C-21d` is live and empty, so this envelope demonstrably does not routinely carry events,
which is what `absent` means. But the case is a suppression case — the attacker blinded
`dev-ws-1`, and `l-002` on the same host is the suite's only hand-labelled `-noise`. So
`l-001`'s stream did go dark; it simply had nothing to lose. That is precisely the
"suppression needs a baseline to remove" distinction the oracle prompt correction is
about, and a thin baseline is exactly the condition under which it is hard to see. The
abstention is the judge declining to call it from two live control hours, one of them
empty. Re-measure before deciding who was right.
