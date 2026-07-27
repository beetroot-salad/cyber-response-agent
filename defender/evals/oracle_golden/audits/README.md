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

## `verdict-selfagreement_judge-claude-opus-5-high_47d6044a` — 2026-07-27

The verdict pass, `audit_judge.py --pass verdict --repeats 5`. It has no hand-labelled
ground truth, so **this is not a calibration**. It measures the two things that can be
measured: how often the judge gives the same lead the same verdict, and how often it
disagrees with the pass that measured the telemetry.

Run over the 17 dev leads a real score graded (`glm-5.2_effort-none_prompt-711`), reusing
the committed `labels/<judge-tag>.json` as the measurement of record — the same input
`score.py` feeds it. Letting the label pass vary underneath would fold two variances into
one number that names neither.

| | |
|---|---|
| mean self-agreement over 5 repeats | **0.988** |
| leads that did not answer identically every time | **1/17** |
| `contradicts-measurement` | **0/17** |
| cost | $5.28 |

**The noise floor is one lead.** The dev active band is 7 leads, so a prompt edit has to
move at least 2 of them before the change is distinguishable from the judge re-running
on an unchanged projection. That is the number to hold a tuning result against, and it is
the reason this sweep is not optional: without it, a one-lead "improvement" is
indistinguishable from noise.

Zero `contradicts-measurement` is the more reassuring half. The verdict pass never once
read the telemetry differently from the pass that measured it, across 85 calls — the two
passes are looking at the same evidence and agreeing about what it says, which is what
makes the split worth its cost rather than just its complexity.

### The one unstable lead: `case-002-authorized-keys-falco/l-001`

`C-FABRICATED-VALUE` on four of five repeats, `faithful: true` on the fifth. This is the
`evt.type: write` / `openat` divergence — the projection reproduces the Falco rule, the
file path and the user correctly, placeholders the volatile container id correctly, and
gets one field wrong. Whether a single wrong non-distinguishing field makes the whole
projection unfaithful is a genuinely marginal call, and the judge makes it the same way
four times in five.

It is not a defect to tune away. A judge that answered identically on a lead this close
would be a judge with an artificially narrow notion of fabrication, and the design's rule
holds here too: adjudicate by re-reading the payload, not by editing the prompt until the
wobble stops.
