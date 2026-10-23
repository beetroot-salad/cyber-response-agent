# Replay #1256: final scoring (steps 1–4)

Run outputs are in `../runs/`:
- `contract-map.md` and `fidelity-review.md`;
- `attack-a1.md` and `attack-a2.md`, plus their exploit patches (each applies to the contract commit, which is in `contract-c08e868/` as patches against base `d7b1886d`);
- the step 1–2 files.

The fixtures are in `../fixtures/` (`design-r3.md`, `ground-truth.md`).

Contract under review: `c08e868`, 42 tests (36 expected red, 6 green controls). It was written against design r3 unchanged, using the sketch's readings of the open gaps and no rulings.

## Ground truth

| ID | History found it at | Replay | Step | Evidence |
|---|---|---|---|---|
| G1 one owner of status, judged before the run folder | code review → r4 | **caught** | spike + design check, again at step 4 | DC-1a. Fidelity F-1: the contract forces two owners. Attacker a1: a single refusal site can't pass. |
| G2 down gate before lead claim, every cause | code review → r4 | **caught** | step 4 (spike found it, design check dropped it) | a1 H1: lead zero on an import-broken system claims its lead and spends a gather count. |
| G3 one maker of a down cause | code review → r4 | caught (mostly) | design check | DC-2, DC-4, DC-6 |
| G4 D5/D5a lead zero keeps its summary | code review → human | partial | design check + step 4 | DC-2. a1 H2 / F-9: a ConfigFault raised inside lead zero, and what lead zero says when that happens, are left open. |
| G5 / A1 fault-type census | code-stage adversary | caught (borderline) | step 4 | a2 H1: the check covers only the keys the contract drops; 8/8 other ConfigFault inputs stay Up. a2 H8: an unreadable or non-UTF-8 config.env counts as Up. a1 H4: ConfigFault is recognised by message text. |
| G6 / A2 run.py ignores broken adapters | code-stage adversary | **caught** | step 4 | F-1: `run.main` checks the real checkout, so the test's broken adapter is invisible to it. a2 H2: the all-down refusal drops an import-broken system's reason. |
| G7 / A3 resume drops down status | code-stage adversary | **caught** | step 4 | a1 H3: resumed runs and siblings skip the start check. |
| G8 / A4 combined log line | code-stage adversary | missed | | a1 tried logging twice, which was rejected. A combined line was never tried. |
| G9 / A5 instruction polarity | code-stage adversary | caught | step 4 (×3) | a1 H6, a2 H5, F-5: the "don't dispatch / name the gap" instruction is asserted nowhere. |
| G10 / A6 host paths on model-visible surfaces | code-stage adversary | partial | step 4 | a2 H13, low confidence: a traceback with host paths reaches MAIN. Flagged as a design gap, not exploited as a hole. |
| G11 / A7 exception types at import / check | code-stage adversary | **caught** | step 4 | a2 H9: only ImportError counts as broken. a2 H12 / F-4: no-check and non-ConfigFault checks are silently Up. |
| G12 #1080 import census | implementation | missed | | |
| G13 #1210 `.data_root` census | implementation | missed | | |
| G14 `run.main(roster=)` honoured | implementation | caught (borderline) | step 4 | F-1: the test's adapters reach only the inner investigation, and the harness rebuilds the tenant itself. Same class as G14 (the start check must judge what it is handed), but a different parameter: `defender_dir=`, not `roster=`. |
| G15 specific older-test / contract defects | implementation | partial | steps 3–4 | Different instances of the same class: F-1's harness defect, and F-2 / author G1 (the default fixtures are all-down). The three specific defects were missed. |
| G16 literal folder label | CI | missed | | |
| G17 startup scope = gather grants; CI fixtures | after code review | **caught** | design check, again at steps 3–4 | DC-1b, DC-5. Author G1 and G10. Fidelity F-2, F-6. |

**Tally (G1–G17)**
- **Caught:** 10. G1, G2, G3, G5, G6, G7, G9, G11, G14 and G17. G5 and G14 are borderline. Neither flips the decision criterion.
- **Partial:** 3. G4, G10 and G15.
- **Missed:** 4. G8, G12, G13 and G16.

Of history's seven code-stage adversary holes, step 4 reproduced 5 and half-reproduced 1, before any implementation existed.

## Parity with the original write-tests review (R1–R7)
- **R1** (a lead-zero adapter-broken scene leaks its imports): no direct match. The replay suite has no such scene, so there was nothing to leak.
- **R3** (the all-down refusal's routes in, and the sibling refusal): covered. Author O-8/O-9, a1 H3, F-3.
- **R4** (the shared fixture writes settings for all eight systems): F-2 and author G1.
- **R5** (an escaped ConfigFault during lead zero): a1 H2. DC-2 also has it.
- **R6** (AdapterBroken names its own cause, with no host path): a2 H2 and a2 H13.
- **R7** (p006 framing): author G3 and design check DC-6.

Step 4 is at least comparable to the original review. It is not a regression.

## Findings not in history
Plausible-real:
- DC-3: ConfigFault shares exit code 2 / infra.
- a2 H10: a reason containing `{}` crashes the gate, through `str.format` with an echoed config value.
- a2 H4: the in-call gate sits after the param screen and repeat guard.
- a2 H6 / H7: breaker and refusal wording still blames settings or uses breaker words.
- F-3: the sibling ruling D2 is enforced only where it overlaps O-8.
- a2: three docs and the connect skill go stale. The connect skill never tells a new adapter to declare a check.

Valid findings that the contract over-demands:
- F-7: it asks for exactly one log record.
- F-8: `_assert_uncharged` is broader than the design.

No finding was judged wrong on reading, so noise did not dominate.

## Decision criteria (from plan.md)
"Promising if the spike or design check surfaces at least one of G1–G4, or the step-4 attackers reproduce at least two of G5–G11, without noise dominating." Both conditions are met: G1 and G3 at the design check, and 5 of G5–G11 at step 4. **Proposed looks promising** (one fixture, directional).

## Cost (same price table as the week's analysis)
| Agent | Model / effort | Steps | Final context | Cost |
|---|---|---|---|---|
| Code map | Sonnet / medium | 20 | 152k | $0.93 |
| Sketch | Opus / medium | 43 | 179k | $2.84 |
| Spike | Sonnet / medium | 39 | 166k | $1.62 |
| Design check | Opus / high | 32 | 158k | $2.27 |
| Thorough author | Sonnet / medium | 41 | 205k | $2.21 |
| Fidelity reviewer | Opus / high | 37 | 162k | $2.45 |
| Attacker a1 | Sonnet / high | 54 | 215k | $2.85 |
| Attacker a2 | Sonnet / high | 68 | 225k | $3.34 |
| **Total** | | | | **$18.52** |

The plan estimated $40–80. The saving is mostly in step count: 20–68, against last week's 100–140. Every agent started at about 31k and ended at 150–225k, against last week's 217k median. An earlier draft quoted 300–400k peaks. Those were single requests near the end that counted the cache twice, not real context. No agent paid for an idle reload.

Where the $18.52 went:
- **By token type:** cache reads 46% (re-sending the context on every step), output including thinking 28%, cache writes 26%.
- **By agent:** the two attackers were the most expensive, at 33% together. They ran the most steps (54 and 68), so they re-sent the most context (8.5M and 10.3M tokens). The three Opus seats cost 41%; at high effort, their output share is 30–37%.
- **What fills context:** each agent read only 50–70k tokens. The rest is the 31k start, the agent's own writing (tests and patches, about 20%) and thinking (60–170k characters per agent). Of what was read:
  - existing tests and fixtures 34%;
  - production code 31%;
  - briefing documents 29%. The design check spent 56% of its reading here.
- **How it was read:** 60% through shell `cat`/`sed`/`grep`, 10% through the Read tool, and only 7% through the outline helper. The replay ran no repair rounds and no human rulings, so a real run costs more.

## Caveats
- The replay skipped repair rounds, so there is no evidence on whether Sonnet repairs close these holes.
- The design check's fixes were not adopted (r3 unchanged, by choice), so step 4 attacked a weaker contract than a §5-resolved one would be. A real run would close some of these holes earlier; this run's step 4 had more to find.
- Independence slip: attacker a2 saw attacker a1's patch filenames in a directory listing. It did not open them.
- G5 and G14 are scored on a close reading. The plan's second-judge read was not run, and neither row changes the verdict.
- Lenses were chosen from the skill's standard list without looking at the ground truth. Still, "cross-surface effects" maps naturally onto A4–A6.

## Lessons for the skill
1. **The design check's filter.** It dropped G2 as "pre-existing". Pre-existing behavior that the new design makes wrong is a finding. Step 4 recovered G2, but two stages late.
2. **The harness-ownership defect.** F-1 shows the contract itself can force two owners of one decision. Here that happened because the harness hands different inputs to the entry point and to the inner investigation. The fidelity charge could name this explicitly: "check that the harness hands the entry point and the inner flow the same inputs".
3. **Step count is the lever left.** Cost grows with steps × context, so the 54- and 68-step attackers dominate. A tighter attack budget per lens, or a third lens instead of longer runs, is the next thing to test.
4. **Attackers write a faithful implementation first.** Both attackers spontaneously built one that passed 42/42, then made small wrong variants of it. That proves the contract can be satisfied (or, for a1, shows where it forces two owners) and makes the exploits easy to read. It is worth writing into `adversary.md`.
