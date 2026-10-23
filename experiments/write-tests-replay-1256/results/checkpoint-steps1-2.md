# Checkpoint after the design check (steps 1–2)

Run outputs are in `../runs/`: codemap.md, sketch-report.md, spike-friction.md, spike.diff and design-check.md.

## Scoring against what history found late

| ID | Historically found at | Replay | Where |
|---|---|---|---|
| G1 one owner of system status, judged once before the run folder, handed down | code review → r4 | **caught** | spike F9 (two owners of "what refuses a run", fires after run folder); design check DC-1a proposes a run-start step in `run.main` before `materialize`, a frozen verdict handed down — near-identical to the r4 fix |
| G2 down gate before the lead claim, every cause | code review → r4 | **found by spike, dropped by design check** | spike F16 logged it; design check dismissed F16 as "pre-existing tripped behaviour" |
| G3 one maker of a down cause, paths hidden at boundaries | code review → r4 | **caught (mostly)** | DC-2 "down spelled four ways" → one `down_cause` accessor; DC-4 the check duplicates the loaders; DC-6 one redaction. Scaffold validator not mentioned |
| G4 D5/D5a lead zero keeps its summary | code review → human | **partial** | DC-2 identifies the same unspecified scenario (lead zero's system goes down mid-lead) and asks to amend O-6; different resolution, no summary rule |
| G14 `run.main(roster=)` judged and honoured | implementation | **partial** | DC-1a reads the roster once in `run.main` and hands it down |
| G17 startup scope = gather grants; CI fixtures with explicit grants (post-review commits 30530458, 4eea157a) | after code review | **caught** | DC-1b: three readings of "granted"/O-8 predicate, needs a ruling; DC-5: 58 `1222` tests fail on the fixture tenant |
| — `descriptor_catalog` retired for `descriptor_index(...).render(down)` | code review round 2 | **caught** | DC-7: `descriptor_catalog` silently drops a broken adapter from gather's index |
| G12 #1080 import census / G13 #1210 `.data_root` census | implementation | missed | |
| G15 specific older-test defects | implementation | missed (analogous older-test fallout found: DC-5) | |
| G16 literal folder label | CI | missed | |
| G5–G11 adversary holes | code-stage adversary | n/a until step 4 | DC-6 (reason redaction) and DC-7 touch A6 and O-3 |

Original-review parity: R5 (escaped ConfigFault in lead zero must not name the breaker) is re-found by DC-2.

Not in history, plausibly real: DC-3 (ConfigFault shares exit 2 and `error_class="infra"`; the no-charge flag protects one site only).

## Cost
| Agent | Model | Steps | Cost |
|---|---|---|---|
| Code map | Sonnet | 20 | $0.93 |
| Sketch | Opus | 43 | $2.84 |
| Spike | Sonnet | 39 | $1.62 |
| Design check | Opus | 32 | $2.27 |
| **Total** | | | **$7.66** |

## Lessons for the skill
- The design check's "drop spike mess / pre-existing behaviour" filter discarded a real finding (G2). Pre-existing behaviour that the new design makes wrong is a finding, not noise.
