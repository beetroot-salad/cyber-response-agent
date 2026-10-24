# Replay: new write-tests steps 1–4 on #1256

## Question
Engineering — does the new write-tests front end (code map, sketch, spike, design check, Sonnet thorough authoring, fidelity reviewer + attackers) surface, before the contract is committed, problems that the historical #1256 run only found later (code-stage adversary, implementation, CI, code review)?

Directional, not a quality verdict: the replay is one bounded pass and will be less rigorous than the real run.

## Variants
### current (regression) — the historical run, not re-run
Design r3 → old write-tests (Opus author, Opus reviewer + lenses, repairs R1–R7) → contract `50aa46cf` → old write-code-from-tests (honest implementer + blind adversary) → code review → r4. Its record (PR #1261 body, commits, #1256 comments) is the baseline. Re-running it would cost as much again and still be compared against the same history.

### proposed — PR #1280 head, write-tests §1–§4 only
Sketch (Opus) → spike (Sonnet) → design check (Opus) → thorough authoring (Sonnet, one author, core flows) → panel: fidelity reviewer (Opus, no code map) + 2 attackers (Sonnet). No repair rounds, no human rulings: findings are recorded, not acted on.

This bundles several changes; it tests the package, not one variable. Attribution comes from *which step* found each item.

## Fixture
- Issue #1256, design r3 (first comment, as of 2026-10-15T15:19Z), base `d7b1886d`.
- Load-bearing: the historical run's late findings include two structural shortcuts code review traced to design properties (one owner of status, one maker of a down cause), a human ruling (D5) and 7 holes the code-stage adversary found in a reviewed contract.

### Leakage controls
- A fresh repository containing only history up to `d7b1886d` (`git fetch` of that commit into an empty repo), so later commits and branches don't exist.
- Agents get the design r3 text as a file; they may not use `gh` or read #1256, #1261 or anything in `/workspace` outside the skill files.
- Agents read skill text from `/workspace/spec-flow/skills/` (branch `spec-flow/cheaper-agent-work`), nothing else from `/workspace`.

## Ground truth (what history found after the original write-tests stage)
| ID | Found at | Item |
|---|---|---|
| G1 | code review → r4 | One owner of system status: judged once at run start, every surface renders from current status |
| G2 | code review → r4 | Down gate must run before the lead claim, for every cause |
| G3 | code review → r4 | One maker of a down cause (start check, call-time escape, scaffold validator); paths hidden only at boundaries |
| G4 | code review → r4 (human) | D5/D5a: lead zero keeps a summary (its final text) written before its system went down |
| G5–G11 | code-stage adversary | A1 fault-type census; A2 run.py ignoring broken adapters; A3 resume drops down status; A4 combined log line; A5 instruction polarity; A6 host paths in model-visible surfaces; A7 exception types at import/check |
| G12 | implementation | `ConfigFault` import would break the #1080 import census |
| G13 | implementation | `.data_root` read banned by the #1210 census; roots come from `Tenant.root_names()` |
| G14 | implementation | `run.main(roster=)` not honoured; the start check must judge the roster handed in |
| G15 | implementation | Contract defects: "no systems" arm deletes a file tenant resolution needs; upper-case run id refused; #1234 retry test broken by the harness change |
| G16 | CI | Query tool spelled the code-folder label as a literal |

Baseline parity: the original write-tests review found R1–R7. The replay's step 4 should find comparable contract-level issues; failing that is a regression signal.

## Trials
Validation = the run: 1 trial. No scale-up planned; a second fixture (#1263, 19 adversary holes) only if this one is well-formed and the signal is ambiguous.

Estimated cost: 7 agents, roughly $40–80 at list prices.

## Scoring
Per ground-truth item: **caught** (the finding names the same defect, with evidence), **partial** (points at the right area, wrong or vague mechanism), **missed**; plus the step that caught it. Separately: findings that don't match history, sorted into plausible-real versus noise, because a pipeline that "finds" everything is useless. Scored by me against quoted findings; borderline items get a second read by a fresh judge given only the finding and the ground-truth row.

## Decision criteria
- **Proposed looks promising** if the spike or design check surfaces at least one of G1–G4, or the step-4 attackers reproduce at least two of G5–G11, without noise dominating.
- **Proposed looks no better** if none of G1–G11 surface, or step 4 misses most of what R1–R7 found.
- Either way it is one fixture: directional only.

## Layout
experiments/write-tests-replay-1256/
  plan.md
  fixtures/   design-r3.md, ground-truth.md
  runs/       per-step outputs (sketch, spike log + diff, design check, authoring, review, attacks)
  results/    scoring.md
