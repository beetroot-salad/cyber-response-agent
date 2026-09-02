# Findings — moving invlang authorship out of MAIN

16 trials, glm-5.2 MAIN, clerk on kimi-k2.6, two fixtures × two arms × 4, live playground
restored from the 2026-08-12 snapshot. Per-fixture detail: `f1.md` (benign), `f2.md`
(malicious). Scores: `final.jsonl`; judge: `judge-F1.jsonl`, `judge-F2.jsonl`.

## Answer, in three lines

1. **Cost: with the kimi clerk the whole run is a wash ($0.79 vs $0.79 per run) — MAIN gets
   59% cheaper and the clerk costs that back; with a cheap clerk the whole run drops to
   $0.64 (DeepSeek V4 Flash, arm D) or $0.51 (GLM 5.3 Flash, arm E) — 33–46% under today —
   because the clerk then costs $0.03–0.06.** (Both n=3, F1 only.) The pre-measurement's prediction (clerk
   arm 15–40% more) was wrong for a reason worth keeping: MAIN's output tokens fell 65%, not
   the 22% the "mechanical share" said — two thirds of MAIN's thinking was about the format.
2. **Quality: the clerk arm never produced a false negative; the current arm produced three.**
   On the attack fixture A closed `benign` 3/4 on "this is a training simulation"; C found the
   same markers and refused to close benign without an authorizing record. On the benign
   fixture C was right 3/4 vs A's 2/4, and A closed `malicious` once on a container startup
   script. The blinded judge — which scores *earned process*, not the label — leans C on F1
   (8–5–3) and A on F2 (11–4–1; A 7–4–1 with C's crashed run removed): overall A 16, C 12,
   tie 4. The two instruments disagree exactly where the fixture's simulation markers make a
   well-evidenced benign close and a false negative the same document.
3. **Reliability: the throwaway build is the arm's weak point, not the idea — and one of its
   faults confounds the judge.** In 8 of 11 clerk-arm runs the record has **no `:T conclude`
   block** (A: 8/8 have it): MAIN's prose-only prompt sends it straight to
   `close_investigation` without `record`ing the closing prose, so the disposition's
   rationale, ceiling and detection notes never reach rows. The judge reads the record's
   closing claim — so every A-vs-C pair compared a closed document against one that ends at
   its last ANALYZE, which is part of why the judge leans A on F2 (11–4). Also: one C run died
   on a provider 503 the tool doesn't catch; one blocking pattern (a resolution owned by two
   leads) is 60% of the clerk's absorbed refusals and most of its give-ups. All are one-line
   fixes in a real build (the cleanest: `close_investigation` refuses a record with no
   `:T conclude`); none were fixed mid-experiment so the arms would stay comparable.

## Arm D — clerk on DeepSeek V4 Flash (added after, n=3 on F1; detail in `d.md`)

Whole run **$0.64** vs kimi-clerk $0.79 and current $0.96 — a third cheaper than today.
MAIN's saving is identical ($0.175 vs $0.170; it comes from the prose-only prompt, not the
clerk's model) and the clerk itself drops from $0.27 to **$0.06** per run (DeepSeek V4 Flash
serverless: $0.22 / $0.007 / $0.66 per M — a quarter of kimi's price, which outweighs its
worse cache-hit share, 29% vs 56%). With this clerk MAIN+clerk is $0.23 against A's MAIN
alone at $0.43. The record it compiles, though, is judged the weaker one in every pair
against the kimi clerk (C 10, D 0, tie 2 on 12 pairs — both arms share the close-block gap,
so that comparison is clean). Against the current arm the judge says A 7, D 2, tie 3 of 12.
Dispositions benign / malicious / unresolved (1/3 correct); the malicious one is the operator-SSH
bait no kimi-clerk run took. Three runs: the cost result is solid (it is arithmetic on the same
token counts), the quality result is a flag, not a finding. (The first version of this note
priced DeepSeek from Fireworks' training-API table, 8× too high; corrected.)

## Arm E — clerk on GLM 5.3 Flash (added after, n=3 on F1; detail in `e.md`)

Whole run **$0.51** — the cheapest arm — with the clerk at $0.03/run and MAIN at the same
$0.17 every clerk arm shows. This clerk needed the fewest rounds per record of any (1.56 vs
2.7–2.8) and the fewest model calls per run (13 vs 18–19), *with reasoning on*: GLM refuses
`reasoning_effort=none`, so E ran at `low` where kimi and DeepSeek ran with reasoning off — a
second variable, and possibly the reason it converges faster. Dispositions benign ×2,
inconclusive (2/3); no bait taken, no `unresolved`. Judged: kimi's records beat GLM's 10–1–1,
GLM's beat DeepSeek's 5–2–2 — the record-quality ranking is kimi > GLM > DeepSeek and the cost
ranking is the reverse. Three runs: the cost is arithmetic and solid; the quality is a good
sign, not a result.

## The numbers (n=8 per arm, both fixtures)

| per run | A current | C clerk |
|---|---|---|
| whole run $ | 0.787 | 0.791 |
| MAIN $ | 0.372 | **0.154** |
| clerk $ | — | 0.245 |
| gather $ | 0.357 | 0.337 |
| MAIN output tokens | 38.3k | **13.3k** |
| MAIN turns | 17.3 | 14.3 |
| validator refusals MAIN absorbed | 1.1 | 0.1 |
| clerk calls / refusals absorbed / give-ups | — | 6.3 / 11.3 / 1.0 |
| concluded | 8/8 | 7/8 (one 503 crash) |
| correct vs label | 3/8 | 4/8 |
| closed benign on the attack (FN) | **3** | **0** |
| record validates at close | 8/8 | 7/7 |
| wall min | 13.4 | 14.1 |

Gather is the largest and noisiest cost centre (per-run $0.11–0.82, driven by lead count and
how deep each gather session goes). It decides the headline in both directions — favouring C
on F1, A on F2 — and this n cannot say whether MAIN plans fewer leads with less in front of it.
Read MAIN+clerk instead: $0.40 vs A's $0.37. The clerk pays for itself; it does not yet net a
saving on the part of the run it touches.

## What was actually learned

**The grammar is where MAIN's thinking went.** Every A run has a 10–11.5k-token turn — the
row-authoring turn; C's largest is 2.4–4k. The prose MAIN sends through tools is the same
size in both arms. This is the mechanism the auditor-role-986 Track 2 hypothesised
("interference") and could not measure; it is now measured, and it is bigger than the
share-of-context argument predicted.

**The refusal split works as designed and is the useful instrument.** Parse, cell-count and
vocab errors stayed with the clerk (MAIN saw 0.1 refusals/run instead of 1.1); judgment
refusals — a declared prediction never settled, a `--` resting on a non-authoritative edge —
came back to MAIN as gaps. The clerk's own diagnoses read like the #986 issue text
("container `e5b0213bd690` mentioned but never given a vertex id"), which is what a monitor
of prose-versus-record is for.

**Discipline, not correctness, is what moved.** The label match barely moved (3/8 → 4/8).
What moved is the *shape* of the errors: A's misses are confident closes on the wrong side
(malicious on a startup script; benign on a planted key); C's are `inconclusive`/`unresolved`
with the gap named. For a system whose cardinal sin is the false negative, that is the
difference that matters, and it came with MAIN doing less thinking, not more.

**Two fixture caveats travel with these results.** F1's window coincides with the operator's
own root SSH into the VPS (A-t3's "malicious" and the earlier b986-t6 both bit on it). F2's
attack runner plants a key literally named `fake_key` with comment `attacker@elsewhere` and
the host carries months of simulation history — A's benign closes are reading the lab, and
the label calls that a miss. Both should be scrubbed before either alert becomes a held-out
case.

## Decision against the plan's criteria

- *C wins on cost* — **no**: whole-run $ equal; MAIN+clerk slightly higher.
- *C wins on quality* — **partly**: F1 correct rate 3/4 vs 2/4 (the plan asked for ≥3/4 —
  met), F2 zero malicious→benign flips in C (met) — but the pairwise judge is 50% on F1 and
  25% on F2, both under the 65% bar, and n=4 per cell. On the judge's own terms A's closes
  are the better-earned documents; on the label's terms three of them are misses — and the
  judge compared closed A records against C records that mostly have no close block, so the
  pairwise number is not clean.
- *A retained on "only the record got tidier"* — **no**: the record did get tidier, and MAIN's
  thinking dropped by two thirds and its false negatives went from 3 to 0. That is not tidiness.

**Recommendation:** take the split to a design, on the strength of the false-negative result
and the MAIN-thinking result — not the judge, which favours A. The experiment shows the cost
of the mechanism is neutral and its quality effect is on the axis that matters, with the caveat
that the clerk here is a two-day throwaway whose three known faults each cost it runs. The
design questions it leaves are the ones the throwaway dodged: provider-error degradation in
`record`, the multi-owner-lead rule in the clerk prompt, and whether gather's lead count
genuinely shifts when MAIN's context shrinks — the last needs n≈15 on one fixture, ~$12.

## Follow-ups filed here, not fixed

- **`close_investigation` should refuse a record with no `:T conclude` block** (or the C
  prompt must `record` the REPORT prose before closing). 8 of 11 clerk-arm records end at
  ANALYZE; re-judge A-vs-C after this fix before trusting any pairwise number.
- `CLERK.md`: "a resolution names exactly one owning lead; other contributing leads go in
  `cites_leads`" — 28 of 47 absorbed refusals on F1.
- `record`: catch provider errors, keep the prose, return "rows pending" to MAIN.
- `record`: on give-up, return the clerk's last block to MAIN so a re-statement is a repair,
  not a rewrite.
- A per-lead gather budget or a lead-count comparison at n≥15 before any cost claim beyond
  "neutral" is made.
- Scrub the two fixtures' world artifacts (operator SSH in F1's window; simulation markers in
  F2) before promoting either to `fixtures/held-out/`.
