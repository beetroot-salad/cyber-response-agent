# #289 design proposal — gather writes verifiable summary code (pure-transform suite)

*Status: **landed (MVP).** Validated pilot under `variants/proposed/`; this doc
was the landing spec. Production rationale lives at
`defender/docs/gather-verifiable-summary.md`; this copy stays as the experiment's
record. **Naming:** the landed helper is `defender-record-summary` writing
`summaries.jsonl`; the pilot prototype under `variants/proposed/` used the older
`record-analysis`/`analyses.jsonl` names — those artifacts are left as-is.*

## Problem (recap of #289)

The gather subagent (Haiku) returns a **free-text summary** of each query's raw
payload. Those summaries are LLM assertions over data the main loop can never
see (`block_main_loop_raw_access` bars it from `gather_raw/`). When the summary
silently drops or distorts a dimension it was asked for (the "A2" class), the
loss is unrecoverable and invisible downstream. gather's SKILL already bans
*interpretation* (§4) — so A2 is not gather editorializing, it is gather
**misreporting a number it was asked for**, especially over large/truncated
payloads it cannot eyeball.

## Two mechanisms, two consumers (keep them separate)

#289 bundles two things that have different consumers and different blast
radius. Pulling them apart is what makes the MVP small.

1. **The wrapper pass-through — the runtime win.** The capture wrapper runs the
   analysis snippet and **its stdout *is* the reported value**; gather cannot
   substitute prose for a snippet that errored or returned nothing. The runtime
   defender benefits directly, through gather's summary. **This needs no table.**
2. **The `summaries.jsonl` table — the offline audit surface.** The runtime
   defender never reads it (it is blocked from `gather_raw/` and reasons only
   from the summary). Its consumer is the **learning-loop judge** (#275). See
   *Why the table, and why it is a follow-up* below.

## Proposed change (validated)

Make each *computable* `what_to_summarize` dimension a **recorded computation
whose output is the reported value**, not a prose assertion.

1. **`defender-record-summary` capture wrapper** (sibling of
   `record_query.py`). Runs an analysis snippet over an already-persisted,
   read-only payload, captures stdout, and **that stdout is the value**.
   Appends a `{lead_id, payload_seq, analysis_seq, label, snippet, output,
   exit_code}` row to a sibling **`summaries.jsonl`** and passes output through.
   ```bash
   defender-record-summary --lead l-001 --label distinct-srcusers -- \
       jq '[.[].data.srcuser] | unique' gather_raw/l-001/0.json
   ```
2. **gather SKILL §4 rewrite (code-first).** For each computable dimension:
   write a snippet, **self-test it on ~5 sample records** with the bare tool
   (cheap, in-context — catches wrong field paths), then run the validated
   snippet over the *full* payload through the wrapper. Salience (which entity
   matters) stays a model judgement, anchored to the computed numbers above it.
   The framing that tested best: *the whole summary is produced by code;
   judgement enters in what to compute*, not a per-bullet computable/interpretive
   split.

## The analysis tool suite — pure transforms only

jq alone covers ~80% of computable dimensions (counts, cardinalities, ranges,
first/last, ratios, top-N, regex, epoch-datetime deltas). The gap is real
**statistics** (median/percentile/stddev/mode/grouped aggregates) and
**columnar/set** operations, which jq expresses badly.

The line that keeps the analysis step **safe without a sandbox** is a single
property: every permitted tool is a **pure transform** — no `exec`, no
`system()`, no network, no file-write, no shell-out. A tool that has any of
those is not a filter, it is a *language*, and admitting it is the same
decision as admitting arbitrary Python (deferred — see Phase 2).

**Permitted (pure transforms):**

- **`jq`** — JSON reshape / filter / cardinality / regex / epoch math.
- **GNU `datamash`** — the statistics keystone: `mean median q1 q3 perc stddev
  mode count countunique sum min max`, `groupby`, `crosstab`. No DSL, no
  `system()`, no write.
- **coreutils filters** — `sort, uniq, cut, comm, join, wc, tr, paste, nl,
  head, tail` (the `sort | uniq -c | sort -rn` distribution idiom; `comm`/`join`
  for set-ops across two payloads).
- **`grep`** — read-only match (already allowed).

The bridge onto nested JSON is the standard recipe `jq -r '… | @tsv' | datamash
…` — well represented in training data, so Haiku reaches for it. Estimated
coverage: jq ~80% → + coreutils ~88% → **+ datamash ~93–95%**.

**Excluded (a `system()`/exec surface — this *is* the Python decision):**

- **`awk`** (`system()`, `cmd | getline`, `print > file`),
  **`sqlite3`** (`.shell`/`.system`/ATTACH/`load_extension`),
  **`mlr`** (its `put`/`filter` DSL has `system()`), **`sed`** (GNU `e`/`r`/`w`;
  only `sed --sandbox` is safe, and it is text-munging, not stats — low value),
  and **arbitrary `python3`** (Phase 2).

The residual ~5% (stateful multi-pass logic, sequential-pattern detection,
arbitrary cross-payload correlation) is genuinely *language-shaped* — it is the
real Phase-2 trigger, or it belongs up in the defender's ANALYZE / the judge's
reasoning.

## The gate — honest and deterministic

The honest gate is **the wrapper itself**, not a settings glob or a head-based
hook: the inner tool is opaque to anything that only inspects the segment head
(that is the auto-approve hole this closes). The wrapper is the **sole**
privileged path — `python3` is not on the runtime allowlist, so privileged code
only ever reaches execution through the scanning wrapper, and the design keeps
it that way.

Enforcement, all in the wrapper, all deterministic, **fail-closed** (any doubt →
`exit 2`, never "allow"):

- **Pipeline-aware, shell-free.** A `jq … | datamash …` pipeline is split on
  `|` outside quotes (reusing `hooks/_cmd_segments.split_segments`), each
  segment's **head must be in the tool allowlist**, and the segments are wired
  with `subprocess` pipes — the wrapper never hands the string to a shell.
- **No redirects / substitutions / assignments** in any segment
  (`>`/`<`/`$(`/backtick/`VAR=`) → deny.
- **Read-scope is load-bearing.** Every path argument must resolve under
  `$DEFENDER_RUN_DIR/gather_raw/` (no absolute paths outside it, no `..`
  escape). This is what makes record-summary structurally "read-only over
  persisted payloads" and closes `jq '.' /workspace/.env`-style exfil.
- **Scrubbed env + resource limits.** The inner subprocess gets a minimal env
  (no adapter creds — note even `jq -n env`/`$ENV` reads the environment, so the
  strip matters for jq too), plus `RLIMIT_CPU`/`RLIMIT_AS`/`RLIMIT_FSIZE=0`
  (no writes) and a wall timeout.

## Why the table, and why it is a follow-up

`summaries.jsonl` is keyed `(lead_id, payload_seq, summary_seq)` — a sibling of
the queries table, FK to a specific payload. The MVP **writes** it (with
`payload_seq` derived from the payload path, so the FK is structured, not a
parsed string) but does **not** wire it into `lead_repository.py`, because the
only consumer is the judge and consuming it is a deliberate judge change, not
plumbing:

- The #275 judge **is built** and already has a from-scratch raw surface (`jq` +
  `grep` over `gather_raw/{lead}/{seq}.json`; it *must* query the full payload to
  assert an absence). So it can already *catch* a wrong number.
- What it cannot do today is **attribute**: its surface is oracle projection vs.
  actual payload vs. the *defender's* invlang reasoning — gather's summary (the
  A2 layer) is never separately surfaced, so a refuted belief can't be split
  into *gather misreported* vs. *defender misreasoned*.
- `summaries.jsonl` gives the judge the values gather actually computed, closing
  that attribution gap and offering a cheap replay target. **But** it needs a
  `judge.md` surface addition **and a new `gather-fidelity` finding type** (the
  current `lead-set | lead-quality | analyze-discipline | observability |
  detection-confirmed` set has no slot for it). That is its own PR.

## Pilot evidence

Isolated gather replay (real Haiku, in-process PydanticAI agent, fake adapter
serving frozen payloads), one variable: prose §4 vs code-first §4. Judge:
Sonnet, hand-calibrated. Full method + caveats in
`results/validation-findings.md` (n=1/cell — directional, not powered).

| fixture | A2 current ↓ | A2 proposed ↓ | completes | replay (prop) | cost (prop vs cur) |
|---|---|---|---|---|---|
| large-sshd-dump (4 MB, 2319 rec) | **1.00** | **0.00** (11/11) | cur **fails** → prop ok | 1.00 | n/a (cur crashes) |
| healthy-small (clean 8 rec) | 0.18 | **0.00** | both | 1.00 | **cheaper** (40s/3.4k vs 79s/6.1k) |
| same-second (buried 471 KB) | 0.12 | 0.12 | both | 0.88 | +34% wall (within 1.5×) |

- **Decisive on large dumps.** proposed computed every dimension exactly,
  including the A2 trap `distinct_users = 5` (sample-estimation under-reports it).
  prose-current **overflowed the 200 K context window** and returned nothing.
- **Small fidelity edge even on clean payloads** and **no cost regression**.
- **Scoping finding:** the buried-needle case is **parity** — #289's value
  concentrates on **aggregate fidelity over large dumps** (counts,
  cardinalities, ranges), not buried-fact reconstruction.

The directional signal is strong enough to land the MVP without first running
the `validation-findings.md` focused scale-up (large-dump N=10, etc.); production
runs are the next signal.

## What to land (MVP)

1. Promote `record_summary.py` → `defender/scripts/tools/` as the **enforcing,
   pipeline-aware** wrapper above (tool allowlist, path-scope, env-strip,
   rlimits, fail-closed); add `payload_seq` to the recorded row.
2. Add the `defender-record-summary` shim to `defender/bin/` (mirrors
   `defender-record-query`). The `NON_ADAPTER_SHIMS += defender-record-summary`
   gate edit already landed with the pilot.
3. Add `datamash` + the coreutils filters to `approve_shim_invocations.READONLY_TOOLS`
   so bare self-test pipelines auto-approve. Add `datamash` to the prod/dev
   image (`apt-get install datamash`).
4. Ship the proposed §4 (with the pure-transform suite; **no `python3` line**) as
   the real `defender/skills/gather/SKILL.md`.

## Deferred / filed follow-ups

- **Judge attribution (#275 composition):** wire `summaries.jsonl` into
  `lead_repository.py` + add the `summaries.jsonl` surface and a `gather-fidelity`
  finding type to `judge.md`.
- **Phase 2 — Python via AST allowlist + namespace sandbox.** Only the ~5% the
  pure-transform suite can't express. The security boundary is **kernel-enforced
  isolation**, not the AST scan: in prod run the snippet under a namespace
  sandbox (`bwrap`/`nsjail`) **inside the existing run container** (no
  per-gather container needed) — no network namespace, read-only bind of
  `gather_raw/`, tmpfs elsewhere, stripped env, rlimits — with the AST allowlist
  (`json/re/statistics/datetime/collections/math/itertools`; deny
  `eval/exec/compile/__import__/getattr/__builtins__`/dunder-attr) as
  defense-in-depth and inline `-c` only (scan-and-run the same bytes, no TOCTOU).
  Dev may run AST + rlimits + env-strip without the namespace (accepted risk).
  The analysis step needs **no credentials** (it runs over persisted files),
  which is what makes this sandboxable at all.
- **`read_file` tool cap (#303)** and **`GATHER_REQUEST_LIMIT` (#304)** — own
  runtime-reliability issues; the MVP mitigates #303's symptom by keeping gather
  off whole-file reads, but the tool cap is the real fix.
- **Banned-interpretation leak** — both variants still append "consistent with
  an automated script"; orthogonal to #289, a separate gather-SKILL tightening.
