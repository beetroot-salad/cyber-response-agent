# Gather writes verifiable summary code (#289)

*Design rationale for the `defender-record-summary` capture wrapper and the
code-first gather SKILL §4. The runnable spec is `skills/gather/SKILL.md` §4 +
`scripts/tools/record_summary.py`; this doc is the why. Validated as a pilot in
`experiments/gather-verifiable-code-289/` (n=1/cell, directional).*

## Problem

The gather subagent (Haiku) returns a free-text **summary** of each query's raw
payload. The main loop is barred from `gather_raw/`
(`hooks/block_main_loop_raw_access.py`), so the summary *is* the contract. When
the summary silently drops or distorts a dimension it was asked for — the "A2"
class — the loss is unrecoverable by the defender and invisible downstream. This
is not gather editorializing (the SKILL already bans interpretation); it is
gather **misreporting a number it was asked for**, especially over large or
truncated payloads it cannot eyeball.

## Two mechanisms, two consumers

The fix bundles two things with different consumers — keep them separate:

1. **The wrapper pass-through — the runtime win.** `defender-record-summary`
   runs the snippet and **its stdout *is* the reported value**; gather cannot
   substitute prose for a snippet that errored or returned nothing. The runtime
   defender benefits directly, through gather's summary. *Needs no table.*
2. **The `summaries.jsonl` table — the offline audit surface.** The runtime
   defender never reads it. Its consumer is the learning-loop judge (#275), for
   fault **attribution** (see below). The MVP **writes** the table; wiring it
   into `learning/lead_repository.py` + `judge.md` is a filed follow-up.

## The analysis tool suite — pure transforms only

jq covers ~80% of computable dimensions. The gap (real statistics, columnar/set
ops) is closed by **GNU `datamash` + coreutils filters** (`sort`, `uniq`, `cut`,
`comm`, `join`, `wc`, `tr`, `paste`, `nl`, `head`, `tail`, `grep`), bridged onto
nested JSON by `jq -r '… | @tsv' | datamash …`. Estimated ~93–95%.

The one property that lets the summary step run **without a sandbox**: every
permitted tool is a *pure transform* — no `exec`/`system()`/network/file-write.
A tool with a scripting surface (`awk`, `sqlite3`, `mlr`'s DSL, `python3`) is a
*language*, and admitting one is the Phase-2 sandbox decision, not this. The
residual ~5% (stateful multi-pass logic, sequential-pattern detection, arbitrary
correlation) is language-shaped — Phase 2, or it belongs in the defender's
ANALYZE / the judge's reasoning.

## The gate — honest and deterministic

The gate is **the wrapper itself** (`record_summary.py`), because the inner tool
is opaque to a head-based permission hook (`approve_shim_invocations` only sees
the `defender-record-summary` shim at the segment head). `python3` is not on the
runtime allowlist, so privileged code reaches execution *only* through this
scanning wrapper — the design keeps it that way. Enforcement is fail-closed (any
doubt → `exit 2`):

- **No shell, ever.** The pipeline is split quote-aware on `|` and wired with
  `subprocess` pipes. So `>`/`$(...)`/backticks are inert literal argv tokens
  (the tool chokes on them), not redirects or substitutions — they can't fire.
  This is what reduces the gate to four cheap, deterministic checks.
- **Tool allowlist** — every pipe segment's head ∈ the pure-transform suite.
- **Read-scope** — any token resolving to an *existing* file must live under
  `{run_dir}/gather_raw/`; closes `jq '.' /workspace/.env`-style exfil. Non-file
  tokens (jq programs, field numbers) are unconstrained — they leak nothing.
- **Scrubbed env + rlimits** — minimal env (no creds; note `jq -n env` would
  otherwise dump the environment), CPU/address-space caps, wall timeout.

The model writes correct code when it checks it, so §4 has gather **self-test**
the snippet on ~5 sample records with the bare tool before running the validated
snippet through the wrapper over the whole payload.

## Why a third table, and why consumption is a follow-up

`summaries.jsonl` is keyed `(lead_id, payload_seq, summary_seq)` — a sibling of
the queries table, FK to a specific payload (the wrapper derives `payload_seq`
from the `gather_raw/l-…/<seq>.json` path the snippet reads). The MVP writes it
but does **not** wire `lead_repository.py`, because the only consumer is the
judge and consuming it is a deliberate judge change:

- The #275 judge already has a from-scratch raw surface (`jq`/`grep` over
  `gather_raw/`), so it can already *catch* a wrong number.
- What it cannot do today is **attribute**: its surface is oracle projection vs.
  actual payload vs. the *defender's* reasoning — gather's summary (the A2 layer)
  is never separately surfaced, so a refuted belief can't be split into *gather
  misreported* vs. *defender misreasoned*. `summaries.jsonl` gives the judge the
  values gather actually computed, plus a cheap replay target.
- Realizing that needs a `judge.md` surface addition **and a new
  `gather-fidelity` finding type** (the current type set has no slot for it).

This is also the backstop for the one integrity gap: the value-producing run
*should* go through the wrapper, but the self-test legitimately uses bare jq, so
no hard gate can force it. A reported value with no backing `summaries.jsonl` row
is exactly a `gather-fidelity` finding for that judge pass.

## Deferred / follow-ups

- **Judge attribution (#275):** wire `summaries.jsonl` into `lead_repository.py`
  + add the surface and `gather-fidelity` finding type to `judge.md`.
- **Phase 2 — Python via AST allowlist + namespace sandbox.** Only the ~5% the
  suite can't express. The security boundary is **kernel-enforced isolation**,
  not the AST scan: run the snippet under a namespace sandbox (`bwrap`/`nsjail`)
  **inside the existing run container** (no per-gather container) — no-network
  namespace, read-only `gather_raw/` bind, tmpfs elsewhere, stripped env,
  rlimits — with the AST allowlist (`json/re/statistics/datetime/collections/
  math/itertools`; deny `eval/exec/compile/__import__/getattr/__builtins__`/
  dunder-attr) as defense-in-depth and inline `-c` only (scan-and-run the same
  bytes, no TOCTOU). The summary step needs **no credentials** (it runs over
  persisted files), which is what makes it sandboxable.
- **`read_file` tool cap (#303)** / **`GATHER_REQUEST_LIMIT` (#304)** — own
  runtime-reliability issues; this MVP mitigates #303's symptom by keeping gather
  off whole-file reads, but the tool cap is the real fix.

## Ops

`datamash` must be installed in dev and the prod run-container
(`apt-get install -y datamash`); jq + coreutils + grep are already present.
