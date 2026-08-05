# #575 — demands extracted from the design (step 2)

## Demand #0 — the return-value contract  ⚠️ AMBIGUOUS, carry to step 7

Design says: *"The gate returns **which grant matched**; dispatch switches on `grant.route` instead of on `decision.adapter_argv` / `.sql_pipe` set from a per-agent bit."*

But `tools.py:257-271` (`_tool_bash`) consumes `decision.adapter_argv` and `decision.sql_pipe` to drive `_capture_adapter` / `_capture_adapter_sql`. Two defensible readings:

- **(A) Decision gains `.route` + `.grant`; `.adapter_argv`/`.sql_pipe` are DELETED.** `_tool_bash` switches on `decision.route` and pulls the argv out of the already-parsed `decision.pipelines`. Purest — "dispatch switches on grant.route" literally.
- **(B) Decision gains `.route`; `.adapter_argv`/`.sql_pipe` remain as the ROUTE'S PAYLOAD**, now populated from the matched grant rather than from a per-agent bit. Smaller blast radius on `tools.py`; the bit is gone either way.

**Provisional reading: (B)** — the design's stated non-goal is "a re-shaping of the mechanism, not a re-scoping"; the capture path's payload shape is not what the issue set out to change, and (A) forces `_tool_bash` + `_capture_adapter*` into the diff. Flag as fork F0.

d0  behavior/test — `decide_bash` returns a `Decision` carrying the matched grant's `route`, and (provisionally) retains `adapter_argv`/`sql_pipe` as that route's payload; `allow=False` carries `reason`.
    binds: [decide_bash, Decision.route, Decision.adapter_argv, Decision.sql_pipe]

## The containment model

d1  behavior/test — a command is allowed only if it matches a grant's `pattern` AND every operand the program opens resolves into that grant's `scope`.  binds: [decide_bash, Grant.pattern, Grant.scope]
d2  negative/test — **no compiled `Grant.pattern` contains a path**: introspect every agent's `bash_allow` and assert no pattern's source contains `/` or the run_dir/defender_dir strings.  binds: [Grant.pattern]
    positive control: the *scope* patterns DO contain the anchored roots (so the observation channel can see the difference).
d3  behavior/test — `under(root, tail)` fullmatches against the **resolved** path.  binds: [under]
d4  negative/test — no path shape uses `[^\x00]*`; the run-dir shapes are tight (`gather_raw/\d+\.json`, `investigation\.md`, `report\.md`, `gather_summaries/l-\d+\.md`).  binds: [GATHER_RAW, INVESTIGATION, REPORT, SUMMARIES]
d5  negative/test — **symlink**: a symlink at `{run_dir}/evil.json` → `/etc/passwd` is DENIED for `cat` on the BASH lane.  binds: [decide_bash, Grant.scope]
    positive control: a real (non-symlink) `{run_dir}/gather_raw/0.json` under the same grant is ALLOWED for gather.
d5b negative/test — a symlink at `{run_dir}/x.json` → another **in-root** file is ALLOWED (resolve() lands in scope) — pins that d5 denies for the right reason (escape), not "symlinks are banned".

## The PROGRAMS table

d6  behavior/test — `PROGRAMS["cat"]` is `_cat_input_files`; every other granted program maps to `OPENS_NOTHING`.  binds: [PROGRAMS]
d7  behavior/test — `compile_policy` **RAISES** (loud, not silent) when a grant names a program absent from `PROGRAMS`.  binds: [compile_policy, PROGRAMS]
    (This is the structural fix for the `viewers` silent-drop bug.)
d8  domain-outcome/test — `_cat_input_files` returns `None` (→ DENY) for **every** unrecognized `-`-prefixed token; per-token table.  binds: [_cat_input_files]
    positive control: known boolean bundles (`-n`, `-A`, `-vET`) extract the file operands correctly.
d9  behavior/test — a program mapped to `OPENS_NOTHING` opens nothing: `grep`/`head`/`tail`/`wc`/`jq` with any argv extract `[]`, so the scope check is vacuous and the shape regex is the whole gate.  binds: [PROGRAMS, OPENS_NOTHING]

## The lane after the change

d10 domain-outcome/test — **stdin-only viewers**: `grep -n secret {run}/x.md` (file operand) is **DENIED**; `cat {run}/x.md | grep -n secret` is **ALLOWED**. Same for `head`/`tail`/`wc`/`jq`.  binds: [Grant.pattern[grep], Grant.pattern[head], Grant.pattern[tail], Grant.pattern[wc], Grant.pattern[jq]]
    ⚠️ This is THE documented behavior change. Pin both sides.
d11 negative/test — `ls` (any form) and `cd` (any form) are DENIED for main and gather.  binds: [MAIN_DEF.bash_allow, GATHER_DEF.bash_allow]
    positive control: the surviving programs (`cat`, `grep`, `defender-sql`, …) still ALLOW.
d12 survival/test — the one live `jq` query template's command (`cat ${payload} | jq -r --arg uid VAL '<filter>'`) is still ALLOWED for gather — no template rewrite needed.  binds: [Grant.pattern[jq]]
d13 survival/test — `_overflow_filter_hint` still names a reducer the agent can actually run (`jq` survives for main/gather), i.e. the hint's program is admitted by the caller's own lane.  binds: [_overflow_filter_hint]

## gather_raw — positive enumeration

d14 domain-outcome/test — `cat {run_dir}/gather_raw/0.json`: **ALLOW for gather, DENY for main**, on the bash lane.  binds: [GATHER_RAW, MAIN_DEF.bash_allow, GATHER_DEF.bash_allow]
d15 parity/test — the same `(agent, path)` verdict holds on the **read tool** (`decide_read`) as on the bash lane, for gather_raw AND for the corpus — read↔bash parity, now that both consume the same shape objects.  binds: [decide_read, decide_bash]
d16 negative/test — `RAW_MARKER`-in-command substring scan is gone: a command whose **grep pattern or SQL string** merely CONTAINS the literal text `gather_raw` (but opens no gather_raw file) is NOT denied for that reason. e.g. main: `cat {run}/report.md | grep gather_raw` → ALLOW.
    ⚠️ Under HEAD this DENIES (substring scan). This is a second documented behavior change — surface at step 7.  binds: [decide_bash]

## Definitions carry their own policy

d17 seam/test — every `AgentDefinition` carries `bash_shapes`, and all three builders share the signature `(ResolvedRoots) -> tuple[...]`.  binds: [AgentDefinition.bash_shapes, AgentDefinition.read_shapes, AgentDefinition.write_shapes]
d18 negative/test — nothing under `runtime/` imports a private symbol from `defender.learning.*`, and nothing under `runtime/` enumerates agents (AST scan over the package).  binds: [runtime]
    positive control: `defender/agents.py` (the relocated registry) DOES import the 6 `*_DEF`s — proof the scan can see such an import when present.
d19 negative/test — `BashGrammar` no longer exists; `AgentPolicy` no longer carries `read_shapes`/`read_roots`/`read_confine`/`raw_reads`/`operand_gated`/`adapters`/`adapter_sql_pipe`.  binds: [AgentPolicy, BashGrammar]

## Parity

d20 parity/test — **the allow-matrix**: a fixed corpus of `(agent, command)` triples, verdict-for-verdict identical to HEAD, EXCEPT the documented rows (d10 file-operand viewers, d11 ls/cd, d16 raw substring). Golden file, committed.  binds: [decide_bash]
    All 8 agents × the corpus.
d21 behavior/test — the e2e replay suite (`-m e2e`) is green. (Existing suite; no new test — records the obligation.)

## The audit tool

d22 behavior/test — `defender-policy show <agent> --run-dir X` prints each agent's read/write/bash grants with scopes.  binds: [defender-policy]
d23 behavior/test — `defender-policy explain <agent> "<cmd>"` prints the resolution trace (shape matched → opens → resolved → scope verdict) and the final ALLOW/DENY, agreeing with `decide_bash`.  binds: [defender-policy, decide_bash]

## Classified BACKGROUND (not demands)

- "Net LOC does not increase" — a review property, not observable behavior. `form: clause`.
- "The lines that die are logic; the lines born are data" — rationale.
- The #579/#581 history, the `_common.py:136` invariant narrative — motivation.
- "Every subsequent permission refinement should be a one-line change to a tuple" — a design aspiration; d17+d19 are its testable core.

## Forks to carry to step 7

- **F0** — Decision's shape (reading A vs B above). Provisional: B.
- **F1** — d16: dropping the RAW_MARKER substring scan is a *second* undocumented-in-the-issue behavior change. Is it intended? (I believe yes — it's the point of positive enumeration — but the issue's parity criterion names only the `cat |` change.)
- **F2** — d13: does `jq` actually survive for main/gather, or was retiring it still intended? The design says jq survives (stdin-only). But the user said "jq has been effectively retired, this is the cleanup." Conflict between the conversation and the final design text.
