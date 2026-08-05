# GROUNDING BRIEF — #575 (defender in-process permission gate rebuild)

Worktree `/workspace/.worktrees/575-write-tests`, base `09e0a93c`. FACTS, established by reading the code. Ground every test stub in these.

## THE CHANGE

- `AgentPolicy.bash_allow` becomes `tuple[Grant, ...]`. `Grant = {pattern: re.Pattern (command SHAPE — program + flags + arity, NO paths), scope: tuple[re.Pattern,...] (allowlist fullmatched against the RESOLVED operand path), route: Route (PLAIN | CAPTURE_ADAPTER | CAPTURE_ADAPTER_SQL)}`.
- Global `PROGRAMS: dict[str, Extractor]`: `cat -> _cat_input_files`; every other granted program -> `OPENS_NOTHING`. `compile_policy` must **RAISE** if a grant names a program absent from `PROGRAMS`.
- Gate: match a grant's `pattern` → `PROGRAMS[argv[0]](argv)` → `None` = DENY (fail closed) → `resolve()` each operand → fullmatch against `grant.scope` else DENY.
- `grep`/`head`/`tail`/`wc`/`jq` **lose their file-operand slot** → stdin-only pipe stages, `OPENS_NOTHING`.
- `ls` and `cd` are **deleted** from the main/gather lane.
- All textual path anchors leave the regexes. Containment = `resolve()` + anchored-regex-over-resolved-path.
- `read_shapes` / `reader_read_shapes` **deleted**. `raw_reads` bit **deleted**. The `RAW_MARKER in cmd` substring scan **deleted** — main's gather_raw denial becomes **positive enumeration** (the gather_raw path shape simply isn't in main's lists).
- `BashGrammar` dissolves. `_bash_allow`'s per-agent branches + its lazy `defender.learning.*` imports go. The registry (`runtime/agents.py`) moves out of `runtime/`.
- New path shapes (tight, declared — NOT `[^\x00]*`): `INVESTIGATION={run}/investigation\.md`, `REPORT={run}/report\.md`, `GATHER_RAW={run}/gather_raw/\d+\.json`, `SUMMARIES={run}/gather_summaries/l-\d+\.md`, `CORPUS_MD={dfn}/(lessons|skills|examples)/…\.md`.
- New CLI `defender-policy show <agent> --run-dir X` / `explain <agent> "<cmd>"`.

## A. THE GATE TODAY (base 09e0a93c)

`decide_bash(command, *, policy, run_dir, defender_dir) -> BashDecision` — `runtime/permission/bash.py:354-413`:
1. empty cmd → ALLOW (no pipelines) — :370
2. **RAW clamp** :379-384 — `if RAW_MARKER in cmd and not policy.raw_reads and not _names_a_gather_payload_tool(cmd): DENY`. A **substring scan over the raw string, before any parse**. `RAW_MARKER = "gather_raw"` (`hooks/block_main_loop_raw_access.py:62`). Exemption tokens: `record_query`, `defender-record-query` (bash.py:78-80).
3. `_parse(cmd)` :386-396 — `unwrap()` (strips `timeout <n>`, `bash -c`) → `bash_exec.parse`. `UntokenizableCommand` → DENY(UNTOKENIZABLE_REASON); other error → DENY(policy.deny_reason).
4. `_decide_readers(...)` :404-406 — returns non-None verbatim.
5. `command_shape.has_adapter(pipelines)` → `_decide_adapter` :410-411.
6. fall-through DENY(policy.deny_reason) :413.

`_decide_readers` (:325-351), three-valued:
- `if not stages or not all(_stage_shape_ok(s, policy)): return None`  (→ caller tries adapter routing)
- `if any(_stage_unsafe(s)): DENY`
- `if policy.operand_gated and not all(_operand_reads_within_roots(s,…)): DENY`
- else ALLOW.

`_stage_shape_ok(argv, policy)` :314-322 — `joined = " ".join(t.replace(" ", "\x00") for t in argv)`; `any(p.fullmatch(joined) for p in policy.bash_allow)`.
**`_TOKEN_SPACE = "\x00"` (:311): each token's OWN spaces become NUL, so every real space in `joined` is a true token boundary (anti-spoof).** This is why `[^\x00]` appears in argv-matched patterns — but a **scope** pattern matches a RESOLVED PATH, not a joined argv, so `[^\x00]*` there really does admit spaces/newlines.

`_stage_unsafe(argv)` :121-138 — DENY if a token is `(`/`)`, contains `$(` or a backtick, is `export`, or argv[0] matches `^[A-Za-z_]\w*=`.

`_operand_reads_within_roots(argv, policy, *, run_dir, defender_dir)` :264-297 — `extract = _OPERAND_GATED_PROGRAMS.get(argv[0])`; **`None` → True (PASS-THROUGH — an untabled program is silently ungated today)**; `files is None` → False; `defender_dir is None` → False; relative operands rebased on `defender_dir.parent`; each via `read_allowed_path`.

`_cat_input_files(argv)` :230-249 — the fail-closed rule:
```python
files, opts_done = [], False
for t in argv[1:]:
    if opts_done or t == "-" or not t.startswith("-"):
        if t != "-": files.append(t)          # bare "-" = stdin, NOT an operand
    elif t == "--": opts_done = True          # ends options
    elif not _CAT_BOOL_BUNDLE.fullmatch(t): return None   # FAIL CLOSED
return files
```
`_CAT_BOOL_BUNDLE = -[AbeEnstTuv]+` (bash.py:95). `_OPERAND_GATED_PROGRAMS = {"cat": _cat_input_files}` (:259-261) — the single entry.

`BashDecision(Decision)` :98-114 — `allow, reason, pipelines, adapter_argv, sql_pipe`. `Decision(allow, reason)` — `permission/decision.py`.

`_decide_adapter(pipelines, policy)` :212-227 — `not policy.adapters` → DENY(ADAPTER_DENY_REASON); `standalone_adapter_argv` → ALLOW(adapter_argv=…); `policy.adapter_sql_pipe and adapter_sql_split` → ALLOW(sql_pipe=…); else DENY(ADAPTER_STANDALONE_REASON).

`AgentPolicy` (policy.py:41-98) — 10 fields: `bash_allow, operand_gated, adapters, adapter_sql_pipe, raw_reads, read_roots, read_confine, write_allow, read_shapes, deny_reason`.

`files.py`: `_RESOLVE_ERRORS = (OSError, RuntimeError, ValueError)` (:27 — ValueError = embedded NUL). `_denylisted(rp)` (:39-49) — denies if any path PART is in `read_deny_dirs()` (`.ssh`) or any substring in `read_deny_substrings()` (`.env`, `credentials`, `ground_truth`, `ground-truth`, `cases.json`) is in `rp.name`. `read_allowed_path` (:81-104) — None roots → False; resolve error → False; denylisted → False; else `any(_is_within(rp, root))`. **Applies the denylist, NOT the raw clamp.** `decide_read` (:107-175) — resolve → roots → **`policy.read_shapes` fullmatch** (:156) → denylist (:166) → **`RAW_MARKER in str(rp) and not raw_reads` → RAW_DENY_REASON (:173)** → allow. `build_write_allow(root, suffix="")` (:68-78) — `re.escape(str(root.resolve())) + /[^\x00]*`.

`_common.py` (262 lines) — `_file_operand(run,dfn)` = deny-lookahead + `(_under(run) | _corpus_md(dfn))`. `_dir_operand` uses `_at_or_under` (ls/cd ONLY). Flag classes :108-138. `_VIEWER_ORDER = ("cat","wc","tail","head","grep","ls","cd","jq")` :155. **:141-154 = the load-bearing no-symlink-writer invariant comment.** `_viewer_program_patterns` :162-196, `pat = (?!-)[^ ]+` (:174, the #579 close):
```
cat : cat(?: {CAT_FLAG})*(?: {f})*        wc  : wc(?: {WC_FLAG})*(?: {f})*
tail/head: (?: (?:{NUM_FLAG}|[0-9]+))*(?: {f})*
grep: grep(?: {GREP_FLAG})*(?: {pat})(?: {f})*
ls  : ls(?: {LS_FLAG})*(?: {d})+   (operand REQUIRED)      cd : cd(?: {d})?
jq  : jq(?: (?:{JQ_FLAG}|{JQ_KV_FLAG}))*(?: {pat})   -- NO file slot already
```
File operands are `*` (optional) so **stdin-only pipe stages already match**. `reader_patterns_for` (:210-237) and `reader_read_shapes` (:240-262) are BOTH `@lru_cache(maxsize=1)`. **:250-259 = the opposite-resolution-semantics comment** (read shapes anchor on RESOLVED roots; the bash cat lane stays UNRESOLVED on purpose).

`bash_exec.py` — `parse()` raises `UntokenizableCommand` on lex failure; rejects operators/redirects it doesn't model. **`cd` is executed INLINE** (`_do_cd` :180-191, `_is_cd_pipeline` :300-302) and the updated cwd is **threaded into later pipelines** (:332-334). `_run_pipeline` spawns with **`shell=False`**, `cwd=defender_dir.parent` — so **globs, `$(...)`, `$VAR` NEVER EXPAND**.

## B. ALL 8 AGENT DEFINITIONS

| Def | file | ToolSet | BashGrammar | read_shapes | write_shapes | deps |
|---|---|---|---|---|---|---|
| MAIN_DEF | driver.py:243 | read,bash,write | `shims=NON_ADAPTER_SHIMS, viewers=READER_VIEWERS` | `(reader_read_shapes,)` | `(_main_write_shape,)` = `build_write_allow(run_dir)` | AgentDeps |
| GATHER_DEF | driver.py:261 | read,bash | same + `adapters=True, adapter_sql_pipe=True, raw_reads=True` | `(reader_read_shapes,)` | () | GatherDeps |
| JUDGE_DEF | judge/engine_pydantic.py:151 | read,bash | `operand_gated=True, raw_reads=True` (NO viewers/shims) | () | () | JudgeDeps |
| ACTOR_DEF | pipeline/actor_engine.py:125 | read,bash | `BashGrammar()` empty | () | () | ActorDeps; requires_confine |
| ORACLE_DEF | pipeline/oracle_engine.py:68 | `ToolSet()` TOOL-FREE | bash=None | () | () | OracleDeps |
| VERIFY_DEF | author/verify_forward/engine.py:79 | `ToolSet()` TOOL-FREE | bash=None | () | () | VerifierDeps |
| LEAD_AUTHOR_DEF | leads/lead_author_engine.py:122 | read,bash,write | `skills_rm=True` only | () | `build_write_allow(dfn/"skills", suffix=".md")` | LeadAuthorDeps; requires_explicit_tree |
| CORPUS_AUTHOR_DEF | author/curator_engine.py:289 | bash,write,forward_check,lesson_read (**no read**) | `BashGrammar()` | () | () | CuratorDeps; **bindable=False** |

Private bash builders the Grant migration must reproduce:
- `_judge_policy(read_roots, ticket_cli)` judge:115-143 → `[_CAT_PATTERN, _SQL_PATTERN, (_ticket_pattern)]`. **`_CAT_PATTERN = ^cat(?: [^ ]+)*$` (:96) — unanchored, NO flag restriction; containment is wholly the operand gate.** `_SQL_PATTERN = ^defender-sql(?: .*)?$`. `_ticket_pattern` (:100-112) requires `--require-closed` (the security property) and admits only `list-tickets`/`get-ticket`.
- `_actor_policy(scripts, read_confine)` actor:95-113 → `_script_pattern(s)` = `^(?:[^ ]*/)?python3? (?:{rel}|{abs})(?: .*)?$`. `read_confine` REPLACES the defender_dir base.
- `_rm_skills_pattern(skills_dir)` lead_author:61-82 → `^rm (?:{SKILLS_REL}|{abs})(?:/{seg})+$`, no flags, single path.
- **`_corpus_author_policy(corpus_dir)` curator:198-223 — built DIRECTLY, never via `compile_policy`.** `bash_allow = (_rm_pattern, *_viewer_patterns(corpus_dir))`. **`_viewer_patterns` (:166-189) is a SECOND, PRIVATE COPY of the cat/grep/ls grammars** (file operand `+` REQUIRED, dir operand admits a trailing `/`). **No secret denylist on this lane** (:184-186).

## C. CONSUMERS OF WHAT IS REMOVED

**`ls` HAS PROMPT-LEVEL CONSUMERS BEYOND GATHER — the CURATORS:**
- `learning/author/lessons/prompt.md:70-82,152` — literal `ls defender/lessons/`, `grep -l 'source_signature:…' …`, `grep '^description:' …`
- `learning/author/malicious_actor/prompt.md:19` — "List it with `ls defender/lessons-actor/` … (or `grep` a field …)"
- `learning/author/benign_actor/prompt.md:30` — "List it with `ls {lessons_dir}` …"
- `skills/gather/queries/SCHEMA.md:21` — "as a coarse `ls`-time filter"

**`cd` consumers:** ACTOR prompts say "do NOT `cd`" (`pipeline/{benign,malicious}_actor/prompt.md:47,49`). Test `test_read_confine_bash.py::test_cd_prefixed_shim_allowed` (:147) pins a cd-prefixed shim ALLOWED today.

**`jq` consumers:** `skills/gather/SKILL.md:13` forbids jq over payloads. **One positive instruction**: `skills/gather/queries/host-state/container-identity-and-uid.md:28` — literal `cat ${passwd_payload} | jq -r --arg uid "${uid}" '.entries[] | select(...)'` (the `_JQ_KV_FLAG` consumer). **`_overflow_filter_hint` (tools.py:64-97) probes `_lane_admits(policy, "jq '.'")` — the LITERAL string `jq '.'` must still fullmatch a main/gather Grant or the hint silently degrades to the `defender-sql` branch.**

**Deny-reason strings NAMING the programs** (these are prompt surface — a reason naming a dead program teaches a dead command):
- `policies/main.py:16-20` — "read-only viewers (**jq/ls/cat**/…)"
- `policies/gather.py:19-24` — "read-only viewers (**jq/grep/ls/cat**/…)"
- `judge/engine_pydantic.py:56` — "No grep/ls/head/echo in bash"
- `bash.py:70` ADAPTER_STANDALONE_REASON — "filter the persisted payload file with **jq/grep**/Read"

**`raw_reads`/`RAW_MARKER` consumers:** `bash.decide_bash:381` (substring clamp), `files.decide_read:173` (RAW_DENY_REASON) and `files.is_untrusted_read:182`. **e2e `test_replay_skeleton.py:152-179` deny-tail parametrize asserts the RAW deny-REASON SUBSTRING** ("must not read gather_raw") for `raw-read-from-main`. `bash_policy.json` has `raw_reads` keys whose loaders have NO production caller.

**Caches (cross-run bleed hazard — #497/#534):** `reader_patterns_for` / `reader_read_shapes` / `bash_policy._policy()` are all `@lru_cache(maxsize=1)`. `resolve_roots` is deliberately UNCACHED.

## D. EXECUTION CONTEXTS

`run.py` (**os.execv re-exec into .venv python at :30**), `runtime/driver.py` (`run_investigation`), `runtime/tools.py` (`_tool_bash` :260-311 → `decide_bash` :263 → `ModelRetry(reason)` :268; `GatherDeps` isinstance narrow routes `decision.adapter_argv`→`_capture_adapter`, `decision.sql_pipe`→`_capture_adapter_sql` :279-296), the 6 learning engines, `learning/loop.py` (**also os.execv re-execs :27**), `defender/evals/*` (temp trees), `hooks/block_main_loop_raw_access.py:112`.
**PATHS relocation (#562):** `_paths.py:87` `PATHS = DefenderPaths(REPO_ROOT)` computed at import; both re-execs recompute it in the new interpreter. `bind`/`compile_policy_for` thread `defender_dir` explicitly (default `PATHS.defender_dir`) so a lead-author worktree overrides it.

## E. REAL TOOL SEMANTICS (verified: coreutils 9.7 = the runtime image's; grep facts from gnu_flags.py + GNU docs — the DEV BOX grep is ugrep, NOT GNU grep)

**`cat` complete short-flag set: `-A -b -e -E -n -s -t -T -u -v`. NONE consumes an argument.** = `CAT_BOOL="AbeEnstTuv"`. No long option takes an arg.

Flags that CONSUME an argument (a stdin-only grammar must still exclude these):
| prog | arg-consuming short | file-OPENING |
|---|---|---|
| grep | `-e PAT`, `-f FILE`, `-m N`, `-A/-B/-C N`, `-d`, `-D` | `-f`, `--file=`, `--exclude-from=`; `-e` promotes a positional to a FILE; `-r/-R` walk the CWD with NO operand |
| head | `-c N`, `-n N` | none |
| tail | `-c N`, `-n N`, `-s S` | none; `-f` never returns (wedges the stage) |
| wc | **NONE** short | **`--files0-from=F` OPENS A FILE** |
| jq | `-f/--from-file F`, `-L DIR`, `--arg N V`, `--argjson N V`, `--slurpfile N F`, `--rawfile N F`, `--indent N`; `--args`/`--jsonargs` consume ALL remaining | `-f`, `--from-file`, `--slurpfile`, `--rawfile`, `-L`, `--argfile` |
| ls | `-I PAT`, `-w COLS`, `-T COLS` | (being deleted) |

**`gnu_flags.bundle()` emits a single-dash bundle `-[letters]+` — NO long option (`--…`) is admitted by any reader-lane grammar.** That is what excludes `wc --files0-from=`, `jq --rawfile`, `grep --file=`.

## F. THE TEST HARNESS

**Gate-test idiom** (`tests/test_read_confine_bash.py` — the primary #535 spec, ~490 lines). Mirror this exactly:
```python
from defender.runtime.agent_definition import compile_policy_for
main   = compile_policy_for(MAIN_DEF,   run_dir=run, defender_dir=dfn)   # :57
gather = compile_policy_for(GATHER_DEF, run_dir=run, defender_dir=dfn)   # :58
d = permission.decide_bash(cmd, policy=pol, run_dir=run, defender_dir=dfn)  # :64
```
`compile_policy_for` (not `bind(...).policy`) — avoids minting a discarded salt+deps. Judge/actor/lead-author: `bind(JUDGE_DEF, run, scope=RunScope(add_dirs=(cmp,), ticket_cli=("python3", tcli)))`, `bind(ACTOR_DEF, run, scope=RunScope(scripts=…, read_confine=…))`, `bind(LEAD_AUTHOR_DEF, run, defender_dir=wtd)`.
**`decide_bash` NEVER STATS OPERANDS** (test_read_confine_bash.py:43) — fixture files need only exist where a test asserts a read. **(NOTE: the new design's `resolve()` DOES touch the filesystem for symlinks — this is a change.)**

Existing tests that will move/break (test_read_confine_bash.py): `test_tail_wc_grep_over_investigation_allowed` (:121), `test_cd_prefixed_shim_allowed` (:147), `test_grep_dash_f_patternfile_escapes` (:209), `test_grep_dash_e_promotes_positional_to_file` (:218), `test_grep_recursive_denied` (:225/:238), `test_tail_head_arg_consuming_flag_stays_anchored` (:254), `test_wc_files0_from_escapes` (:288), `test_jq_*` (:295-324), `test_stdin_consuming_viewers_in_pipe_allowed` (:345), `test_stdin_viewer_second_stage_still_anchors_files` (:362), read↔bash parity (:374-448), `test_empty_denylist_does_not_brick_reader_lane` (:466), `test_raw_clamp_main_denied_gather_allowed` (:484).
Also: `test_bind_sole_seam_551.py` (`test_d5_reader_patterns_for_kept` :704 asserts `callable(reader_patterns_for)`), `test_cat_operand_gate_differential.py`, `test_agent_definition.py`, `test_bash_policy.py`, `test_curator_glm_policy.py`, `test_bash_exec.py`.

**e2e** (`tests/e2e/_replay_harness.py`) — `Turn(tool_calls=[("bash", {"command": "…"})])`; drives the REAL `driver.run_investigation`; models injected via the `make_model` DI seam. Deny-tail asserts `probe.calls >= 2` and `reason_substr in probe.seen[-1]`.

## G. CONFIG KNOBS

`_BASH_TIMEOUT_S = 120` (tools.py:45, not env-overridable). `bash_policy.json` — `read_deny.substrings = [".env","credentials","ground_truth","ground-truth","cases.json"]`, `read_deny.dirs = [".ssh"]` (LIVE, feed `files._denylisted` + `_common._deny_lookahead`); the `adapters`/`adapter_sql_pipe`/`raw_reads` keys have NO production caller. `DEFENDER_RUNS_BASE` (default `/tmp/defender-runs/`). `_common._deny_lookahead` :44-68 — **an EMPTY denylist axis contributes NO lookahead** (an empty alternation would brick the whole reader lane; pinned by `test_empty_denylist_does_not_brick_reader_lane`).
