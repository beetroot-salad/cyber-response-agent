"""Shared regex builders for the runtime-agent policy files (main/gather).

The mechanism (compile a per-agent, PER-RUN anchored allowlist) is shared; the
*policy* (which capability bits, which deny reason) stays per-agent.

Since #535 the main/gather reader lane is **anchored**: every file operand a
viewer opens must be a run-dir path or a tight corpus `.md` — closing the bypass
where the bash lane could `cat /etc/passwd` while the `read_file` tool was already
confined (`files.decide_read`). The anchoring is TEXTUAL (a pure regex over the
tokenized argv, matched per stage by `bash._stage_shape_ok`): the bash lane does
no `resolve()`, so a `..` segment is rejected literally and the roots are baked in
from the run's `run_dir`/`defender_dir` (`compile_policy` is per-run, exactly like the
judge's policy). Operand *path*-containment is the pattern's job here; the shared
security invariants (the secret/ground-truth denylist and the `gather_raw` raw
clamp) still apply globally in `bash.decide_bash` regardless of the allowlist.

Design (see #535): jq is stdin-compute-only (NO file slot); grep keeps a free-text
pattern but anchors its trailing file operand; cat is the single file-reader; the
corpus is tight `.md` under lessons/skills/examples; viewer flags are flag-aware
(a file-opening flag like `wc --files0-from` / `grep -f` / `jq --rawfile` fails the
grammar, so it can't smuggle an out-of-root read past a clean trailing operand)."""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

from defender.runtime import bash_policy

# The corpus subdirs whose `.md` files a runtime agent may read on the bash lane —
# lessons (pitfalls), skills (per-system references + gather query templates), and
# examples. These live directly under `defender_dir` (the DefenderPaths layout); the
# names are the stable corpus offsets, the anchoring root is derived (not literal).
_CORPUS_SUBDIRS = ("lessons", "skills", "examples")

# One path segment that is not a `..` traversal: `..` as a WHOLE segment (followed by
# `/`, a token-boundary space, or end-of-token) is rejected textually, since the bash
# lane never resolve()s. A real path operand carries no embedded spaces, so `[^/ ]+`
# (one segment, no `/` or space) matches exactly one directory/file name.
_SEG = r"(?!\.\.(?:/| |$))[^/ ]+"


def _deny_lookahead() -> str:
    """Two negative lookaheads rejecting a file operand that TEXTUALLY carries a denied
    secret/ground-truth substring or a denied dir component — the bash-lane parity with
    `files._denylisted`, applied to the anchored operand only (never the free-text grep
    pattern). `[^ ]*` scopes each scan to this one token (a real space is a true token
    boundary). Matches `_denylisted`'s two axes exactly:

      - a denied SUBSTRING (`.env`/`credentials`/`ground_truth`/…) counts only in the
        BASENAME (`s in rp.name`): `<sub>` then non-`/` chars up to the token boundary —
        so a parent dir that merely CONTAINS the text (a pytest tmp named
        `…ground_truth…/`) does not over-reject a `lessons/ok.md` under it;
      - a denied DIR (`.ssh`) counts as any path COMPONENT (`d in rp.parts`).

    An EMPTY axis contributes NO lookahead (not an empty `(?:)` alternation, which
    would match at every position and flip the negative lookahead to reject every
    operand — silently bricking the whole reader lane). Empty denylist ⇒ nothing
    denied here, exactly like `files._denylisted` returning False."""
    subs = [re.escape(s) for s in bash_policy.read_deny_substrings()]
    dirs = [re.escape(d) for d in bash_policy.read_deny_dirs()]
    lookahead = ""
    if subs:
        lookahead += rf"(?![^ ]*(?:{'|'.join(subs)})[^/ ]*(?: |$))"
    if dirs:
        lookahead += rf"(?![^ ]*/(?:{'|'.join(dirs)})(?=/| |$))"
    return lookahead


def _under(root: str) -> str:
    """A path token strictly UNDER `root` (>=1 non-`..` segment). `re.escape(root)`
    plus a `/`-boundary means a sibling sharing the prefix (`{root}-evil/…`) can't
    match — the anchor is a path boundary, not a string prefix."""
    return re.escape(root) + r"(?:/" + _SEG + r")+"


def _at_or_under(root: str) -> str:
    """`root` itself OR a path under it — for `ls`/`cd` dir operands (`cd {defender_dir}`,
    `ls {run_dir}/gather_raw`)."""
    return re.escape(root) + r"(?:/" + _SEG + r")*"


def _corpus_md(defender_dir: str) -> str:
    """A tight corpus operand: a `.md` file under `{defender_dir}/(lessons|skills|
    examples)/…`. Nested (`skills/gather/queries/<sys>/<id>.md`) but every segment is
    non-`..` and the basename ends `.md` — a grammar too tight to spell a traversal or
    a non-`.md` secret."""
    subdirs = "|".join(_CORPUS_SUBDIRS)
    return (
        re.escape(defender_dir)
        + r"/(?:" + subdirs + r")(?:/" + _SEG + r")*/(?!\.\.)[^/ ]*\.md"
    )


def _file_operand(run: str, dfn: str) -> str:
    """A file a viewer may OPEN: a run-dir path (the agent's own scratch) or a tight
    corpus `.md`, minus the secret/ground-truth denylist."""
    return _deny_lookahead() + r"(?:" + _under(run) + r"|" + _corpus_md(dfn) + r")"


def _dir_operand(run: str, dfn: str) -> str:
    """A dir `ls`/`cd` may name: the run dir or the defender corpus, at-or-under
    either root (minus the denylist)."""
    return _deny_lookahead() + r"(?:" + _at_or_under(run) + r"|" + _at_or_under(dfn) + r")"


# Per-program safe flag classes (single-dash bundles). A flag that OPENS a file or
# recurses is deliberately EXCLUDED so it fails the grammar (fail closed) rather than
# smuggling an out-of-root read: grep's `-f`/`-e`/`-r`/`-R`, `wc --files0-from`
# (double-dash → not a short bundle), jq's `-f`/`-L`. Double-dash long options are not
# admitted anywhere, so `--files0-from=…`/`--rawfile` fail too.
_GREP_FLAG = r"-[nicovwxHhsEFabz]+"    # safe grep short flags (NO f/e/r/R/L/l/d)
_JQ_FLAG = r"-[rjcnesRaSCM]+"          # safe jq boolean short flags (NO f/L file-openers)
_VIEW_FLAG = r"-[A-Za-z]+"             # cat/wc/ls: any short flag (none open a 2nd file)
_NUM_FLAG = r"-[A-Za-z0-9]+"           # tail/head: `-5`/`-1`/`-n`/`-c`

# jq's file-FREE key/value flags: `--arg NAME VALUE` / `--argjson NAME VALUE` bind a
# shell var into the filter as a STRING/JSON literal — they open NO file (unlike the
# denied `--rawfile`/`--slurpfile`/`--argfile`/`-f`/`-L`), so the VALUE is inert even
# when it looks like a path. Two operand tokens, neither anchored (neither is read).
# This is the idiomatic safe way to pass a bound `${uid}`/`${host}` into a jq filter,
# which the gather query templates use (skills/gather/queries/host-state/…).
_JQ_KV_FLAG = r"(?:--arg|--argjson) [^ ]+ [^ ]+"


# The reader viewer program set + its canonical emit order. `compile_policy` builds
# `bash_allow` from the DECLARED subset of these (a `BashGrammar.viewers` naming only
# `("cat",)` compiles JUST the cat grammar — #545 makes the viewer CONTENTS load-bearing,
# not merely their non-emptiness), and iterates this fixed order so the emitted tuple is
# order-stable regardless of the declaring def's tuple order (the reader lane is a per-stage
# ordered-tuple `bash_allow` match, so a stable emit order keeps it deterministic per run).
# INVARIANT (load-bearing — see #547, #540): every program here is a READ-ONLY viewer,
# and every shim in `NON_ADAPTER_SHIMS` opens no writable path — so NOTHING on the bash
# surface can create a symlink/hardlink (the write lane is `write_text`, regular files
# only). That is why the reap-time run_dir link scrub (#547) is deferred to the #540
# isolate: with no sanctioned writer there is no live way to plant a link a trusted
# host-side consumer (visualizer / learning loop) would follow out of `run_dir`. Admit a
# program that writes bytes to a chosen path, unpacks a tree (`tar -x`, `cp`), or is a
# brokered subprocess, and you break this invariant — land the #547 scrub in that change.
_VIEWER_ORDER = ("cat", "wc", "tail", "head", "grep", "ls", "cd", "jq")

# The full main/gather viewer set — the reader defs (MAIN_DEF / GATHER_DEF) declare exactly
# this set, so `compile_policy` compiles their full reader lane via `reader_patterns_for`.
READER_VIEWERS = _VIEWER_ORDER


def _viewer_program_patterns(run: str, dfn: str) -> dict[str, str]:
    """The anchored per-program stage grammars (raw regex strings, `fullmatch`ed by
    `bash._stage_shape_ok` against the space-joined tokens), keyed by program name so a
    grammar can compile just the subset a `BashGrammar` declares."""
    f = _file_operand(run, dfn)
    d = _dir_operand(run, dfn)
    pat = r"[^ ]+"  # a free-text grep search pattern / a jq filter program (one token)
    return {
        # single file-reader + the read/format viewers: PROG (flag)* FILE* — the file
        # operands are OPTIONAL (`*`, not `+`): a viewer reading STDIN in a downstream
        # pipe stage (`… | grep foo`, `… | wc -l`, `… | head -5`) names no file, so it
        # must still match. Any file operand that IS present is anchored; an out-of-root
        # operand still fails `fullmatch` (it matches neither a flag nor `{f}`), so the
        # `*` re-admits the stdin shape without widening file access.
        "cat": rf"cat(?: {_VIEW_FLAG})*(?: {f})*",
        "wc": rf"wc(?: {_VIEW_FLAG})*(?: {f})*",
        "tail": rf"tail(?: (?:{_NUM_FLAG}|[0-9]+))*(?: {f})*",
        "head": rf"head(?: (?:{_NUM_FLAG}|[0-9]+))*(?: {f})*",
        # grep: safe-flags, one free-text PATTERN (may look like a path), anchored FILE*
        "grep": rf"grep(?: {_GREP_FLAG})*(?: {pat})(?: {f})*",
        # ls/cd: anchored DIR operand (recon confined to the read roots). ls REQUIRES a
        # dir operand (`+`): a bare `ls` lists cwd (= repo root, out-of-root recon).
        "ls": rf"ls(?: {_VIEW_FLAG})*(?: {d})+",
        "cd": rf"cd(?: {d})?",
        # jq: stdin-compute-only — safe boolean flags + file-free `--arg`/`--argjson`
        # key/value flags + exactly one filter, NO file slot.
        "jq": rf"jq(?: (?:{_JQ_FLAG}|{_JQ_KV_FLAG}))*(?: {pat})",
    }


def _shim_names(shims: frozenset[str]) -> list[str]:
    """The program-only allowlist for the DECLARED shims plus the argument-inert viewers
    (`echo`/`true`) that open no file. Each is allowed with any trailing args — the argv
    is de-quoted + expansion-free and `shell=False` keeps it inert; a `$(...)`/backtick/
    `VAR=` stage is still rejected by `bash._stage_unsafe`. `echo`/`true` are always
    admitted (inert regardless of the declared shim set). Data-source adapters are NOT
    here (they route structurally, `bash._decide_adapter`)."""
    argument_inert_viewers = {"echo", "true"}
    return sorted(shims | argument_inert_viewers)


@lru_cache(maxsize=1)
def reader_patterns_for(
    run_dir: Path, defender_dir: Path, viewers: frozenset[str], shims: frozenset[str],
) -> tuple[re.Pattern[str], ...]:
    """The main/gather bash reader allowlist for a DECLARED viewer/shim set, ANCHORED to
    `run_dir` + the defender corpus (#535). Only the viewers in `viewers` (and the shims in
    `shims`, plus the inert `echo`/`true`) compile a grammar — so a `BashGrammar` naming a
    tighter viewer set gets a tighter lane (#545 makes the declared CONTENTS load-bearing).
    Viewers emit in the canonical `_VIEWER_ORDER`, shims sorted, so the tuple is order-stable
    for the field-for-field parity checks. Every viewer's file/dir operand must resolve —
    textually, no `resolve()` — under the roots; jq is stdin-compute-only; the program-only
    shims open no model-supplied path.

    Memoized on `(run_dir, defender_dir, viewers, shims)`: the compiled tuple is a pure
    function of the roots + declared sets + the process-static denylist (`bash_policy._policy`
    is itself cached), and `bind(GATHER_DEF, …)` is called once per gather DISPATCH (many per
    run) — so without the cache each dispatch recompiles the whole ~14-pattern allowlist for a
    per-run-constant value. `maxsize=1`, not unbounded: within a run main + every gather
    dispatch share ONE `(run_dir, defender_dir, viewers, shims)` key (both reader defs declare
    the full set), so a single slot serves every hit; a new run evicts the prior entry rather
    than retaining a ~14-`Pattern` entry per run forever (the latent leak an unbounded cache
    would grow in the e2e replay suite / eval harness temp trees). Mirrors the sibling
    `bash_policy._policy`'s `@lru_cache(maxsize=1)`."""
    run, dfn = str(run_dir), str(defender_dir)
    grammars = _viewer_program_patterns(run, dfn)
    programs = [grammars[name] for name in _VIEWER_ORDER if name in viewers]
    shim_pats = [rf"{re.escape(n)}(?: .*)?" for n in _shim_names(shims)]
    return tuple(re.compile(rf"^{p}$") for p in (*programs, *shim_pats))


@lru_cache(maxsize=1)
def reader_read_shapes(run_dir: Path, defender_dir: Path) -> tuple[re.Pattern[str], ...]:
    """The read-tool FILENAME filter for a main/gather reader agent — the read-tool twin of
    the bash `cat` lane's file-operand grammar (`_file_operand`). `decide_read` `fullmatch`es
    a RESOLVED read path against this, so the read tool admits exactly the filename set `cat`
    does (#545 read↔bash parity): a run-dir path OR a tight corpus `.md`, minus the secret/
    ground-truth denylist. ONE grammar source shared with `reader_patterns_for`'s cat operand
    (`_file_operand`) — no second, drifting filename grammar. Threaded as a shape-builder on the
    reader `AgentDefinition`s' `read_shapes`, compiled per-run by `compile_policy`.

    The grammar anchors on the RESOLVED roots. `decide_read` matches `str(path.resolve())`
    (canonicalized — `..` and symlinks collapsed), so a pattern built from an UNRESOLVED
    `run_dir` (a symlinked `$DEFENDER_RUNS_BASE`, macOS `/tmp` → `/private/tmp`) would never
    match the resolved read path — denying the agent its own run-dir files while the textual
    bash `cat` lane still admits them (a parity + functional break). Resolving here matches
    the canonicalization `decide_read` already applies to both the path and its read roots
    (`files._resolved_read_roots`); the bash `cat` lane stays UNRESOLVED on purpose (it
    matches the operand the model literally typed, so it must not canonicalize). Memoized
    (`maxsize=1`) like the sibling `reader_patterns_for`: main + every gather dispatch share
    one `(run_dir, defender_dir)` key per run, so the resolve()/compile happens once."""
    return (
        re.compile(rf"^{_file_operand(str(run_dir.resolve()), str(defender_dir.resolve()))}$"),
    )
