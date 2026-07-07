"""Shared regex builders for the runtime-agent policy files (main/gather).

The mechanism (compile a per-agent, PER-RUN anchored allowlist) is shared; the
*policy* (which capability bits, which deny reason) stays per-agent.

Since #535 the main/gather reader lane is **anchored**: every file operand a
viewer opens must be a run-dir path or a tight corpus `.md` — closing the bypass
where the bash lane could `cat /etc/passwd` while the `read_file` tool was already
confined (`files.decide_read`). The anchoring is TEXTUAL (a pure regex over the
tokenized argv, matched per stage by `bash._stage_shape_ok`): the bash lane does
no `resolve()`, so a `..` segment is rejected literally and the roots are baked in
from the run's `run_dir`/`defender_dir` (`policy_for` is per-run, exactly like the
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
from pathlib import Path

from defender.hooks._cmd_segments import NON_ADAPTER_SHIMS
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
      - a denied DIR (`.ssh`) counts as any path COMPONENT (`d in rp.parts`)."""
    subs = "|".join(re.escape(s) for s in bash_policy.read_deny_substrings())
    dirs = "|".join(re.escape(d) for d in bash_policy.read_deny_dirs())
    basename_sub = rf"(?![^ ]*(?:{subs})[^/ ]*(?: |$))"
    dir_component = rf"(?![^ ]*/(?:{dirs})(?=/| |$))"
    return basename_sub + dir_component


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


def _reader_program_patterns(run: str, dfn: str) -> list[str]:
    """The anchored per-program stage grammars (raw regex strings, `fullmatch`ed by
    `bash._stage_shape_ok` against the space-joined tokens)."""
    f = _file_operand(run, dfn)
    d = _dir_operand(run, dfn)
    pat = r"[^ ]+"  # a free-text grep search pattern / a jq filter program (one token)
    return [
        # single file-reader + the read/format viewers: PROG (flag)* FILE+
        rf"cat(?: {_VIEW_FLAG})*(?: {f})+",
        rf"wc(?: {_VIEW_FLAG})*(?: {f})+",
        rf"tail(?: (?:{_NUM_FLAG}|[0-9]+))*(?: {f})+",
        rf"head(?: (?:{_NUM_FLAG}|[0-9]+))*(?: {f})+",
        # grep: safe-flags, one free-text PATTERN (may look like a path), anchored FILE+
        rf"grep(?: {_GREP_FLAG})*(?: {pat})(?: {f})+",
        # ls/cd: anchored DIR operand (recon confined to the read roots)
        rf"ls(?: {_VIEW_FLAG})*(?: {d})+",
        rf"cd(?: {d})?",
        # jq: stdin-compute-only — safe boolean flags + exactly one filter, NO file slot
        rf"jq(?: {_JQ_FLAG})*(?: {pat})",
    ]


def _shim_names() -> list[str]:
    """The program-only allowlist: the non-adapter `defender-*` shims (corpus/query
    tooling + the sanctioned stdin `defender-sql`) plus the argument-inert viewers
    (`echo`/`true`) that open no file. Each is allowed with any trailing args — the
    argv is de-quoted + expansion-free and `shell=False` keeps it inert; a
    `$(...)`/backtick/`VAR=` stage is still rejected by `bash._stage_unsafe`. Data-source
    adapters are NOT here (they route structurally, `bash._decide_adapter`)."""
    argument_inert_viewers = {"echo", "true"}
    return sorted(set(NON_ADAPTER_SHIMS) | argument_inert_viewers)


def reader_patterns(run_dir: Path, defender_dir: Path) -> tuple[re.Pattern[str], ...]:
    """The main/gather bash reader allowlist, ANCHORED to `run_dir` + the defender
    corpus (#535). Every viewer's file/dir operand must resolve — textually, no
    `resolve()` — under those roots; jq is stdin-compute-only; the program-only shims
    open no model-supplied path. Baked into `AgentPolicy.bash_allow` per run by
    `policy_for`, so the reader lane (`bash._decide_readers`) stays a uniform
    per-stage `bash_allow` match with no role branch."""
    run, dfn = str(run_dir), str(defender_dir)
    programs = _reader_program_patterns(run, dfn)
    shims = [rf"{re.escape(n)}(?: .*)?" for n in _shim_names()]
    return tuple(re.compile(rf"^{p}$") for p in (*programs, *shims))
