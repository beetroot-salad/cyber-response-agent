"""GNU short-flag ARITY facts for the programs the bash reader lanes admit.

A reader lane gates a TOKENIZED argv with a regex shaped `PROG (flag)* (operand)*`, where the
operand slot is ANCHORED to the lane's read roots. That grammar is sound only while the gate and
the program agree on which token is an operand — and a short flag that CONSUMES the next token
breaks the agreement. Three ways it broke (#579):

  - `ls -I {run_dir}` reads to the gate as "flag, anchored dir"; to `ls` it reads as
    "ignore-pattern {run_dir}", leaving NO operand — so ls falls back to listing the CWD.
  - `grep -m 1 {run_dir}/x.md`: `-m` eats the search pattern, the anchored path slides into the
    PATTERN slot, and grep — with no FILE operand — walks the CWD.
  - `grep -e PAT {anything} {anchored}`: `-e` SUPPLIES the pattern, which demotes the gate's
    free-text pattern slot into a FILE operand that grep then opens. An arbitrary read.

So a flag class MUST be a BOOLEAN allowlist, spelled POSITIVELY — the flags that exist and take no
argument — never a catch-all minus the known-bad. Positive fails CLOSED when a future coreutils or
grep grows an arg-consuming flag; an exclusion list fails OPEN.

This module is the ONE home for those letter sets, because two lanes consume them and the sets are
a property of the runtime container's BINARIES, not of any one agent's policy:

  - `runtime/permission/policies/_common.py` — the main/gather reader lane;
  - `learning/author/curator_engine.py`      — the lesson curators' corpus lane.

They were cloned once, and #579 then had to be fixed twice — the second copy was missed. A lane
SUBTRACTS from these facts whatever its own policy disallows (`bundle(..., drop=...)`), so the
facts stay factual and the policy stays in the lane.

Verified against the runtime image's binaries (`python:3.11-slim` → GNU coreutils 9.7, GNU grep
3.11), which is what actually executes — NOT the dev box, whose `grep` is `ugrep` and whose flag
arity therefore proves nothing about the gate."""

from __future__ import annotations

# cat: coreutils gives it NO arg-taking short option at all. That is the whole reason `cat` is the
# judge's operand-gated file-opening program — "which files does this argv open?" is answerable
# without reimplementing an option parser. The SOLE encoding of that set (`permission/bash`'s
# `_CAT_BOOL_BUNDLE` compiles it, and the judge's admitting pattern deliberately does not repeat it).
CAT_BOOL = "AbeEnstTuv"

# wc: no arg-taking short option either (`--files0-from=F` / `--total=WHEN` are long-only).
WC_BOOL = "clLmw"

# ls: every BOOLEAN short flag — the full valid set MINUS its three arg-takers, `-I PATTERN` /
# `-w COLS` / `-T COLS`. (`-F`'s argument is optional AND long-form-only; `-p` takes none.)
LS_BOOL = "aAbBcCdDfFgGhHiklLmnNopqQrRsStuUvxXZ1"
# ...of which exactly one DESCENDS. A lane whose read roots contain a subtree the agent may not
# enumerate has to drop it: recursion reaches that subtree without ever NAMING it, so a lane that
# guards the subtree with a textual path check never sees it coming.
LS_RECURSE = "R"

# grep: the boolean short flags. EXCLUDES every arg-taker — the file-openers `-f FILE` / `-e
# PATTERN`, and the count/action takers `-m NUM` / `-A|-B|-C NUM` / `-d|-D ACTION`.
GREP_BOOL = "nicovwxHhsEFabz"
# boolean, and open no file: they report WHICH files matched instead of printing the matches.
GREP_LIST = "lL"
# boolean, but with no FILE operand `grep -r` walks the CWD. Admissible ONLY on a lane whose file
# operand is REQUIRED (`+`), where a recursive grep always has an anchored root to descend from.
GREP_RECURSE = "rR"

# tail/head: `-q`/`-v`/`-z` are boolean; `-c`/`-n` DO consume a NUM. Admitting those two is safe —
# and is not a violation of the rule above — because the token they consume must still match the
# lane's ANCHORED operand slot to pass the grammar at all: an out-of-root path denies outright, and
# an in-root path misread as a count merely errors. `-f`/`-F` (follow) and `-s SECS` are excluded:
# `-s` is an arg-taker, and `-f` never returns, so it would wedge the stage until the executor's
# wall-clock timeout fires.
TAIL_HEAD_BOOL = "cnqvz"
# tail/head also accept a FUSED count (`tail -5`, `head -50`) — a flag-shaped digit run.
DIGITS = "0123456789"


def bundle(letters: str, *, drop: str = "") -> str:
    """The single-dash short-flag BUNDLE regex over `letters`, minus any letter in `drop` — the
    seam a lane uses to subtract what its own policy disallows. Order-preserving, so the compiled
    pattern is stable and a policy change reads cleanly in a diff. `letters` is a letter/digit run
    by construction, so no character in it is a regex metacharacter inside the class."""
    kept = "".join(c for c in letters if c not in drop)
    return rf"-[{kept}]+"
