"""#535 — the gather+main bash reader lane confines file operands to {run_dir, corpus}.

Spec (write-tests) for the anchored-read migration: gather/main move from a
program-only bash allowlist (`^cat(?: .*)?$`, ANY operand) to a **per-run,
full-line regex allowlist whose file operands are ANCHORED** to the run dir +
corpus — so the bash lane confines reads the SAME way `decide_read` (the read_file
tool) already does. Closes a demonstrated bypass: pre-#535
`decide_bash("cat /etc/passwd", policy=compile_policy_for(GATHER_DEF, …)).allow` was True.

Entry points under test (the per-run contract this spec pins):
  - `compile_policy_for(<DEF>, run_dir, *, defender_dir)` — the policy-only half of `bind`
    (#551); RAISES on a missing run_dir / degenerate root (safe-by-construction: no
    unconfined fallback). The MAIN/GATHER reader defs anchor their lane per-run off these
    roots.
  - `decide_bash(command, *, policy, run_dir, defender_dir) -> BashDecision`
    (.allow / .reason / .adapter_argv / .sql_pipe).

Resolved forks (see scratchpad 535-resolved.md): jq = stdin-compute-only, NO file
slot; adapter|jq denied; corpus = tight `.md` under lessons/skills/examples;
grep/wc/ls flag-aware (deny file-opening flags, gate ls); relative operands denied;
parity with decide_read (out-of-root + denylist + raw-clamp); ln -s denied
(pre-existing symlink = documented residual, NOT asserted).

The gate does not stat operands (only `decide_read` resolves), so the anchored
roots here are real tmp dirs and commands interpolate their ABSOLUTE paths.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

from defender.runtime import permission  # noqa: E402
from defender.runtime.agent_definition import compile_policy_for  # noqa: E402
from defender.runtime.driver import GATHER_DEF, MAIN_DEF  # noqa: E402


# --------------------------------------------------------------------------- #
# Fixtures: a per-run run dir + corpus, and the two per-run policies built off  #
# them. decide_bash never stats operands, so these need only exist for the      #
# decide_read parity assertions (which do resolve()).                           #
# --------------------------------------------------------------------------- #
@pytest.fixture
def env(tmp_path):
    run = tmp_path / "run"
    (run / "gather_raw" / "l-001").mkdir(parents=True)
    (run / "gather_summaries").mkdir()
    dfn = tmp_path / "defender"
    (dfn / "lessons").mkdir(parents=True)
    (dfn / "skills" / "elastic").mkdir(parents=True)
    (dfn / "skills" / "gather" / "queries" / "elastic").mkdir(parents=True)
    (dfn / "examples").mkdir()
    (dfn / "fixtures" / "held-out" / "m01").mkdir(parents=True)
    main = compile_policy_for(MAIN_DEF, run_dir=run, defender_dir=dfn)
    gather = compile_policy_for(GATHER_DEF, run_dir=run, defender_dir=dfn)
    return SimpleNamespace(run=run, dfn=dfn, main=main, gather=gather)


def _bash(env, cmd, which="gather"):
    pol = env.gather if which == "gather" else env.main
    return permission.decide_bash(cmd, policy=pol, run_dir=env.run, defender_dir=env.dfn)


def _read(env, path, which="gather"):
    pol = env.gather if which == "gather" else env.main
    return permission.decide_read(Path(path), run_dir=env.run, defender_dir=env.dfn, policy=pol)


# ===========================================================================  #
# A. Safe-by-construction: the compile seam cannot build an unconfined policy    #
# ===========================================================================  #

def test_compile_policy_for_requires_run_dir():
    """compile_policy_for(GATHER_DEF) with NO run_dir RAISES → the confined reader policy can't
    be built in an unconfined state (run_dir is a required positional, no silent fallback)."""
    # rejected: return a permissive default policy (re-opens the cat /etc/passwd bypass)
    with pytest.raises((TypeError, ValueError)):
        compile_policy_for(GATHER_DEF)


def test_compile_policy_for_rejects_degenerate_roots(tmp_path):
    """An empty-string / '/' root — run_dir OR an explicit defender_dir — must RAISE, not anchor
    the reader lane to the CWD / filesystem root (which would allow reading anything). The shared
    `require_anchor_root` guard rejects both.

    (Unlike the retired `policy_for`, `compile_policy_for`'s `defender_dir` legitimately DEFAULTS
    to the PATHS checkout when omitted — a real confined tree, not unconfined — so an OMITTED
    defender_dir is allowed; only a degenerate EXPLICIT root is rejected.)"""
    # rejected: accept '' or '/' and produce a root-anchored (=everything) policy
    for bad in ("", "/"):
        with pytest.raises((TypeError, ValueError)):
            compile_policy_for(GATHER_DEF, run_dir=Path(bad), defender_dir=tmp_path)
        with pytest.raises((TypeError, ValueError)):
            compile_policy_for(MAIN_DEF, run_dir=tmp_path, defender_dir=Path(bad))


# ===========================================================================  #
# B. In-root reads ALLOW (positive controls — the reads real runs actually make) #
# ===========================================================================  #

def test_cat_run_investigation_allowed(env):
    """cat {RUN}/investigation.md → ALLOW: the agent's own case log, absolute, under the run dir."""
    assert _bash(env, f"cat {env.run}/investigation.md", "main").allow
    assert _bash(env, f"cat {env.run}/investigation.md", "gather").allow


def test_cat_run_gather_summary_allowed(env):
    """cat {RUN}/gather_summaries/l-001.md → ALLOW: the per-lead summary (built inline at
    tools_gather.py, NOT a RunPaths prop — the anchoring must still cover it)."""
    assert _bash(env, f"cat {env.run}/gather_summaries/l-001.md", "main").allow


def test_cat_run_executed_queries_allowed(env):
    """cat {RUN}/executed_queries.jsonl → ALLOW: a run-dir artifact (RunPaths.executed_queries)."""
    assert _bash(env, f"cat {env.run}/executed_queries.jsonl", "main").allow


def test_tail_wc_grep_over_investigation_allowed(env):
    """tail/wc/grep over {RUN}/investigation.md → ALLOW: the real read/format shapes from run traces."""
    for cmd in (f"tail -5 {env.run}/investigation.md",
                f"wc -l {env.run}/investigation.md",
                f'grep -n "T resolutions" {env.run}/investigation.md'):
        assert _bash(env, cmd, "main").allow, cmd


def test_cat_corpus_lesson_allowed(env):
    """cat {DFN}/lessons/<slug>.md → ALLOW: a lessons-corpus read (absolute, .md under lessons/)."""
    assert _bash(env, f"cat {env.dfn}/lessons/auth-log-scope.md", "main").allow


def test_cat_multi_lesson_allowed(env):
    """cat {DFN}/lessons/a.md {DFN}/lessons/b.md 2>/dev/null → ALLOW: the real multi-file lesson cat
    (multiple anchored operands + benign stderr discard)."""
    cmd = (f"cat {env.dfn}/lessons/a.md {env.dfn}/lessons/b.md 2>/dev/null")
    assert _bash(env, cmd, "main").allow


def test_cat_corpus_skill_and_query_template_allowed(env):
    """cat {DFN}/skills/<sys>/SKILL.md and a query template → ALLOW: enumerated corpus .md shapes."""
    assert _bash(env, f"cat {env.dfn}/skills/elastic/SKILL.md", "gather").allow
    assert _bash(env, f"cat {env.dfn}/skills/gather/queries/elastic/x.md", "gather").allow


def test_cd_prefixed_shim_allowed(env):
    """cd {DFN} && defender-lessons --tags → ALLOW: the real cd-prefixed shim shape from traces."""
    assert _bash(env, f"cd {env.dfn} && defender-lessons --tags", "main").allow


def test_gather_reads_its_own_gather_raw_absolute(env):
    """cat {RUN}/gather_raw/l-001/1.json → ALLOW for gather (raw_reads), absolute + in-shape."""
    assert _bash(env, f"cat {env.run}/gather_raw/l-001/1.json", "gather").allow


# ===========================================================================  #
# C. Out-of-root reads DENY (guarded negatives, each with a positive control)   #
# ===========================================================================  #

def test_cat_etc_passwd_denied_both(env):
    """cat /etc/passwd → DENY (both agents): the demonstrated bypass #535 closes.
    Positive control: cat {RUN}/investigation.md (same program, in-root) is allowed."""
    assert not _bash(env, "cat /etc/passwd", "gather").allow
    assert not _bash(env, "cat /etc/passwd", "main").allow
    assert _bash(env, f"cat {env.run}/investigation.md", "gather").allow  # positive control


def test_grep_out_of_root_denied(env):
    """grep root /etc/passwd → DENY: grep's trailing file operand escapes the roots.
    Positive control: grep root {RUN}/investigation.md (in-root file) is allowed."""
    assert not _bash(env, "grep root /etc/passwd", "gather").allow
    assert _bash(env, f"grep root {env.run}/investigation.md", "gather").allow  # positive control


def test_cat_traversal_out_of_prefix_denied(env):
    """cat {RUN}/../outside.txt → DENY: a `..` segment escapes the run dir; the anchored pattern
    must reject `..` TEXTUALLY (the bash lane does no resolve()).
    Positive control: cat {RUN}/report.md (no traversal) is allowed."""
    # rejected: rely on resolve() to collapse `..` (the bash lane deliberately does not resolve)
    assert not _bash(env, f"cat {env.run}/../outside.txt", "gather").allow
    assert _bash(env, f"cat {env.run}/report.md", "gather").allow  # positive control


def test_cat_in_prefix_traversal_escape_denied(env):
    """cat {RUN}/gather_raw/../../../etc/passwd → DENY: starts with the run-dir prefix (would pass a
    naive startswith) but the `..` segments tunnel out — the textual `..` reject must catch it."""
    assert not _bash(env, f"cat {env.run}/gather_raw/../../../etc/passwd", "gather").allow


def test_second_operand_escape_denied(env):
    """cat {RUN}/investigation.md /etc/passwd → DENY: the FIRST operand is in-root but the SECOND
    escapes — every operand must be anchored, not just the first.
    Positive control: cat {RUN}/investigation.md {RUN}/report.md (both in-root) is allowed."""
    assert not _bash(env, f"cat {env.run}/investigation.md /etc/passwd", "gather").allow
    assert _bash(env, f"cat {env.run}/investigation.md {env.run}/report.md", "gather").allow


def test_corpus_lookalike_sibling_denied(env):
    """cat {DFN}-evil/x.md → DENY: a sibling dir sharing the corpus PREFIX but not under it must
    not match (the anchor is a path-boundary, not a string prefix)."""
    assert not _bash(env, f"cat {env.dfn}-evil/x.md", "gather").allow


# ===========================================================================  #
# D. File-opening FLAGS — the escape that a clean trailing operand hides         #
# ===========================================================================  #

def test_grep_dash_f_patternfile_escapes(env):
    """grep -f /etc/passwd {RUN}/inv.md → DENY: -f opens the out-of-root PATTERN file even though the
    trailing operand is in-root. Positive control: grep -f {DFN}/lessons/pats.md {RUN}/inv.md (in-root
    pattern file) is allowed OR grep with no -f is allowed."""
    # rejected: gate only the trailing operand (misses -f's file)
    assert not _bash(env, f"grep -f /etc/passwd {env.run}/investigation.md", "gather").allow
    assert _bash(env, f"grep root {env.run}/investigation.md", "gather").allow  # positive control


def test_grep_dash_e_promotes_positional_to_file(env):
    """grep -e root /etc/shadow → DENY: -e fills the pattern slot so /etc/shadow becomes a FILE
    operand (not a pattern) and escapes."""
    # rejected: model grep as always pattern+files positionally (ignores -e)
    assert not _bash(env, "grep -e root /etc/shadow", "gather").allow


def test_grep_recursive_denied(env):
    """grep -r secret {RUN}/gather_raw → DENY: -r/-R walks a dir operand (and follows symlinks out of
    root), reading files the trailing-operand anchor can't bound. The dir is IN-ROOT on purpose — a
    naive `grep -r secret /etc` would deny on the out-of-root operand no matter what `_GREP_FLAG`
    does, so it can't see a regression that admits `r`/`R`; anchoring the deny on `-r` itself (in-root
    dir + an out-of-root variant) is what pins that `r`/`R` stays out of the safe-flag class."""
    # rejected: allow -r/-R over an in-root dir (recursive walk / symlink follow escapes the anchor)
    assert not _bash(env, f"grep -r secret {env.run}/gather_raw", "gather").allow
    assert not _bash(env, f"grep -R secret {env.run}/gather_raw", "gather").allow
    assert not _bash(env, "grep -r secret /etc", "gather").allow
    assert _bash(env, f"grep secret {env.run}/investigation.md", "gather").allow  # positive control (no -r)


def test_grep_recursive_single_operand_denied(env):
    """grep -r {RUN}/x.md → DENY. The SINGLE-operand form the two-operand
    `test_grep_recursive_denied` misses: `-r` is (correctly) excluded from `_GREP_FLAG`, but without
    the `(?!-)` guard the free-text PATTERN slot RE-ABSORBS it — the argv matches and runs as
    `grep -r <path>` = `-r` flag + pattern + NO FILE operand, which walks the CWD (the repo root),
    reading every file under it including denylisted ones (#579). With two positional tokens the
    extra token has nowhere to land so it already denied; with ONE it slipped through. Positive
    control: `grep -n secret {RUN}/inv.md` (a real leading-dash-free pattern + anchored file)."""
    # rejected: `pat = r"[^ ]+"` (a leading-dash pattern slot re-absorbs the rejected -r)
    for which in ("main", "gather"):
        assert not _bash(env, f"grep -r {env.run}/investigation.md", which).allow, which
        assert not _bash(env, f"grep -R {env.run}/investigation.md", which).allow, which
        assert not _bash(env, f"grep -rn {env.run}/investigation.md", which).allow, which
        assert _bash(env, f"grep -n secret {env.run}/investigation.md", which).allow, which  # control


def test_tail_head_arg_consuming_flag_stays_anchored(env):
    """tail -n /etc/passwd → DENY. tail/head's `-n`/`-c` DO consume the next token (unlike cat/wc),
    but — unlike `ls -I` (#579) — that is NOT a read leak: the consumed token must still match the
    anchored `{f}` operand slot to pass the grammar, so an out-of-root path denies outright, and an
    in-root path used as a line/byte COUNT merely errors at runtime (no out-of-root read is
    reachable). `-n`/`-c` are therefore ADMITTED, and this pins that the ANCHORING (not the flag
    class) is what protects them, so a future operand-grammar change can't silently reintroduce a
    leak.

    `-f`/`-F` are a separate story and are DENIED: they open no new file, but a follow never
    returns, so `tail -f` wedges the stage until the executor's wall-clock timeout fires — a
    liveness bug, not a confinement one. `-s SECS` is out as an arg-taker. Positive controls: the
    fused-count forms `tail -5` / `head -5` and the separated `tail -n 20` over an in-root file."""
    # rejected: treat tail/head like ls and assume -n/-c can smuggle an out-of-root read
    for which in ("main", "gather"):
        assert not _bash(env, "tail -n /etc/passwd", which).allow, which
        assert not _bash(env, "head -c /etc/shadow", which).allow, which
        # follow never terminates → burns the stage's whole timeout budget
        assert not _bash(env, f"tail -f {env.run}/investigation.md", which).allow, which
        assert not _bash(env, f"tail -F {env.run}/investigation.md", which).allow, which
        assert not _bash(env, f"tail -s 5 {env.run}/investigation.md", which).allow, which
        assert _bash(env, f"tail -5 {env.run}/investigation.md", which).allow, which     # control
        assert _bash(env, f"head -5 {env.run}/investigation.md", which).allow, which     # control
        assert _bash(env, f"tail -n 20 {env.run}/investigation.md", which).allow, which  # control
        assert _bash(env, f"head -c 100 {env.run}/investigation.md", which).allow, which # control


def test_grep_free_text_pattern_not_anchored(env):
    """grep "/home/x/.ssh/authorized_keys" {RUN}/investigation.md → ALLOW: the path-LOOKING token is
    the search PATTERN, not a file; only the trailing operand is anchored (real trace shape)."""
    # rejected: deny because a token looks like an out-of-root path (over-anchors the pattern)
    assert _bash(env, f'grep "/home/x/.ssh/authorized_keys" {env.run}/investigation.md', "main").allow


def test_wc_files0_from_escapes(env):
    """wc --files0-from=/etc/passwd → DENY: --files0-from opens the named file AND every path inside it,
    a two-hop out-of-root read the trailing-operand view misses."""
    # rejected: leave --files0-from ungated
    assert not _bash(env, "wc --files0-from=/etc/passwd", "gather").allow


def test_jq_standalone_file_operand_denied(env):
    """jq '.x' {RUN}/gather_raw/l-001/1.json → DENY: jq is stdin-compute-only, NO file slot — even an
    IN-ROOT positional file is denied (flips the pre-#535 allow). Substitute: cat FILE | jq '.x'."""
    # rejected: allow an in-root positional file (the pre-#535 behavior; then jq needs a file slot)
    assert not _bash(env, f"jq '.x' {env.run}/gather_raw/l-001/1.json", "gather").allow


def test_jq_stdin_rawfile_flag_escapes(env):
    """cat {RUN}/gather_raw/l-001/1.json | jq --rawfile y /etc/passwd '.' → DENY: --rawfile opens
    /etc/passwd EVEN in a stdin pipe stage; the jq pattern must carry no file-flag slot."""
    # rejected: ALLOW (a free `^jq .*$` stdin pattern lets --rawfile through)
    cmd = f"cat {env.run}/gather_raw/l-001/1.json | jq --rawfile y /etc/passwd '.'"
    assert not _bash(env, cmd, "gather").allow


def test_jq_stdin_slurpfile_and_L_escape(env):
    """jq --slurpfile / -L file-opening flags in a stdin stage → DENY (both open out-of-root files/
    module bodies)."""
    assert not _bash(env, f"cat {env.run}/report.md | jq --slurpfile y /etc/shadow '.'", "gather").allow
    assert not _bash(env, f"cat {env.run}/report.md | jq -L /etc '.'", "gather").allow


def test_jq_stdin_compute_only_allowed(env):
    """cat {RUN}/executed_queries.jsonl | jq -r 'select(.lead_id=="l-001")' → ALLOW: the real jq shape
    (stdin formatter over an in-root artifact, no file operand, boolean/value flags only)."""
    cmd = f"""cat {env.run}/executed_queries.jsonl | jq -r 'select(.lead_id=="l-001")'"""
    assert _bash(env, cmd, "gather").allow


def test_jq_stdin_arg_and_argjson_allowed(env):
    """cat {RUN}/… | jq -r --arg uid "0" '<filter>' → ALLOW: `--arg`/`--argjson NAME VALUE` bind a
    shell var into the filter as a STRING/JSON literal and open NO file, so they are safe on the
    stdin-only jq lane. This is the shape the gather query template ships
    (skills/gather/queries/host-state/container-identity-and-uid.md) — the gate must not deny its own
    documented workflow. The VALUE is inert even when it looks like a path (`--arg` never reads it)."""
    # rejected: admit only boolean jq short flags (denies `--arg`, breaking the passwd/uid template)
    tmpl = (f"cat {env.run}/gather_raw/l-001/0.json | "
            "jq -r --arg uid \"0\" '.entries[] | select(split(\":\")[2] == $uid)'")
    assert _bash(env, tmpl, "gather").allow
    assert _bash(env, f"cat {env.run}/report.md | jq --argjson n 5 '.hits[:$n]'", "gather").allow
    # a path-LOOKING --arg VALUE is a bound string, not a file read → still allowed
    assert _bash(env, f"cat {env.run}/report.md | jq --arg p /etc/passwd '.'", "gather").allow
    # but a FILE-opening jq flag stays denied even alongside --arg (no widening of the file lane)
    assert not _bash(env, f"cat {env.run}/report.md | jq --arg u 0 --rawfile y /etc/passwd '.'", "gather").allow


# ===========================================================================  #
# D2. Stdin-consuming viewers in a pipe: a downstream stage names NO file        #
# ===========================================================================  #

def test_stdin_consuming_viewers_in_pipe_allowed(env):
    """`<in-root reader | shim> | grep/wc/head/tail/cat` → ALLOW: a downstream viewer reads STDIN and
    names no file operand, so the anchored file grammar must be OPTIONAL (`{f}*`, not `{f}+`). These
    are common in-root read/filter idioms the pre-#535 `^{name}(?: .*)?$` viewers allowed; only `jq`/
    `defender-sql` survived the migration, silently dropping grep/wc/head/tail/cat stdin forms."""
    # rejected: require >=1 anchored file operand (`{f}+`), denying every piped-into viewer
    for cmd in (f"cat {env.run}/investigation.md | grep -n resolved",
                f"tail -50 {env.run}/investigation.md | grep err",
                f"grep foo {env.run}/investigation.md | head -5",
                f"cat {env.run}/investigation.md | wc -l",
                "defender-lessons --tags | grep auth",
                "defender-lessons --tags | wc -l",
                f"cat {env.run}/investigation.md | tail -5"):
        assert _bash(env, cmd, "gather").allow, cmd
        assert _bash(env, cmd, "main").allow, cmd


def test_stdin_viewer_second_stage_still_anchors_files(env):
    """The `{f}*` relaxation must NOT admit an out-of-root FILE on a downstream stage: a viewer that
    names a file still has it anchored. `… | grep foo /etc/passwd` and `… | cat /etc/passwd` DENY."""
    assert not _bash(env, f"cat {env.run}/investigation.md | grep foo /etc/passwd", "gather").allow
    assert not _bash(env, f"cat {env.run}/investigation.md | cat /etc/passwd", "gather").allow
    assert not _bash(env, f"cat {env.run}/investigation.md | wc -l /etc/passwd", "gather").allow


# ===========================================================================  #
# E. Cross-surface PARITY: bash denies everything decide_read denies            #
# ===========================================================================  #

def test_parity_out_of_root(env):
    """/etc/passwd: decide_read DENIES and decide_bash("cat …") DENIES — the two read surfaces agree.
    Positive control: {RUN}/investigation.md is allowed on BOTH."""
    assert not _read(env, "/etc/passwd", "gather").allow
    assert not _bash(env, "cat /etc/passwd", "gather").allow
    assert _read(env, f"{env.run}/investigation.md", "gather").allow          # positive control
    assert _bash(env, f"cat {env.run}/investigation.md", "gather").allow      # positive control


def test_parity_ground_truth_inside_corpus(env):
    """{DFN}/fixtures/held-out/m01/ground_truth.yaml lives INSIDE defender_dir; decide_read denies it
    (denylist substring) — the bash lane must deny it too. Positive control: a lessons .md is allowed
    on both."""
    gt = f"{env.dfn}/fixtures/held-out/m01/ground_truth.yaml"
    assert not _read(env, gt, "gather").allow
    assert not _bash(env, f"cat {gt}", "gather").allow
    assert not _bash(env, f"grep x {gt}", "gather").allow
    assert _bash(env, f"cat {env.dfn}/lessons/ok.md", "gather").allow  # positive control


def test_parity_captured_env_in_run_dir(env):
    """A captured .env inside the run dir: decide_read denies it (denylist), so the bash lane must too —
    an in-root operand is NOT sufficient; the secret denylist applies on both surfaces."""
    dotenv = f"{env.run}/.env"
    assert not _read(env, dotenv, "gather").allow
    assert not _bash(env, f"cat {dotenv}", "gather").allow


def test_parity_ssh_dir_component(env):
    """A path with an `.ssh` component is denied on both surfaces (dir-component denylist). The path is
    UNDER the run root on purpose — otherwise the corpus/run shape gate denies it first and the
    `.ssh` dir_component lookahead is never exercised; here `{RUN}/.ssh/id_rsa` and `ls {RUN}/.ssh`
    are in-SHAPE (a run-dir path), so ONLY the dir-component denylist can deny them.
    Positive control: `{RUN}/investigation.md` (same root, no `.ssh`) is allowed on both surfaces."""
    p = f"{env.run}/.ssh/id_rsa"
    assert not _read(env, p, "gather").allow
    assert not _bash(env, f"cat {p}", "gather").allow
    assert not _bash(env, f"grep k {p}", "gather").allow
    assert not _bash(env, f"ls {env.run}/.ssh", "gather").allow
    assert not _bash(env, f"cat {env.dfn}/.ssh/id_rsa", "gather").allow  # out-of-shape variant also denies
    assert _bash(env, f"cat {env.run}/investigation.md", "gather").allow  # positive control


def test_parity_corpus_non_listed_denied_on_both_lanes(env):
    """Read↔bash PARITY on a non-listed corpus file (#545/#546, propagated to the compiled reader
    policy by #551): a corpus file NOT under the tight lessons/skills/examples/**.md grammar
    ({DFN}/docs/x.md) is DENIED on BOTH the read tool (the `read_shapes` filename filter
    `compile_policy_for` carries) AND the bash cat lane (the operand grammar). The
    pre-#546 'read broad, bash tight' asymmetry is CLOSED — the two surfaces now agree. Positive
    control: a tight-corpus lessons/**.md is allowed on both."""
    docs = f"{env.dfn}/docs/learning-loop.md"
    assert not _read(env, docs, "gather").allow           # read tool: read_shapes denies non-tight corpus
    assert not _bash(env, f"cat {docs}", "gather").allow  # bash cat lane denies it too — parity
    ok = f"{env.dfn}/lessons/notes.md"
    assert _read(env, ok, "gather").allow                 # positive control (tight corpus .md, read admits)
    assert _bash(env, f"cat {ok}", "gather").allow        # … and the bash cat lane admits it too


def test_corpus_md_named_secret_denied(env):
    """A `.md`-named secret UNDER a corpus subdir — `{DFN}/lessons/credentials.md` — passes the corpus
    `.md` SHAPE gate, so the basename-substring denylist is the ONLY thing that can deny it. Unlike
    the out-of-corpus `ground_truth.yaml`/`.env` parity cases (which the shape gate denies first),
    this exercises `_deny_lookahead`'s basename axis in isolation on BOTH surfaces.
    Positive control: `{DFN}/lessons/notes.md` (same subdir, benign name) is allowed on both."""
    # rejected: drop the basename-substring lookahead (a `credentials.md`/`.env.md` in-corpus leaks)
    for secret in (f"{env.dfn}/lessons/credentials.md",
                   f"{env.dfn}/skills/elastic/ground_truth.md",
                   f"{env.dfn}/lessons/x.env.md"):
        assert not _bash(env, f"cat {secret}", "gather").allow, secret
        assert not _read(env, secret, "gather").allow, secret
    assert _bash(env, f"{'cat'} {env.dfn}/lessons/notes.md", "gather").allow  # positive control


@pytest.mark.parametrize("axis", ["substring", "dir"])
def test_denylist_parity_bash_matches_decide_read(env, axis):
    """For every configured denylist entry, an OTHERWISE-in-shape in-root operand carrying it denies on
    BOTH the bash lane and decide_read (the two surfaces agree). Iterating the live denylist (not a
    hardcoded sample) keeps the regex `_deny_lookahead` and Python `files._denylisted` from drifting:
    add a new substring/dir to bash_policy.json and this pins both surfaces honor it."""
    from defender.runtime import bash_policy
    if axis == "substring":
        for sub in bash_policy.read_deny_substrings():
            p = f"{env.run}/sub/{sub}xyz"          # denied substring inside an in-root basename
            assert not _bash(env, f"cat {p}", "gather").allow, p
            assert not _read(env, p, "gather").allow, p
    else:
        for d in bash_policy.read_deny_dirs():
            p = f"{env.run}/{d}/inner.json"        # denied dir as an in-root path component
            assert not _bash(env, f"cat {p}", "gather").allow, p
            assert not _read(env, p, "gather").allow, p


def test_empty_denylist_does_not_brick_reader_lane(tmp_path, monkeypatch):
    """A regression guard for the empty-denylist footgun: if `read_deny.substrings` (or dirs) is ever
    emptied, `_deny_lookahead` must contribute NO lookahead — an empty `(?:)` alternation would match
    everywhere and flip the negative lookahead to DENY every operand, silently bricking the lane."""
    from defender.runtime.permission.policies import _common
    monkeypatch.setattr(_common.bash_policy, "read_deny_substrings", lambda: ())  # lint-monkeypatch: ok — force the degenerate empty-denylist config
    monkeypatch.setattr(_common.bash_policy, "read_deny_dirs", lambda: ())  # lint-monkeypatch: ok — force the degenerate empty-denylist config
    assert _common._deny_lookahead() == ""     # no clause, not `(?:)` deny-all
    # end-to-end (fresh roots dodge reader_patterns' cache): an in-root read still ALLOWS
    run, dfn = tmp_path / "run", tmp_path / "dfn"
    pol = compile_policy_for(GATHER_DEF, run_dir=run, defender_dir=dfn)
    assert permission.decide_bash(f"cat {run}/x.md", policy=pol, run_dir=run, defender_dir=dfn).allow


# ===========================================================================  #
# F. gather_raw RAW clamp — parity with decide_read's raw clamp                  #
# ===========================================================================  #

def test_raw_clamp_main_denied_gather_allowed(env):
    """cat {RUN}/gather_raw/l-001/1.json: DENY for main (raw_reads=False, consumes the summary),
    ALLOW for gather (raw_reads=True) — bash-lane parity with decide_read's raw clamp."""
    raw = f"cat {env.run}/gather_raw/l-001/1.json"
    d_main = _bash(env, raw, "main")
    assert not d_main.allow
    assert "gather_raw" in (d_main.reason or "")
    assert _bash(env, raw, "gather").allow


def test_raw_clamp_precedes_shape_gate(env):
    """The raw clamp fires for main even on an otherwise in-shape read — it is a security invariant
    that runs before the reader lane, not something the anchored allowlist can rescue."""
    assert not _bash(env, f"cat {env.run}/gather_raw/l-001/1.json", "main").allow


def test_coarse_clamp_over_denies_gather_raw_as_grep_pattern(env):
    """grep gather_raw {RUN}/investigation.md (main) → DENY: the coarse substring clamp over-fires when
    'gather_raw' is a grep PATTERN, not a path. This is the ACCEPTED fail-safe over-deny (SF4) — the
    clamp stays dumb and un-bypassable."""
    # rejected: make the clamp operand-aware (reintroduces a path parse = a new bypass surface)
    assert not _bash(env, f"grep gather_raw {env.run}/investigation.md", "main").allow


def test_gather_summaries_not_tripped_by_raw_clamp(env):
    """cat {RUN}/gather_summaries/l-001.md (main) → ALLOW: 'gather_summaries' does NOT contain the
    'gather_raw' marker, so the summary read is not swept up by the coarse clamp."""
    assert _bash(env, f"cat {env.run}/gather_summaries/l-001.md", "main").allow


def test_recursive_ls_cannot_dodge_the_raw_clamp(env):
    """ls -R {RUN} → DENY. The clamp above is a SUBSTRING test on the command text (`RAW_MARKER in
    cmd`), so it only fires on a command that NAMES `gather_raw` — and recursion is precisely the
    primitive that reaches a subtree WITHOUT naming it: `ls -R {RUN}` walks into `gather_raw/` and
    lists the whole raw tree (lead dirs + payload files) while spelling the marker nowhere. So the
    clamp is complete only if the reader lane has no recursive descent at all; `_LS_FLAG` drops
    `-R` (grep's `-r`/`-R` were already out, and there is no find/tree), which makes "to reach a
    path you must name it, and naming it trips the clamp" a real invariant instead of an accident.
    Denied on BOTH agents — the flag is off the lane, not conditioned on `raw_reads` (gather reads
    raw by NAMING it, which its policy allows). Positive control: non-recursive `ls` still works,
    and gather can still list the raw dir explicitly."""
    # rejected: keep `-R` and special-case recursive ls inside the clamp (a path/flag parse in the
    # security check = the new bypass surface SF4 exists to avoid — see the test above)
    for which in ("main", "gather"):
        assert not _bash(env, f"ls -R {env.run}", which).allow, which
        assert not _bash(env, f"ls -lR {env.run}", which).allow, which   # bundled
        assert _bash(env, f"ls {env.run}", which).allow, which           # control
    assert _bash(env, f"ls {env.run}/gather_raw", "gather").allow        # control: named, allowed
    assert not _bash(env, f"ls {env.run}/gather_raw", "main").allow      # ...and clamped for main


# ===========================================================================  #
# G. Relative-operand convention (consensus): absolute required                 #
# ===========================================================================  #

def test_relative_operand_denied(env):
    """cat gather_raw/l-001/1.json (relative) → DENY: a pure-regex anchor can't resolve a relative
    path against run_dir; the convention is absolute {RUN}/…. Positive control: the absolute form
    is allowed (for gather)."""
    # rejected: resolve the relative path against run_dir in the gate
    assert not _bash(env, "cat gather_raw/l-001/1.json", "gather").allow
    assert _bash(env, f"cat {env.run}/gather_raw/l-001/1.json", "gather").allow


def test_relative_after_cd_still_denied(env):
    """cd {RUN} && cat gather_raw/l-001/1.json → DENY: the gate is cwd-blind (no resolve), so a
    relative read after `cd` still fails to anchor."""
    assert not _bash(env, f"cd {env.run} && cat gather_raw/l-001/1.json", "gather").allow


# ===========================================================================  #
# H. Symlink invariant: creation blocked; pre-existing = documented residual    #
# ===========================================================================  #

def test_ln_symlink_creation_denied(env):
    """ln -s /etc/passwd {RUN}/x → DENY (both): `ln` is in no allowlist, so the agent cannot CREATE a
    symlink that a later in-shape read would follow out-of-root. This is what closes the symlink
    residual the anchored regex cannot (the bash lane does no resolve())."""
    assert not _bash(env, f"ln -s /etc/passwd {env.run}/x", "gather").allow
    assert not _bash(env, f"ln -s /etc/passwd {env.run}/x", "main").allow

# NOTE (documented residual — deliberately NOT asserted): a PRE-EXISTING symlink at an in-shape path
# (e.g. {RUN}/gather_raw/l-001/1.json -> /etc/passwd) is judged by the bash lane on its literal shape
# only (no resolve() on viewer operands), so the bash gate does NOT catch it. It is closed by (a) `ln`
# denied above, (b) run-dir writes being write_text (regular files), (c) the OS sandbox (#540). A test
# asserting `cat {RUN}/<symlink>` DENY would FAIL and would force resolve() on every operand — not this
# design. See #540.


# ===========================================================================  #
# I. Writes stay on write_file/edit_file; bash redirect-writes deny             #
# ===========================================================================  #

def test_bash_redirect_write_denied(env):
    """cat ... >> {RUN}/investigation.md and echo x > {RUN}/f → DENY: the executor fails closed on
    write redirects (`>`/`>>`). Substitute: the write_file/edit_file tool (invlang-validated)."""
    # rejected: allow the redirect (would bypass the invlang write gate)
    assert not _bash(env, f"echo x >> {env.run}/investigation.md", "main").allow
    assert not _bash(env, f"echo x > {env.run}/f.txt", "gather").allow


def test_write_report_still_allowed(env):
    """decide_write({RUN}/report.md) → ALLOW: the sanctioned main-loop write path is unchanged
    (regression). Main declares its run-dir subtree as its write_allow."""
    pol = permission.AgentPolicy(write_allow=(permission.build_write_allow(env.run),))
    assert permission.decide_write(
        env.run / "report.md", "disposition: benign\n", policy=pol,
    ).allow


def test_write_investigation_invalid_invlang_denied(env):
    """decide_write({RUN}/investigation.md, <invalid invlang>) → DENY: the invlang gate is unchanged
    (the run-dir write_allow admits the path, then invlang denies the content)."""
    pol = permission.AgentPolicy(write_allow=(permission.build_write_allow(env.run),))
    d = permission.decide_write(
        env.run / "investigation.md", "```yaml\nfoo: bar\n```\n", policy=pol,
    )
    assert not d.allow


# ===========================================================================  #
# J. Adapter/compute routing preserved (the gather data lane is untouched)       #
# ===========================================================================  #

def test_standalone_adapter_allowed_and_exposed(env):
    """defender-elastic query 'x' → ALLOW for gather, with .adapter_argv exposed for capture."""
    d = _bash(env, "defender-elastic query 'x'", "gather")
    assert d.allow
    assert d.adapter_argv == ["defender-elastic", "query", "x"]


def test_adapter_sql_pipe_allowed_and_split(env):
    """defender-elastic … | defender-sql 'SELECT …' → ALLOW for gather, with .sql_pipe split
    exposed; main never gets the adapter."""
    cmd = "defender-elastic query 'x' | defender-sql 'SELECT user, count(*) c FROM data GROUP BY user'"
    d = _bash(env, cmd, "gather")
    assert d.allow
    assert d.sql_pipe is not None
    adapter_av, sql_av = d.sql_pipe
    assert adapter_av == ["defender-elastic", "query", "x"]
    assert sql_av[0] == "defender-sql"
    assert not _bash(env, cmd, "main").allow


def test_cat_payload_into_defender_sql_allowed(env):
    """cat {RUN}/gather_raw/l-001/1.json | defender-sql 'SELECT …' → ALLOW for gather: an in-root
    payload streamed into the sandboxed aggregator (cat anchored, defender-sql opens no file)."""
    cmd = f"cat {env.run}/gather_raw/l-001/1.json | defender-sql 'SELECT count(*) FROM data'"
    assert _bash(env, cmd, "gather").allow


def test_adapter_jq_pipe_denied(env):
    """defender-elastic … | jq '.x' → DENY: adapter|jq is NOT a sanctioned pipe (only
    adapter|defender-sql is); the host-state template is rewritten standalone→read instead."""
    # rejected: allow adapter | jq structurally (widens the sanctioned adapter-pipe grammar)
    d = _bash(env, "defender-elastic query 'x' | jq '.x'", "gather")
    assert not d.allow


def test_adapter_denied_for_main(env):
    """A data-source adapter is denied for the main loop (it dispatches gather) — unchanged."""
    d = _bash(env, "defender-elastic query 'x'", "main")
    assert not d.allow
    assert "data-source CLIs directly" in (d.reason or "")


# ===========================================================================  #
# K. ls is a bash-lane-only recon surface — gate it to in-root dirs             #
# ===========================================================================  #

def test_ls_out_of_root_dir_denied(env):
    """ls /etc → DENY: `ls DIR` enumerates out-of-root structure (recon). It has no decide_read
    counterpart, so it's a bash-lane-only decision — anchor its dir operand.
    Positive control: ls {RUN}/gather_raw is allowed."""
    # rejected: leave ls operands unanchored (a low-grade out-of-root recon primitive)
    assert not _bash(env, "ls /etc", "gather").allow
    assert _bash(env, f"ls {env.run}/gather_raw", "gather").allow


def test_ls_arg_consuming_flag_denied(env):
    """ls -I {RUN} → DENY: GNU ls's `-I PATTERN`/`-w COLS`/`-T COLS` CONSUME the next token, so a
    catch-all `-[A-Za-z]+` flag class lets `-I` swallow the anchored dir operand — leaving `ls` with
    NO operand, which falls back to listing the CWD (the repo root): a fail-open (#579). The explicit
    `_LS_FLAG` boolean allowlist (I/w/T excluded) closes it. Both agents share the reader lane.

    `_LS_FLAG` is now a load-bearing 37-letter ENUMERATION of GNU coreutils 9.7's boolean ls flags,
    so the ALLOW side is pinned too: without it, dropping a letter (a coreutils bump, a typo) would
    silently deny a legitimate recon shape with the suite still green. The allow list below is the
    regression floor the tightening must not cost us."""
    # rejected: `-[A-Za-z]+` for ls (admits -I/-w/-T, which then consume the operand)
    for which in ("main", "gather"):
        assert not _bash(env, f"ls -I {env.run}", which).allow, which
        assert not _bash(env, f"ls -w {env.run}", which).allow, which
        assert not _bash(env, f"ls -T {env.run}", which).allow, which
        # -I in a boolean bundle still consumes the operand → still denied
        assert not _bash(env, f"ls -laI {env.run}", which).allow, which
        # ...and in its attached-argument spellings (`-I<PATTERN>` / `-w<COLS>`), which is how a
        # short arg-taker is idiomatically written — the letter is excluded, so the bundle fails.
        # (Deliberately NOT a `gather_raw` pattern: that would trip the raw clamp instead, and the
        # assertion would pass for a reason other than the flag grammar it is meant to pin.)
        assert not _bash(env, f"ls -I*.md {env.run}", which).allow, which
        assert not _bash(env, f"ls -w80 {env.run}", which).allow, which
        # positive controls — every boolean-flag shape a real run uses must still ALLOW.
        # `-R` is NOT among them: see `test_recursive_ls_cannot_dodge_the_raw_clamp`.
        for ok in ("ls", "ls -la", "ls -l", "ls -a", "ls -1", "ls -lt", "ls -lh",
                   "ls -lS", "ls -ltr", "ls -F", "ls -d"):
            assert _bash(env, f"{ok} {env.run}", which).allow, f"{which}: {ok}"


# ===========================================================================  #
# L. Degenerate inputs                                                          #
# ===========================================================================  #

def test_empty_command_allowed(env):
    """An empty / whitespace-only command is a no-op → ALLOW (unchanged current behavior; nothing is
    read)."""
    assert _bash(env, "", "gather").allow
    assert _bash(env, "   ", "main").allow


def test_arbitrary_shell_still_denied(env):
    """curl / rm / python3 → DENY for both agents (regression floor — the allowlist is deny-by-default)."""
    for cmd in ("curl http://evil", "rm -rf /tmp/x", "python3 -c 'x'"):
        assert not _bash(env, cmd, "gather").allow, cmd
        assert not _bash(env, cmd, "main").allow, cmd
