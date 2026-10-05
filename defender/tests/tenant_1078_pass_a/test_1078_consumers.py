"""#1078 pass (A) — D4's runs-base CONSUMERS and O7's census: every tool that finds runs through a
runs base gets that base from a tenant, and none falls back to a default base or skips its check
when it has none.

The consumers, each driven through its REAL entry point:

* the judge (`learning/judge`): `grade_episode(runs_base=...)` — REQUIRED keyword (§7 J48,
  human, design correction R-A3) — threads the base into BOTH readers, the world-label
  collision probe (`family._check_world_labels`, whose `except Exception: return` fallback goes,
  C26) and the sibling union (`render.sibling_union`);
* the review replay (`learning/branch/review.verb_context`, `seams.adapter_seam`): the replay
  env's `DEFENDER_RUNS_BASE` is the threaded base (F3);
* `evals/held_out.py`: the positional runs dir, required, and never resolving the data root
  (§7 J50, human), `--help` never resolving a runs base (C-R17). Its `--tenant` (C27, N9) is
  gone: an evaluation tool outside the application takes no tenant (human, #1120 / PR #1157);
* `evals/oracle_golden/generate_case.py` (D4 row 7, §7 J32, C-R16) is removed (human, #1120 /
  PR #1157: "Remove generate_case"); its cells here went with it.

Every other input is real: the colliding run, the sibling trials, the fixtures and run dirs
held_out scores are written to disk in the test. The judge's model seam is `_judge_921.FakeJudge`
(tier 2: an LLM), whose PROMPTS are what the union assertions read.
"""
from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from defender.tests import _judge_921 as J
from defender.tests import _triplet_947 as T
from defender.tests.tenant_1078_pass_a import _spec1078 as H
from defender.tests.tenant_1078_pass_a._census_1078 import docstring_ids
from defender.tests import _state1135

TENANT = H.VALID_ID


# ======================================================================================
# Local builders
# ======================================================================================

def _judge_roots(tmp_path: Path, monkeypatch, *, stale_base: Path | None = None) -> Path:
    """The judge's queue root under tmp (never the checkout's `learning/_pending/`), an
    episodes root, a data root with T created, and — when given — a STALE retired knob, so a
    consumer that still reads it is caught reading the wrong tree. Returns the data root."""
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")
    monkeypatch.setenv(J.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    if stale_base is None:
        monkeypatch.delenv(J.RUNS_BASE_ENV, raising=False)
    else:
        monkeypatch.setenv(J.RUNS_BASE_ENV, str(stale_base))
    root = tmp_path / "data"
    H.set_data_root(monkeypatch, root)
    H.make_tenant(root, TENANT)
    return root


def _episode(tmp_path: Path, name: str) -> Path:
    """An accepted, gradable #947 episode (worlds a/b/c; `a` is the family's control)."""
    return J.accepted_episode(tmp_path / name, ledgers={"b": [J.staged_row("b")], "c": []})


def _trial(base: Path, run_id: str, *, alert_id: str = J.ALERT_ID) -> Path:
    """A FINISHED run of the episode's alert under `base` — a sibling trial the union reads."""
    run = base / run_id
    run.mkdir(parents=True, exist_ok=True)
    (run / "alert.json").write_text(json.dumps({"alert_id": alert_id}), encoding="utf-8")
    (run / "report.md").write_text(J.report_text("benign"), encoding="utf-8")
    return run


def _judge() -> Any:
    return J.FakeJudge(default=J.as_reply_text(J.reply_doc()))


def _grade_episode():
    return H.mod("learning.judge").grade_episode


def _held_out():
    return H.mod("evals.held_out")


def _fixtures(tmp_path: Path, slug: str = "slug-one", disposition: str = "benign") -> Path:
    """One labeled held-out fixture: `<fixtures>/<slug>/{alert.json, ground_truth.yaml}`."""
    fx = tmp_path / "fixtures" / slug
    fx.mkdir(parents=True)
    (fx / "alert.json").write_text(json.dumps({"rule": {"id": slug}}), encoding="utf-8")
    (fx / "ground_truth.yaml").write_text(
        f"held_out: true\ndisposition: {disposition}\n", encoding="utf-8")
    return fx.parent


def _scored_run(runs: Path, disposition: str, slug: str = "slug-one") -> Path:
    run = runs / slug
    run.mkdir(parents=True, exist_ok=True)
    (run / "report.md").write_text(T.report_text(disposition), encoding="utf-8")
    return run


def _drive_held_out(argv: list[str], capsys) -> tuple[Any, str]:
    """`held_out.main(argv)` → (its status — a return code or a SystemExit code, `None` for a
    clean `--help`), and everything it printed."""
    try:
        status: Any = _held_out().main(argv)
    except SystemExit as stopped:
        status = stopped.code
    out = capsys.readouterr()
    return status, out.out + out.err


SCORED = "# Held-out eval"


# ======================================================================================
# The judge — the collision probe and the sibling union (D4 rows 1-2)
# ======================================================================================

def test_d4_judge_probe_threaded(tmp_path, monkeypatch):
    """_check_world_labels takes the runs base as a parameter threaded from
    grade_episode (its runs_base keyword given runs_base_for(T)) via the launcher's _grade, and a colliding world
    label is refused (JudgeRefused) in the configuration where today's probe returns silently;
    the except-Exception fallback is gone. grade_episode's runs_base is a required keyword:
    calling it without one is a TypeError, never a skipped probe.

    The configuration: the retired `DEFENDER_RUNS_BASE` unset, so today's probe resolves some
    OTHER base (or none) and finds nothing to collide with; the base that holds the colliding
    finished run `b` is the one handed in. The launcher's `_grade` handing it
    `runs_base_for(T)` is the clause `d4_launcher_derives_once`; this test pins the grade's own
    half, which is the only half with a return channel."""
    root = _judge_roots(tmp_path, monkeypatch)
    base = H.runs_base_for(TENANT)
    assert base == root.resolve() / TENANT / "runs"
    _trial(base, "b")  # a finished run whose name is graded world b's label

    ep = _episode(tmp_path, "collide")
    judge_refused = H.mod("learning.judge.family").JudgeRefused
    with pytest.raises(judge_refused) as refused:
        _grade_episode()(ep, judge=_judge(), runs_base=base, draws=1)
    assert "'b'" in str(refused.value), f"the refusal is not the probe's: {refused.value}"
    assert str(base / "b") in str(refused.value), (
        f"the refusal is not the label-collision probe's: {refused.value}")

    # the positive control: the same episode shape with no collision under the threaded base
    # grades — so the refusal above is the probe firing, not the episode being ungradable
    clean_base = tmp_path / "clean-base"
    clean_base.mkdir()
    _grade_episode()(_episode(tmp_path, "clean"), judge=_judge(), runs_base=clean_base,
                     draws=1)

    unthreaded = _episode(tmp_path, "unthreaded")
    with pytest.raises(TypeError):
        _grade_episode()(unthreaded, judge=_judge(), draws=1)


def test_collision_probe_over_a_tenant_runs_base_holding_a_label_named_run(tmp_path,
                                                                           monkeypatch):
    """The judge's collision probe runs against the threaded runs_base_for(T): a finished
    <T>/runs/a collides with world label a and grading refuses (JudgeRefused), as C26's control
    shows; the probe's comparison logic is unchanged. P6 (is that the right base to probe?)
    stays carried.

    World `b` stands in for "world label a" here: in the #947 layout `a` is the family's
    control (role A), which the label probe does not grade. The comparison logic being
    unchanged is pinned by its own spelling of the collision: anything standing at the label's
    name — here a dangling link, which `is_dir()` would miss — collides."""
    _judge_roots(tmp_path, monkeypatch)
    base = H.runs_base_for(TENANT)
    base.mkdir(parents=True, exist_ok=True)
    (base / "b").symlink_to(tmp_path / "nowhere")
    judge_refused = H.mod("learning.judge.family").JudgeRefused
    with pytest.raises(judge_refused) as refused:
        _grade_episode()(_episode(tmp_path, "ep"), judge=_judge(), runs_base=base, draws=1)
    assert "collides" in str(refused.value), refused.value
    assert "'b'" in str(refused.value), refused.value


def test_d4_render_union_threaded(tmp_path, monkeypatch):
    """The judge render's sibling_union reads the same threaded runs_base_for(T).
    grade_episode's runs_base is a required keyword: calling it without one is a TypeError,
    never a skipped probe.

    Observed on what the model seam is SHOWN: a finished trial of the same alert under the
    threaded base is in the prompt, and one under a stale retired knob is not."""
    stale = tmp_path / "old-runs"
    _trial(stale, "trial-under-the-stale-knob")
    _judge_roots(tmp_path, monkeypatch, stale_base=stale)
    base = H.runs_base_for(TENANT)
    _trial(base, "trial-under-the-tenant")

    judge = _judge()
    _grade_episode()(_episode(tmp_path, "ep"), judge=judge, runs_base=base, draws=1)
    world_prompts = [p for p in judge.prompts if "trial-under-the-tenant" in p]
    assert world_prompts, "the sibling union did not read the threaded runs base"
    assert not any("trial-under-the-stale-knob" in p for p in judge.prompts), (
        "the sibling union read the retired DEFENDER_RUNS_BASE rather than the threaded base")

    with pytest.raises(TypeError):
        _grade_episode()(_episode(tmp_path, "unthreaded"), judge=_judge(), draws=1)


def test_judge_sibling_union_after_the_switch(tmp_path, monkeypatch):
    """The judge's sibling union reads the threaded runs_base_for(T) only, so trials in the old
    runs base are absent from it (N4: old bases are not read for T).

    The old base is the one an operator's shell still names (the retired knob); the union is
    read off the graded world's own prompt."""
    old = tmp_path / "defender-runs"
    _trial(old, "old-layout-trial")
    _judge_roots(tmp_path, monkeypatch, stale_base=old)
    base = H.runs_base_for(TENANT)
    _trial(base, "tenant-trial")

    judge = _judge()
    _grade_episode()(_episode(tmp_path, "ep"), judge=judge, runs_base=H.runs_base_for(TENANT),
                     draws=1)
    shown = "\n".join(judge.prompts)
    assert "tenant-trial" in shown, "the union did not read runs_base_for(T)"
    assert "old-layout-trial" not in shown, "a trial in the old runs base entered the union"


# ======================================================================================
# The review replay (D4 row 5)
# ======================================================================================

def test_d4_review_env_threaded(tmp_path, monkeypatch):
    """verb_context(episode_dir, *, runs_base) and seams.adapter_seam(episode_dir, *, runs_base)
    take the runs base; the launcher passes runs_base_for(T), and the replay env's
    DEFENDER_RUNS_BASE is that base; review.py's fallback and its :299 caller pass their
    caller's base.

    "Take" is observed twice: the replay env carries exactly the base handed in (not the
    episode dir's parent `run_env` would export, not the retired knob), and a call that hands
    in NO base is a TypeError — so neither the `replay_one` fallback nor `review`'s own call can
    compose a context without being handed one by their caller."""
    root = tmp_path / "data"
    H.set_data_root(monkeypatch, root)
    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(tmp_path / "stale"))
    ep = tmp_path / "episodes-root" / "ep-1"
    ep.mkdir(parents=True)
    base = tmp_path / "data" / TENANT / "runs"

    review = H.mod("learning.branch.review")
    seams = H.mod("learning.branch.seams")
    ctx = review.verb_context(ep, H.T1106.FIXTURE_SETTINGS, runs_base=base)
    assert ctx.env["DEFENDER_RUNS_BASE"] == str(base)
    assert ctx.run_dir == ep, "the replay context stopped being the episode dir"
    side = seams.adapter_seam(ep, H.T1106.fixture_run_tenant(), runs_base=base)
    assert side.ctx.env["DEFENDER_RUNS_BASE"] == str(base)

    with pytest.raises(TypeError):
        review.verb_context(ep, H.T1106.FIXTURE_SETTINGS)
    with pytest.raises(TypeError):
        seams.adapter_seam(ep, H.T1106.fixture_run_tenant())


def test_review_replay_runs_base_for_an_old_base_episode(tmp_path, monkeypatch):
    """The review replay is handed runs_base_for(T) wherever the episode lives; its adapter
    subprocesses see DEFENDER_RUNS_BASE=<T>/runs (D4 review row).

    The episode lives under an OLD episodes base outside the data root (pass A's gap until
    (B)); a child process started with the replay context's env — the env every adapter
    subprocess the replay spawns inherits — reads `<root>/T/runs`."""
    root = tmp_path / "data"
    H.set_data_root(monkeypatch, root)
    H.make_tenant(root, TENANT)
    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(tmp_path / "stale-knob"))
    ep = tmp_path / "old-episodes-base" / "src-run-n5"
    ep.mkdir(parents=True)

    ctx = H.mod("learning.branch.review").verb_context(
        ep, H.T1106.FIXTURE_SETTINGS, runs_base=H.runs_base_for(TENANT))
    child = subprocess.run(  # noqa: S603 — fixed argv, the test's own interpreter
        [sys.executable, "-c", "import os; print(os.environ['DEFENDER_RUNS_BASE'])"],
        env=ctx.env, capture_output=True, text=True, check=True, timeout=60)
    assert child.stdout.strip() == str(root.resolve() / TENANT / "runs")


# ======================================================================================
# held_out (D4 row 6)
# ======================================================================================

def test_d4_held_out_exactly_one(tmp_path, monkeypatch, capsys):
    """held_out <runs_dir> scores exactly that dir, and a `--tenant` (with or without a runs
    dir) or no runs dir at all is refused. Superseded for #1120 (human, PR #1157): held_out is
    an evaluation tool outside the application and takes no tenant, so the `--tenant` branch
    this test once pinned (C27) is now a usage error.

    Which tree was scored is read off the verdict: a fixture's run under a set-up tenant's runs
    base closes `benign`, the one under a stale retired knob closes `malicious`, and the
    positional dir's closes `inconclusive` — so only the positional dir may be scored. A
    refusal prints no scoring report."""
    root = tmp_path / "data"
    H.set_data_root(monkeypatch, root)
    H.make_tenant(root, TENANT)
    fixtures = _fixtures(tmp_path)
    _scored_run(H.runs_dir(root, TENANT), "benign")
    stale = tmp_path / "stale-runs"
    _scored_run(stale, "malicious")
    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(stale))
    positional = tmp_path / "given-dir"
    _scored_run(positional, "inconclusive")
    fx = ["--fixtures-dir", str(fixtures)]

    status, out = _drive_held_out([str(positional), *fx], capsys)
    assert status == 0, out
    assert "predicted='inconclusive'" in out, f"the positional dir was not the one scored:\n{out}"

    for argv, what in ((["--tenant", TENANT, *fx], "--tenant"),
                       ([str(positional), "--tenant", TENANT, *fx], "a runs dir and --tenant"),
                       (fx, "no runs dir")):
        status, out = _drive_held_out(argv, capsys)
        assert status not in (0, None), f"held_out with {what} was not refused"
        assert SCORED not in out, f"held_out with {what} scored something before refusing:\n{out}"


def test_s7_j50_held_out_positional_ignores_data_root(tmp_path, monkeypatch, capsys):
    """held_out <runs_dir> scores the directory it is given under DEFENDER_DATA_ROOT=rel/ (and
    with it unset): the positional branch never resolves the data root or a tenant."""
    monkeypatch.chdir(tmp_path)
    fixtures = _fixtures(tmp_path)
    given = tmp_path / "given-dir"
    _scored_run(given, "benign")
    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(tmp_path / "stale-knob"))
    for value in ("rel/", None):
        if value is None:
            H.set_data_root(monkeypatch, None)
        else:
            monkeypatch.setenv(H.DATA_ROOT_ENV, value)
        status, out = _drive_held_out([str(given), "--fixtures-dir", str(fixtures)], capsys)
        assert status == 0, f"DEFENDER_DATA_ROOT={value!r}: {out}"
        assert "slug-one: predicted='benign'" in out, out
        assert "WRONG" not in out, out
    assert not (tmp_path / "rel").exists(), "the positional branch created the data root"


def test_s7_generate_case_held_out_migrated(tmp_path, monkeypatch, capsys):
    """held_out --help does not resolve a runs base. The other halves are gone (human, #1120 /
    PR #1157): held_out takes no tenant, and generate_case is removed.

    `--help` is driven in the one configuration today's eager default cannot survive (C-R17):
    the retired knob and the learning state dir naming one directory, which
    `resolve_runs_base()` refuses before argparse ever prints."""
    shared = tmp_path / "shared"
    shared.mkdir()
    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(shared))
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(shared))
    status, out = _drive_held_out(["--help"], capsys)
    assert status in (0, None), f"held_out --help failed:\n{out}"
    assert "usage" in out.lower(), (
        f"held_out --help resolved a runs base before printing:\n{out}")


# ======================================================================================
# O7's census — resolve_runs_base is gone, and nothing reads DEFENDER_RUNS_BASE
# ======================================================================================

KNOB = "DEFENDER_RUNS_BASE"
RESOLVER = "resolve_runs_base"

#: F2's allowlist (§7 F2, auto): the derived EXPORTS — a store into a child's env mapping —
#: inside the functions that build a child's env, and the box env allowlist entry. The review
#: replay's `verb_context` is on it for the same reason `run_env` is: D4's review row makes it
#: export the THREADED base into the replay env (`d4_review_env_threaded`), which is a derived
#: export of `runs_base_for(T)`, never a read of the knob.
EXPORTING_FUNCTIONS = {
    ("run_common.py", "run_env"),
    ("runtime/box/_docker.py", "infra_env"),
    ("learning/branch/review.py", "verb_context"),
}
ALLOWLIST_MODULES = {"runtime/box_codec.py"}


def _is_env_store(parents: list[ast.AST], node: ast.AST) -> bool:
    """`<mapping>["DEFENDER_RUNS_BASE"] = ...` — the one shape an export has."""
    parent = parents[-1] if parents else None
    return (isinstance(parent, ast.Subscript) and parent.slice is node
            and isinstance(parent.ctx, ast.Store))


def _classify(child: ast.AST, *, rel: str, fn: str, parents: list[ast.AST],
              docs: set[int]) -> str | None:
    """One node's census finding, or `None`."""
    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and child.name == RESOLVER:
        return f"{rel}:{child.lineno}: defines {RESOLVER}"
    if isinstance(child, ast.alias) and RESOLVER in (child.name, child.asname):
        return f"{rel}: imports {RESOLVER}"
    if isinstance(child, ast.Name) and child.id == RESOLVER:
        return f"{rel}:{child.lineno}: names {RESOLVER}"
    if isinstance(child, ast.Attribute) and child.attr == RESOLVER:
        return f"{rel}:{child.lineno}: reaches {RESOLVER}"
    if (isinstance(child, ast.Constant) and isinstance(child.value, str)
            and KNOB in child.value and id(child) not in docs):
        allowed = rel in ALLOWLIST_MODULES or (
            (rel, fn) in EXPORTING_FUNCTIONS and child.value == KNOB
            and _is_env_store(parents, child))
        if not allowed:
            return f"{rel}:{child.lineno}: in {fn or '<module>'}: {child.value[:70]!r}"
    return None


def runs_base_census(root: Path) -> list[str]:
    """Every production mention of the retired knob and its resolver under `root` (a
    `defender/` tree): a `def`/import/name/attribute spelling `resolve_runs_base`, and every
    non-docstring string mentioning `DEFENDER_RUNS_BASE` that is not an allowlisted export.
    `tests/` is not production; `.venv` and caches are not source."""
    findings: list[str] = []
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(root).as_posix()
        if rel.startswith(("tests/", ".venv/")) or "/__pycache__/" in f"/{rel}":
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if KNOB not in text and RESOLVER not in text:
            continue
        tree = ast.parse(text)
        docs = docstring_ids(tree)

        def visit(node: ast.AST, fn: str, parents: list[ast.AST], rel: str = rel,
                  docs: set[int] = docs) -> None:
            for child in ast.iter_child_nodes(node):
                found = _classify(child, rel=rel, fn=fn, parents=parents, docs=docs)
                if found is not None:
                    findings.append(found)
                here = child.name if isinstance(child, (ast.FunctionDef,
                                                        ast.AsyncFunctionDef)) else fn
                visit(child, here, [*parents, child])

        visit(tree, "", [])
    return findings


def test_o7_resolve_runs_base_gone(tmp_path):
    """resolve_runs_base no longer exists and no production Python reads DEFENDER_RUNS_BASE to
    find a runs base; the only production mentions left are the derived exports in run_env and
    infra_env, the box env allowlist entry, and bin/defender-invlang's read of the exported
    value.

    `bin/defender-invlang` is a shell shim, outside this Python census (F2 allowlists its read;
    `bin/` does not exist at base, C-R18). Docstrings are allowlisted (F2); message strings are
    not — a remedy telling the operator to set the retired knob is D8's retired-knob text. The
    POSITIVE CONTROL runs the same scanner over a planted tree: a reader of the knob, a copy of
    the resolver and an import of it are each reported, and an allowlisted export is not."""
    assert not hasattr(H.run_common(), RESOLVER), f"run_common.{RESOLVER} still exists"
    findings = runs_base_census(H.DEFENDER)
    assert findings == [], (
        "production Python still reaches the retired runs-base knob or its resolver:\n  "
        + "\n  ".join(findings))

    planted = tmp_path / "defender"
    (planted / "evals").mkdir(parents=True)
    (planted / "evals" / "reader.py").write_text(
        "import os\nfrom pathlib import Path\n"
        "def base():\n    return Path(os.environ.get('DEFENDER_RUNS_BASE', '/tmp/x'))\n",
        encoding="utf-8")
    (planted / "learning").mkdir()
    (planted / "learning" / "copy.py").write_text(
        "from defender.run_common import resolve_runs_base\n"
        "def resolve_runs_base():\n    '''DEFENDER_RUNS_BASE, in a docstring: allowed'''\n",
        encoding="utf-8")
    (planted / "run_common.py").write_text(
        "def run_env(run_dir):\n    env = {}\n    env['DEFENDER_RUNS_BASE'] = str(run_dir.parent)\n"
        "    return env\n", encoding="utf-8")
    control = runs_base_census(planted)
    assert any(f.startswith("evals/reader.py") for f in control), control
    assert any("defines resolve_runs_base" in f for f in control), control
    assert any("imports resolve_runs_base" in f for f in control), control
    assert not any(f.startswith("run_common.py") for f in control), (
        f"the census reported an allowlisted export: {control}")
    assert not any("docstring" in f for f in control), control


# ======================================================================================
# s102 — the test that called the deleted resolver directly (design correction R-A2(b))
# ======================================================================================

def test_tests_that_call_the_deleted_resolver_directly(d9_tenant, data_root, tmp_path,
                                                        monkeypatch):
    """tests/test_budget_seams_631.py:562-576 is rewritten off run_common.resolve_runs_base()
    onto the D9 tenant fixture. D9's file counts do not cover it.

    Pinned two ways: the rewritten test names no deleted resolver (a static read of its own
    body), and the disjointness it guards — the enforced budget pool's runs base apart from the
    unenforced learning state root (O13, `run_common.py:39-44`) — still holds through the
    substitute, `runs_base_for(T)` over the D9 tenant's data root: a learning state root at
    that base (or an alias of it) is refused, and a disjoint one resolves to <root>/T/runs."""
    source = (H.DEFENDER / "tests" / "test_budget_seams_631.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
              and n.name == "test_the_learning_state_root_and_the_runs_base_cannot_be_the_same_dir")
    body = ast.get_source_segment(source, fn) or ""
    assert RESOLVER not in body.split('"""')[-1], (
        "test_budget_seams_631 still calls the deleted resolve_runs_base()")
    assert "d9_tenant" in [a.arg for a in fn.args.args], (
        "test_budget_seams_631 is not driven by the D9 tenant fixture")

    base = H.runs_base_for(d9_tenant)
    assert base == data_root.resolve() / d9_tenant / "runs"
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(base))
    H.owner_refusal(H.runs_base_for, d9_tenant)
    alias = tmp_path / "alias"
    alias.symlink_to(data_root, target_is_directory=True)
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(alias))
    H.owner_refusal(H.runs_base_for, d9_tenant)
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "learn"))
    assert H.runs_base_for(d9_tenant) == base
