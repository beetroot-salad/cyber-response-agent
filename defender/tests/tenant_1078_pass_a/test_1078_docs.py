"""#1078 pass (A) — D8's knobs and docs: the devcontainer's data root, `--tenant` and the
one-time setup step on every documented fresh run, the setup caveats (§7 J13/F8's wording),
`held_out`'s exactly-one invocation, the retired `DEFENDER_RUNS_BASE` knob text, `.gitignore` —
and J57's autouse data-root isolation, the fixture every other test in this suite runs under.

The doc tests read the REAL files at the paths D8 lists (verified present at ed5386bc). They
key on what an invocation or an instruction SAYS — a `--tenant` on the command line, a knob
told to be set — never on line numbers, which the rewrite moves. Red at base means the doc does
not yet say it; that is a doc the implementer rewrites, not a test to loosen.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest
import yaml

from defender.tests._by_path import import_lint_lib
from defender.tests.tenant_1078_pass_a import _spec1078 as H

REPO = H.REPO_ROOT
DEFENDER = H.DEFENDER

#: D8's eleven documented fresh-run invocations (C58), by file. `README.md` is the repo root's;
#: every other path is under `defender/` (the doc's own convention).
FRESH_RUN_DOCS = (
    REPO / "README.md",
    DEFENDER / "CLAUDE.md",
    REPO / ".devcontainer" / "README.runtime.md",
    DEFENDER / "run.py",
    DEFENDER / "evals" / "held_out.py",
    DEFENDER / "evals" / "README.md",
    DEFENDER / "evals" / "oracle_golden" / "README.md",
    DEFENDER / "evals" / "oracle_golden" / "generate_case.py",
    DEFENDER / "docs" / "oracle-calibration.md",
    DEFENDER / "skills" / "handbook" / "SKILL.md",
    DEFENDER / "skills" / "handbook" / "content" / "runtime-loop.md",
)

#: A fresh-run invocation of `run.py`: the script followed by an alert argument (a `<...>`
#: placeholder, a `*.json` path, or a shell variable), never a `--resume` (derived, D3).
_FRESH_RUN = re.compile(r"(?<![\w-])run\.py\s+(?:<[^>]+>|\"?\$|\S+\.json)")
SETUP_STEP = "tenant.py setup playground"


def _logical_lines(text: str) -> list[str]:
    """Lines with shell continuations (`\\` at the end) joined, so a flag on the next line
    counts as part of the invocation."""
    out: list[str] = []
    buf = ""
    for line in text.splitlines():
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            buf += stripped.rstrip("\\") + " "
            continue
        out.append(buf + line)
        buf = ""
    if buf:
        out.append(buf)
    return out


def test_d8_fresh_run_docs():
    """Each of the eleven documented fresh-run invocations names --tenant and the one-time
    tenant.py setup playground step.

    Per file: every fresh-run `run.py` invocation it documents carries `--tenant`, and the
    file names the setup step. `experiments/`, `docs/archive/` and `docs/decisions/` are left
    alone (D8)."""
    problems = []
    for doc in FRESH_RUN_DOCS:
        assert doc.is_file(), f"D8's fresh-run doc {doc} moved"
        text = doc.read_text(encoding="utf-8")
        invocations = [ln for ln in _logical_lines(text)
                       if _FRESH_RUN.search(ln) and "--resume" not in ln]
        rel = doc.relative_to(REPO).as_posix()
        if not invocations:
            problems.append(f"{rel}: documents no fresh-run invocation any more")
        problems += [f"{rel}: `{ln.strip()[:100]}` has no --tenant"
                     for ln in invocations if "--tenant" not in ln]
        if SETUP_STEP not in text:
            problems.append(f"{rel}: does not name the one-time `{SETUP_STEP}` step")
    assert problems == [], "\n".join(problems)


_SKIP_DOC_DIRS = {".spec-flow", "spec-flow", "experiments", "node_modules", ".venv", ".git",
                  "tests", "__pycache__"}


def _docs_naming_setup() -> list[Path]:
    out = []
    for p in sorted(REPO.rglob("*.md")):
        rel = p.relative_to(REPO)
        if _SKIP_DOC_DIRS & set(rel.parts):
            continue
        if rel.as_posix().startswith(("docs/archive/", "docs/decisions/",
                                      "defender/docs/archive/", "defender/docs/decisions/")):
            continue
        if "tenant.py setup" in p.read_text(encoding="utf-8", errors="replace"):
            out.append(p)
    return out


def _section_after(text: str, needle: str) -> str:
    """From the first line naming `needle` to the next markdown heading (or 40 lines)."""
    lines = text.splitlines()
    start = next(i for i, ln in enumerate(lines) if needle in ln)
    out = []
    for ln in lines[start:start + 40]:
        if out and ln.startswith("#") and not ln.startswith("#!"):
            break
        out.append(ln)
    return "\n".join(out)


def test_d8_setup_doc_caveats():
    """Where the docs name the setup step they also say: run it from the main checkout, with
    no run, fork or drain in flight on any checkout of the host, and as the user that runs
    defender; the '(root where the old entries are root-owned)' caveat is worded for the
    (B)/(C) adoption only; and a destination written first makes setup refuse with the remedy
    in its message. They also name DEFENDER_DATA_ROOT (there is no default data root, J01) and
    no longer present a /tmp/defender-data default.

    Read per markdown doc naming `tenant.py setup`, over the section that names it (J13 / F8,
    auto: pass A's docs say to run setup as the user that runs defender; "as root" is only
    ever said of the (B)/(C) adoption). README.md and defender/CLAUDE.md name it (D8's
    fresh-run list), so the set is never empty.

    J01's docs knock-on (phase F RC6, auto): with NO DEFAULT DATA ROOT, setup and every run
    refuse an unset DEFENDER_DATA_ROOT, so the section that names the setup step must also
    name DEFENDER_DATA_ROOT, and no such doc may still present `/tmp/defender-data` as a
    default (J01 dropped it from the data model)."""
    docs = _docs_naming_setup()
    names = {p.relative_to(REPO).as_posix() for p in docs}
    assert {"README.md", "defender/CLAUDE.md"} <= names, (
        f"the setup step is not documented where D8 puts it (found in {sorted(names)})")
    problems = []
    for doc in docs:
        section = _section_after(doc.read_text(encoding="utf-8"), "tenant.py setup")
        flat = " ".join(section.split()).lower()
        rel = doc.relative_to(REPO).as_posix()
        if "DEFENDER_DATA_ROOT" not in section:
            problems.append(f"{rel}: the setup step does not say to set DEFENDER_DATA_ROOT "
                            "(there is no default data root, J01)")
        if "/tmp/defender-data" in doc.read_text(encoding="utf-8"):
            problems.append(f"{rel}: still presents the retired /tmp/defender-data default")
        for what, pattern in (
            ("run it from the main checkout", r"main checkout"),
            ("no run, fork or drain in flight", r"in flight"),
            ("as the user that runs defender", r"user that runs defender|same user"),
            ("a destination written first makes setup refuse (remedy in its message)",
             r"destination[^.]*refus|refus[^.]*destination"),
        ):
            if not re.search(pattern, flat):
                problems.append(f"{rel}: the setup caveats omit '{what}'")
        for sentence in re.split(r"(?<=[.;])\s", flat):
            if re.search(r"\bas root\b|\broot-owned\b", sentence) and not re.search(
                    r"\(b\)|\(c\)|adopt", sentence):
                problems.append(f"{rel}: the root caveat is not scoped to (B)/(C) adoption: "
                                f"{sentence[:120]!r}")
    assert problems == [], "\n".join(problems)


#: `held_out`'s documented invocations (D8's "from (A)" selector list, C60).
HELD_OUT_DOCS = (
    DEFENDER / "evals" / "held_out.py",
    DEFENDER / "evals" / "README.md",
    DEFENDER / "fixtures" / "held-out" / "README.md",
)
_RETIRED_RUNS_DIR = re.compile(r"DEFENDER_RUNS_BASE|/tmp/defender-runs")


def test_d8_held_out_docs():
    """held_out.py:29, evals/README.md:30 and fixtures/held-out/README.md:114 each take
    --tenant or keep the positional runs dir.

    Under D4's "exactly one of `--tenant` or the positional", a documented invocation must name
    one of them: `--tenant <id>`, or a runs dir that is REQUIRED (not `[<runs_dir>]`, which
    documents the neither case O7 now refuses) and is not the retired knob or its default."""
    problems = []
    for doc in HELD_OUT_DOCS:
        rel = doc.relative_to(REPO).as_posix()
        invocations = [ln for ln in _logical_lines(doc.read_text(encoding="utf-8"))
                       if re.search(r"held_out\.py", ln) and re.search(r"python3?\s", ln)]
        if not invocations:
            problems.append(f"{rel}: documents no held_out invocation")
        for ln in invocations:
            if "--tenant" in ln:
                continue
            args = ln.split("held_out.py", 1)[1].split()
            positional = [a for a in args if not a.startswith("-")]
            if not positional or positional[0].startswith("[") or _RETIRED_RUNS_DIR.search(
                    positional[0]):
                problems.append(f"{rel}: `{ln.strip()[:100]}` takes neither --tenant nor a "
                                "runs dir")
    assert problems == [], "\n".join(problems)


#: D8's retired-knob list (C2b, C34, C58), by file; the launcher's entry is `episodes_root`.
RETIRED_KNOB_FILES = (
    DEFENDER / "runtime" / "box" / "_lifecycle.py",
    DEFENDER / "run_common.py",
    DEFENDER / "learning" / "ops" / "trace_lesson.py",
    DEFENDER / "evals" / "held_out.py",
    REPO / "README.md",
    DEFENDER / "CLAUDE.md",
    DEFENDER / "evals" / "README.md",
    DEFENDER / "skills" / "handbook" / "content" / "run-artifacts.md",
    DEFENDER / "skills" / "handbook" / "content" / "invlang.md",
    DEFENDER / "skills" / "handbook" / "SKILL.md",
    DEFENDER / "bin" / "README.md",
    DEFENDER / "docs" / "learning-loop.md",
    DEFENDER / "docs" / "run-records.md",
    DEFENDER / "learning" / "frontend" / "README.md",
)
_DERIVED = "<T>/runs"
_TELLS_TO_SET = (
    re.compile(r"/tmp/defender-runs"),                                  # the retired default
    re.compile(r"DEFENDER_RUNS_BASE=(?!\S*<T>/runs)"),                  # set to a path
    re.compile(r"(?i)\b(set|point|export)\b[^.\n|]{0,40}\bDEFENDER_RUNS_BASE\b"),
)
_READS_THE_KNOB = re.compile(r"\$\{?DEFENDER_RUNS_BASE")


def _prose(path: Path, *, only_function: str | None = None) -> list[tuple[int, str]]:
    """`(line, text)` of what a reader of `path` is TOLD: every line of a markdown doc; the
    string constants (docstrings, messages, remedies) of a Python module — never its code."""
    text = path.read_text(encoding="utf-8")
    if path.suffix != ".py":
        return list(enumerate(text.splitlines(), 1))
    tree = ast.parse(text)
    scope: ast.AST = tree
    if only_function is not None:
        scope = next(n for n in ast.walk(tree)
                     if isinstance(n, ast.FunctionDef) and n.name == only_function)
    out = []
    for node in ast.walk(scope):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            for i, ln in enumerate(node.value.splitlines()):
                out.append((node.lineno + i, ln))
    return out


def _knob_instructions(path: Path, *, only_function: str | None = None) -> list[str]:
    lines = _prose(path, only_function=only_function)
    explained = any(_DERIVED in ln or "run_dir.parent" in ln for _, ln in lines)
    rel = path.relative_to(REPO).as_posix()
    found = []
    for n, ln in lines:
        if _DERIVED in ln:
            continue  # bin/README's derived <root>/<T>/runs instruction, and its like
        if any(p.search(ln) for p in _TELLS_TO_SET) or (
                _READS_THE_KNOB.search(ln) and not explained):
            found.append(f"{rel}:{n}: {ln.strip()[:120]}")
    return found


def test_d8_retired_runs_knob_text():
    """No doc or remedy text on D8's retired-knob list tells an operator to set
    DEFENDER_RUNS_BASE except bin/README's derived <root>/<T>/runs instruction for
    bin/defender-invlang, and _lifecycle.py:47's remedy names DEFENDER_DATA_ROOT.

    "Tells an operator to set it" is read as: names the retired `/tmp/defender-runs` default,
    assigns the knob a path, says to set/point/export it, or uses `$DEFENDER_RUNS_BASE` in a
    file that never says the value is the derived `<root>/<T>/runs` (`run_dir.parent`). The
    launcher's entry on the list is `cli.episodes_root`, read alone."""
    found = []
    for path in RETIRED_KNOB_FILES:
        assert path.is_file(), f"D8's retired-knob file {path} moved"
        found += _knob_instructions(path)
    found += _knob_instructions(DEFENDER / "learning" / "branch" / "cli.py",
                                only_function="episodes_root")
    assert found == [], "retired DEFENDER_RUNS_BASE knob text survives:\n  " + "\n  ".join(found)

    lifecycle = ast.parse((DEFENDER / "runtime" / "box" / "_lifecycle.py").read_text(
        encoding="utf-8"))
    remedies = [ast.unparse(t) for t in ast.walk(lifecycle) if isinstance(t, ast.Tuple)
                and t.elts and isinstance(t.elts[0], ast.Constant) and t.elts[0].value == "run dir"]
    assert remedies, "the box's not-shared refusal for the run dir moved"
    assert all("DEFENDER_DATA_ROOT" in r for r in remedies), (
        f"the box's not-shared remedy does not name DEFENDER_DATA_ROOT: {remedies}")


def test_d8_devcontainer_data_root():
    """.devcontainer/docker-compose.yml's environment sets DEFENDER_DATA_ROOT:
    /workspace/.defender-data, and defender/CLAUDE.md's runs-base instruction becomes 'set
    DEFENDER_DATA_ROOT=/workspace/.defender-data'.

    Under §7 J01 (NO DEFAULT DATA ROOT) this is the devcontainer's ONLY data root, not an
    alternative to a code default."""
    compose = yaml.safe_load((REPO / ".devcontainer" / "docker-compose.yml").read_text(
        encoding="utf-8"))
    env = compose["services"]["devcontainer"].get("environment") or {}
    if isinstance(env, list):
        env = dict(item.split("=", 1) for item in env)
    assert env.get(H.DATA_ROOT_ENV) == "/workspace/.defender-data", (
        f"the devcontainer does not set {H.DATA_ROOT_ENV}: {env}")
    claude = (DEFENDER / "CLAUDE.md").read_text(encoding="utf-8")
    assert "DEFENDER_DATA_ROOT=/workspace/.defender-data" in claude
    assert "DEFENDER_RUNS_BASE=/workspace/.defender-runs" not in claude, (
        "defender/CLAUDE.md still tells the devcontainer to set the retired runs-base knob")


def _ignored(*rels: str) -> set[str]:
    gitscope = import_lint_lib("_gitscope")
    paths = [REPO / r for r in rels]
    hits = gitscope.git_ignored(REPO, paths)
    return {p.relative_to(REPO).as_posix() for p in hits}


def test_d8_gitignore_data_root():
    """.gitignore ignores .defender-data/.

    Asked of git itself (`git check-ignore`, through the lint library's own seam), with the
    old layout's entry as the control that the question reaches git and a tracked file as the
    control that the answer discriminates."""
    got = _ignored(".defender-data/playground/tenant.json", ".defender-runs/r1/alert.json",
                   "defender/run.py")
    assert ".defender-runs/r1/alert.json" in got, "git check-ignore is not being asked"
    assert "defender/run.py" not in got
    assert ".defender-data/playground/tenant.json" in got, ".defender-data/ is not ignored"


def test_data_root_inside_the_checkout_and_repo_wide_walkers():
    """.gitignore gains .defender-data/ (D8, C47). Whether repo-wide walkers descend into the
    in-checkout data root is P11, carried, and is not pinned as 'accepted'.

    Only the .gitignore half: the entry is written as a directory rule, and the deepest file a
    run leaves under a tenant is ignored with it."""
    lines = [ln.strip() for ln in (REPO / ".gitignore").read_text(encoding="utf-8").splitlines()]
    assert any(ln in (".defender-data/", "/.defender-data/") for ln in lines), (
        ".gitignore has no .defender-data/ entry")
    deep = ".defender-data/playground/runs/r1/gather_raw/l-001/0.json"
    assert deep in _ignored(deep)


# ======================================================================================
# J57 — the autouse data-root isolation
# ======================================================================================

_SEEN_ROOTS: list[str] = []


@pytest.mark.parametrize("which", ["first", "second"])
def test_s7_j57_autouse_data_root_isolation(which, tmp_path_factory):
    """An autouse conftest fixture gives every test its own tmp DEFENDER_DATA_ROOT, so a test
    that never asks for isolation, and two xdist workers in different files, never share a data
    root and never touch a host root.

    This test does NOT request the `data_root` fixture: the variable is set anyway, absolute,
    under this worker's pytest base temp (so two workers — two base temps — cannot share one),
    fresh and empty, distinct between the two cases, and it is the root `resolve_data_root()`
    returns."""
    import os

    raw = os.environ.get(H.DATA_ROOT_ENV)
    assert raw, f"{H.DATA_ROOT_ENV} is unset in a test that did not ask for isolation"
    root = Path(raw)
    assert root.is_absolute()
    base = tmp_path_factory.getbasetemp().resolve()
    assert base in root.resolve().parents, f"{root} is not under this worker's base temp {base}"
    for host in (Path("/tmp/defender-data"), REPO / ".defender-data",
                 Path("/workspace/.defender-data")):
        assert root.resolve() != host.resolve(), f"the test's data root IS the host root {host}"
        assert host.resolve() not in root.resolve().parents, f"the data root is inside {host}"
    assert H.entries(root) == [], f"{which}: the per-test data root is not fresh: {H.entries(root)}"
    assert raw not in _SEEN_ROOTS, f"{which}: two tests share the data root {raw}"
    _SEEN_ROOTS.append(raw)
    assert H.resolve_data_root() == root.resolve()

