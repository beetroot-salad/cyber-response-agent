"""Tests for the lint_stale_refs gate (#618).

The gate had no tests, no DI seam, and — for its entire life — no teeth. It diffs
`origin/main...HEAD` to learn which symbols a PR removed, then greps the post-PR tree
for surviving references. In CI it reported clean on every PR without checking anything:

    `actions/checkout` was depth-1, so HEAD (refs/pull/N/merge) was a shallow graft with
    no common ancestor. The gate's only guard was `git rev-parse --verify origin/main`,
    which PASSED — a `--depth=50` fetch of the base ref had created it. But
    `origin/main...HEAD` is the THREE-DOT form and needs a MERGE-BASE, which the graft
    does not have. `git diff` exited 128; the old `_run` swallowed every CalledProcessError
    into `""`; and `if not diff: return set()` read "git could not answer" as "nothing was
    removed". Zero findings, exit 0.

So the two load-bearing tests here are the ones that pin the FAILURE modes — a gate that
cannot run must exit 2, never 0. `test_shallow_graft_*` reproduces the CI shape
command-for-command and is the regression test for the bug itself; note it needs a
`file://` URL, because git SILENTLY IGNORES `--depth` for a local-path clone (it warns
"--depth is ignored in local clones; use file:// instead"). With a plain path the fixture
would quietly build a full clone, stop reproducing the bug, and still pass — the same class
of vacuous-green this whole issue is about. `test_shallow_fixture_really_has_no_merge_base`
probes the fixture itself so that can never rot silently.

Fixtures are real throwaway git repos (the defender/tests/test_git.py philosophy: git is
local and deterministic, so exercise it for real). The gate is driven only through its DI
seam — `main(argv, repo_root=…, base_ref=…, baseline_path=…)` — so no monkeypatching of
module globals is needed, which also keeps the lint_monkeypatch gate quiet.
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

WORKTREE = Path(__file__).resolve().parents[2]
LINT_DIR = WORKTREE / "scripts" / "lint"
LINT_PATH = LINT_DIR / "lint_stale_refs.py"


def _load_gate():
    # scripts/lint is on the gate's own import path (it does `from _baseline import ...`)
    if str(LINT_DIR) not in sys.path:
        sys.path.insert(0, str(LINT_DIR))
    spec = importlib.util.spec_from_file_location("lint_stale_refs", LINT_PATH)
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    # Register BEFORE exec: a module executed outside sys.modules cannot resolve its own
    # __module__, and anything that looks it up — `@dataclass` deciding whether an
    # annotation is a ClassVar, pickle, typing.get_type_hints — dies on the lookup.
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


GATE = _load_gate()


def _env(repo: Path) -> dict[str, str]:
    """A hermetic git env: `HOME` points into the throwaway repo, so no contributor's
    ~/.gitconfig can reach these fixtures. `PATH` comes from the caller's — pinning a
    literal would decide where git lives (it is not in /usr/bin everywhere)."""
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(repo),
        "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
    }


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], cwd=repo, text=True, capture_output=True, check=check,
        env=_env(repo),
    )


def _commit(repo: Path, message: str) -> None:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)


def _write(repo: Path, rel: str, body: str) -> None:
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def _upstream(
    tmp_path: Path,
    *,
    main_files: dict[str, str] | None = None,
    pr_files: dict[str, str | None] | None = None,
) -> Path:
    """A repo whose `main` defines `some_removed_helper` in mod.py and calls it from
    caller.py, and whose `pr` branch deletes the definition.

    `main_files` are committed on `main`, so the PR does NOT touch them. That is where a
    surviving reference must live to be *seen*: `_batch_grep` already skips hits inside
    the diff's own changed files, so a reference planted in a `pr_files` entry is excluded
    for that reason and never reaches the rule under test — a test that passes without
    exercising anything. `pr_files` is therefore only for what the PR really does change
    (pass None to delete).

    Several commits deep on purpose: a depth-1 graft needs real history to be cut off from,
    or the merge-base would be findable by accident.
    """
    up = tmp_path / "up"
    up.mkdir()
    _git(up, "init", "-q", "-b", "main")
    _write(up, "mod.py", "def some_removed_helper():\n    return 1\n")
    _write(up, "caller.py", "x = some_removed_helper()\n")
    for rel, body in (main_files or {}).items():
        _write(up, rel, body)
    _commit(up, "seed")
    _git(up, "commit", "-q", "--allow-empty", "-m", "c2")
    _git(up, "commit", "-q", "--allow-empty", "-m", "c3")

    _git(up, "checkout", "-q", "-b", "pr")
    _git(up, "rm", "-q", "mod.py")
    for rel, body in (pr_files or {}).items():
        if body is None:
            _git(up, "rm", "-q", rel)
        else:
            _write(up, rel, body)
    _commit(up, "delete the helper (caller.py still references it)")
    return up


def _clone(tmp_path: Path, up: Path, *, depth: int | None = None) -> Path:
    """Clone `up`'s `pr` branch and give it an `origin/main`.

    depth=None  -> full clone: origin/main resolves AND shares an ancestor with HEAD.
    depth=N     -> the CI shape: a shallow graft, plus the `--depth=50` base-ref fetch
                   that ci.yml used to run. origin/main RESOLVES; the merge-base does not.

    The `file://` URL is mandatory — git ignores `--depth` for a local-path clone.
    """
    work = tmp_path / "work"
    args = ["clone", "-q", "--branch", "pr"]
    if depth is not None:
        args += [f"--depth={depth}"]
    args += [f"file://{up}", str(work)]
    _git(tmp_path, *args)
    fetch = ["fetch", "-q", "origin", "main:refs/remotes/origin/main"]
    if depth is not None:
        fetch += ["--depth=50"]  # ci.yml's old "Fetch base ref" step, verbatim
    _git(work, *fetch)
    return work


def _baseline(tmp_path: Path, entries: dict[str, str] | None = None) -> Path:
    path = tmp_path / "baseline.json"
    path.write_text(
        json.dumps({"//": "test", "entries": entries or {}}), encoding="utf-8"
    )
    return path


def _run_gate(work: Path, tmp_path: Path, *, argv: list[str] | None = None,
              base_ref: str = "origin/main", entries: dict[str, str] | None = None) -> int:
    return GATE.main(
        argv or [],
        repo_root=work,
        base_ref=base_ref,
        baseline_path=_baseline(tmp_path, entries),
    )


# --------------------------------------------------------------------------------------
# The gate cannot run -> exit 2. Never 0. (Both fail against the pre-#618 module.)
# --------------------------------------------------------------------------------------

def test_unresolvable_base_ref_exits_2(tmp_path, capsys):
    """No origin at all. The old gate printed a WARN and returned [] -> exit 0."""
    repo = tmp_path / "solo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _write(repo, "a.py", "x = 1\n")
    _commit(repo, "seed")

    assert _run_gate(repo, tmp_path, base_ref="origin/main") == 2
    assert "cannot resolve base ref" in capsys.readouterr().err


def test_shallow_graft_without_merge_base_exits_2(tmp_path, capsys):
    """THE regression test. Reproduces the CI checkout: a depth-1 graft whose base ref
    resolves but shares no ancestor with HEAD. The old gate exited 0 having checked
    nothing, even though the diff deletes a symbol that is still referenced."""
    work = _clone(tmp_path, _upstream(tmp_path), depth=1)

    assert _run_gate(work, tmp_path) == 2
    assert "merge-base" in capsys.readouterr().err


def test_shallow_fixture_really_has_no_merge_base(tmp_path):
    """Probe the FIXTURE, not the gate: assert the shape above is the CI shape and stays
    it. Without this, a git change (or a dropped `file://`) could make the graft
    computable, and the regression test would keep passing while testing nothing — the
    very failure mode #618 is about."""
    work = _clone(tmp_path, _upstream(tmp_path), depth=1)
    run = lambda *a: _git(work, *a, check=False).returncode  # noqa: E731

    assert (work / ".git" / "shallow").exists(), "fixture is not actually shallow"
    assert run("rev-parse", "--verify", "origin/main") == 0, "base ref must RESOLVE..."
    assert run("merge-base", "origin/main", "HEAD") != 0, "...but have NO merge-base"
    assert run("diff", "--unified=0", "origin/main...HEAD") != 0, "three-dot diff must fail"


def test_a_required_git_command_failing_raises_instead_of_returning_empty(tmp_path):
    """The swallow itself. A git call the gate depends on can no longer degrade into `""`
    — which is how a failed diff became "nothing was removed"."""
    work = _clone(tmp_path, _upstream(tmp_path))

    with pytest.raises(GATE.GitError) as exc:
        GATE._changed_files(work, "no-such-ref")
    assert "exited" in str(exc.value)


def test_a_git_failure_inside_the_scan_exits_2(tmp_path, capsys):
    """...and main() turns that into exit 2, never a clean report. Here the preflight
    itself cannot run because the directory is not a repo at all."""
    not_a_repo = tmp_path / "not-a-repo"
    not_a_repo.mkdir()

    assert _run_gate(not_a_repo, tmp_path) == 2
    assert "cannot resolve base ref" in capsys.readouterr().err


def test_update_baseline_refuses_on_an_unusable_base(tmp_path):
    """You must not be able to bless an empty result that was never computed."""
    work = _clone(tmp_path, _upstream(tmp_path), depth=1)
    baseline = _baseline(tmp_path, {"caller.py:some_removed_helper": "pre-existing"})
    before = baseline.read_text(encoding="utf-8")

    assert GATE.main(
        ["--update-baseline"], repo_root=work, base_ref="origin/main", baseline_path=baseline
    ) == 2
    assert baseline.read_text(encoding="utf-8") == before, "baseline was rewritten anyway"


# --------------------------------------------------------------------------------------
# The gate CAN run: it finds real stale references and only those.
# --------------------------------------------------------------------------------------

def test_stale_reference_is_flagged(tmp_path):
    """The happy path — same repo and commits as the graft test, only fully cloned."""
    work = _clone(tmp_path, _upstream(tmp_path))

    assert _run_gate(work, tmp_path) == 1
    fingerprints = {f.fingerprint for f in GATE._scan(work, "origin/main")}
    assert "caller.py:some_removed_helper" in fingerprints


def test_deleted_cli_shim_named_in_a_prompt_is_flagged(tmp_path):
    """The #617 shape that exposed all this: a deleted `bin/defender-record-query` shim
    whose name survives in a model-facing prompt. The ident is synthesized from the
    deleted PATH, not from a Python `def`."""
    up = _upstream(tmp_path)
    _git(up, "checkout", "-q", "main")
    _write(up, "bin/defender-record-query", "#!/bin/sh\necho hi\n")
    _write(up, "skills/gather/SKILL.md", "# Gather\n\nRun defender-record-query --id X.\n")
    _commit(up, "add the shim and the prompt that calls it")
    _git(up, "checkout", "-q", "pr")
    _git(up, "merge", "-q", "main", "-m", "merge")
    _git(up, "rm", "-q", "bin/defender-record-query")
    _commit(up, "delete the shim (SKILL.md still tells the model to run it)")
    work = _clone(tmp_path, up)

    assert _run_gate(work, tmp_path) == 1
    fingerprints = {f.fingerprint for f in GATE._scan(work, "origin/main")}
    assert "skills/gather/SKILL.md:defender-record-query" in fingerprints


def test_surviving_module_named_in_a_from_package_import_is_not_flagged(tmp_path):
    """`from pkg import mod` puts a MODULE in the target position, where idents are
    collected. Deleting one importer must not make every OTHER importer of that live
    module read as a stale reference — a module's binding site is a file, which the AST
    binding scan cannot see. `_removed_idents` already refuses to collect the module PATH
    of `from pkg.mod import name` for this reason; the target position is the same shape.
    """
    up = _upstream(
        tmp_path,
        main_files={
            "pkg/__init__.py": "",
            "pkg/shared_taxonomy.py": "NAMES = {'a'}\n",
            # A surviving importer, committed on main so it is outside the PR's diff.
            "other_importer.py": "from pkg import shared_taxonomy\n\ny = shared_taxonomy.NAMES\n",
            # The importer the PR will delete — also on main, so `git rm` on pr finds it.
            "doomed_importer.py": "from pkg import shared_taxonomy\n\nz = shared_taxonomy.NAMES\n",
        },
    )
    _git(up, "checkout", "-q", "pr")
    _git(up, "rm", "-q", "doomed_importer.py")
    _commit(up, "delete one importer; pkg/shared_taxonomy.py itself survives")
    work = _clone(tmp_path, up)

    fingerprints = {f.fingerprint for f in GATE._scan(work, "origin/main")}
    assert "other_importer.py:shared_taxonomy" not in fingerprints, (
        "a surviving importer of a LIVE module was flagged as a stale reference"
    )


def test_a_genuinely_deleted_module_is_still_flagged(tmp_path):
    """Positive control for the rule above: the module-exists check is scoped to
    git-TRACKED paths, so it clears a module that SURVIVES without blunting the deletion
    the gate exists to catch. (A filesystem walk would find a stale copy under
    `.worktrees/` — where a module deleted from this tree still sits on disk — and mask
    exactly this.)

    The surviving reference is prose, not an import: a surviving `from pkg import mod`
    line is itself an AST binding of that name, so `_still_defined` clears it on the
    pre-existing rule and the deleted-module case never reaches the new one. Prose is
    also where the #617-class stale reference actually lives.
    """
    up = _upstream(
        tmp_path,
        main_files={
            "pkg/__init__.py": "",
            "pkg/doomed_mod.py": "NAMES = {'a'}\n",
            "skills/guide.md": "# Guide\n\nThe roster lives in `pkg/doomed_mod.py`.\n",
        },
    )
    _git(up, "checkout", "-q", "pr")
    _git(up, "rm", "-q", "pkg/doomed_mod.py")
    _commit(up, "delete the module itself (skills/guide.md still names it)")
    work = _clone(tmp_path, up)

    fingerprints = {f.fingerprint for f in GATE._scan(work, "origin/main")}
    assert "skills/guide.md:doomed_mod" in fingerprints, (
        "a reference to a genuinely DELETED module was not flagged"
    )


def test_moved_symbol_is_not_flagged(tmp_path):
    """A symbol deleted HERE and defined THERE was moved, not removed."""
    up = _upstream(tmp_path, pr_files={"moved.py": "def some_removed_helper():\n    return 1\n"})
    work = _clone(tmp_path, up)

    assert _run_gate(work, tmp_path) == 0
    assert GATE._scan(work, "origin/main") == []


def test_removed_ident_with_no_surviving_reference_exits_0(tmp_path):
    """`git grep` exits 1 on "no match". That is a legitimate empty answer, not a failure
    — an over-eager fail-closed refactor would turn it into a GitError."""
    up = _upstream(tmp_path, pr_files={"caller.py": None})  # delete the last reference too
    work = _clone(tmp_path, up)

    assert _run_gate(work, tmp_path) == 0


def test_empty_diff_exits_0(tmp_path):
    """"Genuinely nothing removed" (green) must stay distinguishable from "could not
    compute" (exit 2) — the entire point of the change."""
    up = _upstream(tmp_path)
    _git(up, "checkout", "-q", "pr")
    _git(up, "reset", "-q", "--hard", "main")  # pr is now identical to main
    work = _clone(tmp_path, up)

    assert _run_gate(work, tmp_path) == 0


def test_baselined_finding_exits_0(tmp_path):
    work = _clone(tmp_path, _upstream(tmp_path))

    assert _run_gate(
        work, tmp_path, entries={"caller.py:some_removed_helper": "knowingly tolerated"}
    ) == 0


# --------------------------------------------------------------------------------------
# Not-a-reference shapes: each is a RULE in the lint, so the baseline can ship empty.
# --------------------------------------------------------------------------------------

def test_a_dropped_import_line_does_not_condemn_the_MODULE_it_imported(tmp_path):
    """Removing `from pkg_helper_mod import Thing` is evidence about `Thing`, never about
    `pkg_helper_mod`. The module's binding site is a FILE, so `_still_defined` — which only
    recognises AST bindings — structurally cannot clear it, and every surviving importer of
    a module that still exists reads as a stale reference. On the #647 branch that shape
    produced 25 false findings across 20 files, none of them stale."""
    up = _upstream(
        tmp_path,
        main_files={
            "pkg_helper_mod.py": "class Thing:\n    pass\n",
            "notes_a.md": "See `pkg_helper_mod` for the payload shape.\n",
            "importer.py": "from pkg_helper_mod import Thing\n\nx = Thing()\n",
        },
        pr_files={"importer.py": "x = 1\n", "caller.py": None},
    )
    work = _clone(tmp_path, up)

    assert "pkg_helper_mod" not in GATE._collect_removed_idents(work, "origin/main"), (
        "the module PATH of a dropped from-import was collected as a removed identifier"
    )
    assert GATE._scan(work, "origin/main") == []
    assert _run_gate(work, tmp_path) == 0


def test_a_DELETED_module_is_condemned_by_its_own_deletion(tmp_path):
    """The other half of the rule above: the gate must still catch a reference to a module
    the PR really deleted. That evidence comes from `--name-status`, not from an importer
    having dropped a line — so it holds even when NO import of the module was removed
    anywhere (here there is none: the reference that survives is prose).

    Regression pin for the gap the narrowing opened: the removed-paths walk skipped every
    component containing a dot, and since every filename carries a suffix, it dropped the
    BASENAME of every deleted file — leaving the deleted-module class covered by nothing."""
    up = _upstream(
        tmp_path,
        main_files={
            "dead_helper_mod.py": "VALUE = 1\n",
            "notes_b.md": "Run `dead_helper_mod.py` before the drain.\n",
        },
        pr_files={"dead_helper_mod.py": None, "caller.py": None},
    )
    work = _clone(tmp_path, up)

    findings = GATE._scan(work, "origin/main")
    assert [f.fingerprint for f in findings] == ["notes_b.md:dead_helper_mod"], (
        f"the surviving reference to a DELETED module was not flagged: {findings}"
    )
    assert _run_gate(work, tmp_path) == 1


def test_a_RENAMED_module_keeps_its_name_and_is_not_condemned(tmp_path):
    """A rename is not a deletion. `a/moved_helper_mod.py` -> `b/moved_helper_mod.py` leaves
    the module under the same name, so collecting the stem for renames too would flag every
    reference that is still perfectly correct."""
    up = _upstream(
        tmp_path,
        main_files={
            "a/moved_helper_mod.py": "VALUE = 1\n",
            "notes_c.md": "See `moved_helper_mod` for the payload shape.\n",
        },
        pr_files={
            "a/moved_helper_mod.py": None,
            "b/moved_helper_mod.py": "VALUE = 1\n",
            "caller.py": None,
        },
    )
    work = _clone(tmp_path, up)

    # Probe the FIXTURE, not just the gate: the rule under test only engages when git
    # actually reports an `R`. If similarity detection ever stops pairing these two paths,
    # the diff degrades to delete+add, the deleted-stem walk fires legitimately, and this
    # test would fail for a reason that has nothing to do with the rule — or, worse, a
    # future relaxation would make it pass vacuously.
    status = GATE._git(
        ["diff", "--name-status", "origin/main...HEAD"], cwd=work
    )
    assert any(line.startswith("R") and "moved_helper_mod" in line
               for line in status.splitlines()), (
        f"fixture rotted: git did not detect the move as a rename\n{status}"
    )

    assert GATE._scan(work, "origin/main") == []
    assert _run_gate(work, tmp_path) == 0


@pytest.mark.parametrize(
    "rel",
    [
        ".spec/brief.md",                        # spec artifacts quote the old code by design
        "defender/fixtures-e2e/golden-x/investigation.md",  # sibling of the excluded fixtures/
        "defender/lessons-environment/l-01.md",  # sibling of the excluded lessons/
        "defender/tests/spec_graph_551.yaml",    # frozen record of a merged issue
        "docs/design.md",                        # (pre-existing exclusion — pinned here too)
    ],
)
def test_reference_in_an_excluded_path_is_not_flagged(tmp_path, rel):
    """`defender/fixtures-e2e` and `defender/lessons-environment` are the near-misses: the
    match is `rel == d or rel.startswith(d + "/")`, so excluding `defender/fixtures` never
    covered `defender/fixtures-e2e`.

    The control below is what makes this test mean anything: the SAME text at a
    non-excluded path must be flagged, so a pass here is the exclusion doing the work and
    not some other filter."""
    up = _upstream(tmp_path, main_files={rel: "mentions some_removed_helper()\n"})
    work = _clone(tmp_path, up)

    hits = {f.fingerprint for f in GATE._scan(work, "origin/main")}
    # A scan that computed NOTHING would satisfy the exclusion assertion vacuously — the
    # #618 failure passing itself off as a pass. Pin that the scan ran first.
    assert "caller.py:some_removed_helper" in hits, "the scan found nothing at all"
    assert not any(h.startswith(rel) for h in hits), f"{rel} should be excluded"


def test_the_same_reference_at_a_non_excluded_path_IS_flagged(tmp_path):
    """Control for the parametrized exclusion test above."""
    up = _upstream(tmp_path, main_files={"src/notes.md": "mentions some_removed_helper()\n"})
    work = _clone(tmp_path, up)

    hits = {f.fingerprint for f in GATE._scan(work, "origin/main")}
    assert "src/notes.md:some_removed_helper" in hits


def test_frontmatter_name_is_a_declaration_but_the_body_is_a_reference(tmp_path):
    """A skill keeps its own `name:` after the like-named shim is deleted. That line is a
    declaration. The rule is LINE-scoped, so an instruction in the same file that still
    tells the model to RUN the dead command must still go red — otherwise the rule would
    whitelist exactly the bug the gate exists to catch."""
    up = _upstream(tmp_path)
    _git(up, "checkout", "-q", "main")
    _write(up, "bin/defender-elastic", "#!/bin/sh\n")
    _write(
        up, "skills/elastic/SKILL.md",
        "---\nname: defender-elastic\n---\n\nRun defender-elastic esql 'FROM x' to query.\n",
    )
    _commit(up, "add the shim and its skill")
    _git(up, "checkout", "-q", "pr")
    _git(up, "merge", "-q", "main", "-m", "merge")
    _git(up, "rm", "-q", "bin/defender-elastic")
    _commit(up, "delete the shim")
    work = _clone(tmp_path, up)

    displays = [f.display for f in GATE._scan(work, "origin/main")
                if "defender-elastic" in f.fingerprint]
    assert displays, "the body instruction must still be flagged"
    assert all("name: defender-elastic" not in d for d in displays), \
        "the frontmatter declaration must not be flagged"
    assert any("esql" in d for d in displays)


def test_a_parameter_named_like_the_removed_ident_is_a_declaration(tmp_path):
    """`def cmd_health_check(config, _args: Any)` declares a local. Its collision with some
    deleted module-level `_args` means nothing — the parameter is not a reference."""
    up = _upstream(
        tmp_path,
        main_files={
            "sig.py": "def cmd_health_check(cfg: dict, some_removed_helper: int) -> int:\n"
                      "    return 0\n",
        },
        pr_files={"caller.py": None},
    )
    work = _clone(tmp_path, up)

    assert _run_gate(work, tmp_path) == 0


def test_a_default_VALUE_in_a_signature_is_still_a_real_reference(tmp_path):
    """The boundary of the rule above. `def f(x=some_removed_helper())` CALLS the dead
    symbol — it sits in a value slot, not a parameter slot, and must still go red."""
    up = _upstream(
        tmp_path,
        main_files={"sig.py": "def f(x=some_removed_helper()):\n    return x\n"},
        pr_files={"caller.py": None},
    )
    work = _clone(tmp_path, up)

    assert _run_gate(work, tmp_path) == 1
    assert {f.fingerprint for f in GATE._scan(work, "origin/main")} == {
        "sig.py:some_removed_helper"
    }


def test_a_MULTILINE_signature_parameter_does_not_whitelist_the_IDENT(tmp_path):
    """The same parameter, reflowed onto its own line, must stay a line-scoped declaration.

    Textually it is now a bare `some_removed_helper,` — character-for-character what a
    multi-line import member looks like — so a text rule that reads one as a BINDING reads
    the other as one too, and the ident drops out of the whole scan: every surviving
    reference to it, anywhere in the tree, goes quiet. That is the ident-scoped whitelist
    the gate must never have. The AST knows a parameter from an import."""
    up = _upstream(
        tmp_path,
        main_files={
            "sig.py": "def cmd(\n    cfg: dict,\n    some_removed_helper,\n) -> int:\n"
                      "    return 0\n",
            "notes.md": "Run some_removed_helper() to fix things.\n",
        },
        pr_files={"caller.py": None},
    )
    work = _clone(tmp_path, up)

    assert _run_gate(work, tmp_path) == 1
    assert {f.fingerprint for f in GATE._scan(work, "origin/main")} == {
        "notes.md:some_removed_helper"  # the parameter itself is still not a reference
    }


def test_a_bare_name_on_its_own_line_is_a_REFERENCE_not_a_binding(tmp_path):
    """`HANDLERS = [\\n    some_removed_helper,\\n]` reads as a dead symbol in a list — a
    NameError waiting to happen — not as a definition of one. Same bare-`name,` text as the
    import member above; only the AST separates them."""
    up = _upstream(
        tmp_path,
        main_files={"reg.py": "HANDLERS = [\n    some_removed_helper,\n]\n"},
        pr_files={"caller.py": None},
    )
    work = _clone(tmp_path, up)

    assert _run_gate(work, tmp_path) == 1
    assert {f.fingerprint for f in GATE._scan(work, "origin/main")} == {
        "reg.py:some_removed_helper"
    }


def test_a_reflowed_multiline_IMPORT_still_counts_as_defined(tmp_path):
    """The control for the two above, and the reason the bare-`name,` rule existed: a
    surviving import of the symbol means it was moved or re-exported, not removed. Still
    ident-scoped, still green."""
    up = _upstream(
        tmp_path,
        main_files={"reexport.py": "from mod import (\n    some_removed_helper,\n)\n"},
    )
    work = _clone(tmp_path, up)

    assert _run_gate(work, tmp_path) == 0
    assert GATE._scan(work, "origin/main") == []


def test_a_reference_inside_a_default_VALUE_expression_is_flagged(tmp_path):
    """The default-value boundary again, one level deeper: the dead symbol is an ARGUMENT
    inside the default, not the callee. `def f(x=compute(<ident>))` sits after a `(` exactly
    like a parameter does, so the position of the nearest bracket cannot decide this."""
    up = _upstream(
        tmp_path,
        main_files={"sig.py": "def f(x=compute(some_removed_helper)):\n    return x\n"},
        pr_files={"caller.py": None},
    )
    work = _clone(tmp_path, up)

    assert _run_gate(work, tmp_path) == 1
    assert {f.fingerprint for f in GATE._scan(work, "origin/main")} == {
        "sig.py:some_removed_helper"
    }


def test_a_declaration_does_not_mask_another_dead_ident_on_the_SAME_line(tmp_path):
    """One line can declare one dead name and CALL another. Attribution stops at the first
    ident the line references — a declaration is skipped, not treated as the line's answer,
    or the second name (which really is stale) is never looked for."""
    up = _upstream(
        tmp_path,
        main_files={
            "mod2.py": "def a_removed_helper():\n    return 2\n",
            "sig.py": "def f(a_removed_helper, x=some_removed_helper()):\n    return x\n",
        },
        pr_files={"mod2.py": None, "caller.py": None},  # both defs deleted by the PR
    )
    work = _clone(tmp_path, up)

    assert _run_gate(work, tmp_path) == 1
    assert {f.fingerprint for f in GATE._scan(work, "origin/main")} == {
        "sig.py:some_removed_helper"  # `a_removed_helper` on that line is the parameter
    }


def test_inline_marker_suppresses_a_deliberate_dead_name_reference(tmp_path):
    """A negative-assertion test names the dead command ON PURPOSE — to prove it is
    denied. Deleting the name would delete the test's meaning, so it gets a marker."""
    marked = (
        "def test_the_dead_cli_is_denied():\n"
        "    assert not decide_bash(\n"
        "        'some_removed_helper x'  # lint-stale-ref: ok — negative assertion\n"
        "    )\n"
    )
    unmarked = "def test_other():\n    assert not decide_bash('some_removed_helper x')\n"
    up = _upstream(
        tmp_path,
        main_files={"t_deny.py": marked, "t_plain.py": unmarked},
        pr_files={"caller.py": None},
    )
    work = _clone(tmp_path, up)

    # The marker suppresses its own line and ONLY its own line.
    hits = {f.fingerprint for f in GATE._scan(work, "origin/main")}
    assert hits == {"t_plain.py:some_removed_helper"}


def test_the_baseline_file_cannot_be_its_own_finding(tmp_path):
    """The baseline necessarily spells the identifiers it tolerates, so it greps as a
    surviving reference to each. A gate must not be able to find itself."""
    rel = "scripts/lint/lint_stale_refs_baseline.json"
    # The baseline lives INSIDE the repo and on `main` (as it really does), spelling the
    # ident it tolerates — so it greps as a surviving reference to it.
    up = _upstream(tmp_path, main_files={
        rel: json.dumps({"//": "h", "entries": {"caller.py:some_removed_helper": "tolerated"}}),
    })
    work = _clone(tmp_path, up)
    inside = work / rel

    # Control: without the self-exclusion the baseline reports itself.
    assert f"{rel}:some_removed_helper" in {
        f.fingerprint for f in GATE._scan(work, "origin/main")
    }
    # With it, the gate cannot find itself.
    findings = GATE._scan(
        work, "origin/main", exclude_files=GATE._self_reference(inside, work)
    )
    assert not any(f.fingerprint.startswith(rel) for f in findings)
