"""The executed alphabet probe behind `_repo.HOSTILE_NAMES`, kept green so it cannot rot.

`spec-graph claims`' probe-corpus pass asks a name-enumerating probe what alphabet it
sampled. This module is the answer's evidence: it runs the two committed-tree listings a
reader can choose from over a tree holding the hostile names, and pins which one survives
them. Without it, "we sampled non-ASCII" is a sentence in a YAML file; with it, the claim is
a test that fails the day git, the filesystem or the locale stops behaving as recorded.

It also pins the fixture itself. `plant_named_dirs` is only worth handing to other suites if
the names it plants actually reach a commit intact on the platform the suite runs on — a
filesystem that normalized `café`, or a git that refused it, would make every downstream
"hostile" assertion vacuously green.

The expectation everywhere below is the tuple the test PLANTED. Nothing here re-derives the
answer from a second listing, which is the whole discipline `lint_shared_oracle` enforces.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from defender.tests import _repo


def _skills_dir(tmp_path: Path) -> Path:
    d = tmp_path / "defender" / "skills"
    d.mkdir(parents=True)
    return d


def _ls_tree(repo: Path, *flags: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "ls-tree", "-r", *flags, "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout


def test_every_hostile_name_survives_a_commit_and_a_nul_delimited_listing(tmp_path):
    """The corpus is real: each planted name reaches HEAD and comes back byte-identical.

    `-z` is what makes that true. It turns off git's path quoting AND gives the reader a
    delimiter no path can contain, so the two failure modes (`café` arriving C-quoted, `my
    sys` arriving as two tokens) are both closed by the same flag.
    """
    skills = _skills_dir(tmp_path)
    planted = _repo.plant_named_dirs(skills)
    _repo.seed_repo(tmp_path)

    listed = [p for p in _ls_tree(tmp_path, "-z", "--name-only").split("\0") if p]

    assert sorted(listed) == sorted(
        f"defender/skills/{name}/execution.md" for name in planted
    )


def test_the_obvious_listing_loses_every_hostile_name(tmp_path):
    """The control, and the reason the corpus exists.

    `git ls-tree -r --name-only` + `.split()` is the obvious reader — it is what #869's spec
    recorded as an executed probe, what the implementation was transcribed from, and what the
    test that asserted on it computed its expectation with. Over an ASCII tree at the repo
    root it is correct, which is why nothing caught it. Over this tree, EVERY name is lost —
    but by two DIFFERENT mechanisms, which is the fact the corpus exists to keep visible:
    `café` and `say"what` arrive C-quoted and stop ending in `/execution.md`, while `my sys`
    is not quoted at all and is torn by the split into `…/my` and `sys/execution.md`. A reader
    that fixed only one of the two would still lose the other, and would still pass a suite
    whose fixtures are named `elastic`.

    Asserting the bug (rather than deleting the reader and moving on) is what keeps this a
    probe: if a future git stops quoting, this test fails and the recorded alphabet is
    re-grounded instead of quietly becoming folklore.
    """
    skills = _skills_dir(tmp_path)
    planted = _repo.plant_named_dirs(skills)
    _repo.seed_repo(tmp_path)

    naive = _ls_tree(tmp_path, "--name-only").split()
    recovered = {
        Path(p).parent.name for p in naive
        if p.endswith("/execution.md") and p.count("/") == 3
    }

    assert recovered == set()
    assert set(planted) - recovered == set(planted)


def test_the_depth_rule_is_derived_from_the_skills_path_not_a_literal(tmp_path):
    """A nested marker is not a declaration, and the depth that says so is not a magic 3.

    #869's spec recorded `p.count('/') == 3` as the observed output of its probe, and both the
    reader and its test took the literal — a constant that silently re-spells how many
    segments `defender/skills/` has. Planting one nested marker alongside the depth-1 ones
    pins the rule rather than the number: the count is derived from the prefix here, so a
    rename of the skills directory moves this assertion with it.
    """
    skills = _skills_dir(tmp_path)
    planted = _repo.plant_named_dirs(skills)
    nested = skills / "café" / "_draft" / "deeper"
    nested.mkdir(parents=True)
    (nested / "execution.md").write_text("# nested\n", encoding="utf-8")
    _repo.seed_repo(tmp_path)

    prefix = "defender/skills/"
    depth = prefix.count("/") + 1          # <prefix><name>/execution.md
    listed = [p for p in _ls_tree(tmp_path, "-z", "--name-only").split("\0") if p]
    at_depth = {
        Path(p).parent.name for p in listed
        if p.endswith("/execution.md") and p.count("/") == depth
    }

    assert at_depth == set(planted)
    assert "deeper" not in at_depth
