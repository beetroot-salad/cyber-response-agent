"""#1108 P4 slice S-D — O7: every corpus write goes through `TenantDelivery`. One row per writer
O7 names, each observed where it lands: the tenant repo (a commit-maker branch + PR on the tenant
forge), never the product repo.

Writers and how each row reaches it:
  - lessons author, questioner author: behavioural, through the real drain
    (`author_drain`) with the real curator and only its model spawn faked (test_drains.py's
    `CuratorTrigger`); the lesson lands under `agent/lessons/` / `agent/lessons-questioner/`.
  - curators' corpus repair (the post-spawn restore of unapproved files), lead author, draft
    synthesis, pitfalls: today each commits through the product worktree (`ClaimGit`,
    `commit_corpus_paths`, `git checkout --` in the batch worktree). Their behavioural rows need
    the lead lane's run/adapter scaffolding and are left to the implementation check (reported);
    here they are held by the census below: no production module references the legacy commit
    and delivery machinery any more, so none of them can commit or push but through P3.
  - revert: test_revert_cli.py. Connect's tenant half: test_connect_propose.py.
  - the evals harness: drives the author against a draft with the drain tests' fake forge, no
    issuer, no network (`evaluations/harness.py`, tested from here, never edited).

ASSUMED SEAM (reported): `evaluations/harness.py::run_author(tmp, *, invoke_agent=None)` — the
author's model spawn, injectable; `materialize(scenario, tmp)` sets up everything the run needs
(the tenant repo, its draft and fake forge included).
"""
from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from defender._git import REPO_ROOT
from defender.tests.support.learning.curation import _spec773 as S
from defender.tests.tenancy.tenant_1108_p4._support import DEFENDER, bind_forge, git
from defender.tests.tenancy.tenant_1108_p4.test_drains import (
    BoxSpy,
    CuratorTrigger,
    author_drain,
    critical_text,
    drain_paths,
    product_repo,
    product_state,
    queue,
    remote_branches,
    touched,
)

EVALUATIONS = REPO_ROOT / "evaluations"


# ---------------------------------------------------------------------------------------------
# Behavioural rows: the two corpus authors of the author lane
# ---------------------------------------------------------------------------------------------

_ROWS = {
    # writer: (curator module the drain triggers, queue channel, row, corpus under agent/)
    "lessons-author": ("author", "findings", S.finding_row("f1", run_id="f1"), "lessons"),
    "questioner-author": ("questioner_curator", "questioner_findings",
                          S.world_row("w1", systems=["cmdb"]), "lessons-questioner"),
}


@pytest.mark.parametrize("writer", sorted(_ROWS))
def test_o7_each_author_lane_writer_lands_in_the_tenant_repo_and_nowhere_in_the_product_repo(
        p4_tenant, tmp_path, monkeypatch, caplog, writer):
    """O7: the writer's lesson is a commit on a `lessons/` branch of the tenant origin touching
    only `agent/<its corpus>/<lesson>`, with a PR on the tenant forge; the product checkout the
    drain runs over is unchanged (positive control in test_drains' flow-4 case)."""
    from defender.learning.core.state import FINDINGS, QUESTIONER_FINDINGS

    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    monkeypatch.setenv("LEARNING_QUESTIONER_THRESHOLD", "1")
    module, channel, row, corpus = _ROWS[writer]
    t = p4_tenant
    bind_forge(t)
    product = product_repo(tmp_path)
    paths = drain_paths(t, product)
    queue(paths, [row], channel={"findings": FINDINGS, "questioner_findings": QUESTIONER_FINDINGS}[channel])
    before = product_state(product)
    curator = S.FakeCurator(writes={"p4-writer.md": S.lesson(row["finding_id"])})
    trigger, box = CuratorTrigger(**{module: curator}), BoxSpy()
    main = t.origin_main()

    rc = author_drain(t, paths, trigger=trigger, box=box)

    assert rc == 0, critical_text(caplog)
    assert curator.calls, f"{writer}'s model step never ran"
    (branch, tip), = remote_branches(t.remote).items()
    assert touched(t.remote, main, tip) == [f"agent/{corpus}/p4-writer.md"]
    assert [c["head"] for c in t.forge.creates] == [branch]
    assert product_state(product) == before


# ---------------------------------------------------------------------------------------------
# Census: no production module keeps the legacy commit/delivery machinery
# ---------------------------------------------------------------------------------------------

#: Names whose any reference in production code is a writer committing or delivering outside
#: P3's commit-maker: the legacy product-repo delivery (`AuthorBranch`, `GhForge`,
#: its revert, the worktree batch) and the per-claim worktree commits (`ClaimGit`, the corpus
#: commit helpers, worktree creation).
LEGACY_REFERENCES = frozenset({
    "AuthorBranch", "GhForge", "ClaimGit", "revert_lesson_pr",
    "_run_worktree_batch", "finish_batch", "commit_corpus", "commit_corpus_paths",
    "git_commit_paths", "git_worktree_add",
})
#: Of those, the classes and the batch whose very definition must be gone (O7: "deleted").
LEGACY_DEFINITIONS = frozenset({"AuthorBranch", "GhForge", "ClaimGit", "_run_worktree_batch"})


def legacy_hits(source: str, filename: str = "<src>") -> list[tuple[int, str, str]]:
    """`(line, name, how)` for every reference to a `LEGACY_REFERENCES` name (a bare name, an
    attribute, an import) and every definition of a `LEGACY_DEFINITIONS` name in `source`."""
    hits = []
    for node in ast.walk(ast.parse(source, filename)):
        if isinstance(node, ast.Name) and node.id in LEGACY_REFERENCES:
            hits.append((node.lineno, node.id, "ref"))
        elif isinstance(node, ast.Attribute) and node.attr in LEGACY_REFERENCES:
            hits.append((node.lineno, node.attr, "ref"))
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            hits += [(node.lineno, a.name.rsplit(".", 1)[-1], "import") for a in node.names
                     if a.name.rsplit(".", 1)[-1] in LEGACY_REFERENCES]
        elif (isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
              and node.name in LEGACY_DEFINITIONS):
            hits.append((node.lineno, node.name, "def"))
    return hits


def _production_sources() -> list[Path]:
    tests = DEFENDER / "tests"
    return sorted([p for p in DEFENDER.rglob("*.py")
                   if not p.is_relative_to(tests) and ".venv" not in p.parts
                   and "__pycache__" not in p.parts]
                  + [p for p in EVALUATIONS.rglob("*.py") if "_tmp" not in p.parts])


def test_o7_census_scanner_finds_each_kind_of_legacy_spelling():
    """Positive control for the census below: an import, a call through `_git`, an attribute
    call and a class definition are each found; the P3 commit-maker's names are not."""
    src = (
        "from defender.learning.author.branch import AuthorBranch\n"   # 1
        "from defender import _git\n"
        "_git.git_commit_paths(root, [], [], 'm')\n"                    # 3
        "branch.finish_batch(batch_id, wt)\n"                           # 4
        "class GhForge:\n    pass\n"                                    # 5
        "batch.commit(change_set, 'm'); delivery.finish(batch)\n"
    )
    assert sorted(legacy_hits(src)) == [(1, "AuthorBranch", "import"),
                                        (3, "git_commit_paths", "ref"),
                                        (4, "finish_batch", "ref"), (5, "GhForge", "def")]


def test_o7_no_production_writer_commits_or_delivers_outside_the_tenant_commit_maker():
    """O7: `GhForge`, `AuthorBranch`'s product path, the legacy worktree drain and the per-claim
    worktree commits are gone from production code (`defender/` outside `tests/`, and
    `evaluations/`): no definition, import or reference remains, so the lead author, draft
    synthesis, pitfalls, corpus repair and every curator can reach git only through P3's
    `TenantDelivery` (`Batch.commit`, `finish`, `deliver`, `revert`)."""
    hits = []
    for path in _production_sources():
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        hits += [f"{path.relative_to(REPO_ROOT)}:{line}: {name} ({how})"
                 for line, name, how in legacy_hits(source, str(path))]
    assert hits == [], "legacy commit/delivery machinery remains:\n" + "\n".join(hits)


# ---------------------------------------------------------------------------------------------
# The evals harness: the author against a draft, a fake forge, no issuer, no network
# ---------------------------------------------------------------------------------------------

_HARNESS_RUN = """
import json, sys
from pathlib import Path
evals, scenario, scratch = (Path(a) for a in sys.argv[1:4])
sys.path.insert(0, str(evals))
import harness
from defender.tests.support.learning.curation._spec773 import FakeCurator, lesson
curator = FakeCurator(writes={"harness-lesson.md": lesson("f1")})
harness.materialize(scenario, scratch)
run, _wall = harness.run_author(scratch, invoke_agent=curator)
print(json.dumps({"rc": run.returncode, "stderr": run.stderr, "spawned": len(curator.calls)}))
"""


def _repositories(root: Path) -> list[Path]:
    """Every git repository under `root`: a work tree's `.git` and a bare repo's directory."""
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        if ".git" in dirnames or ".git" in filenames:
            found.append(here)
        elif {"HEAD", "objects", "refs"} <= set(filenames) | set(dirnames):
            found.append(here)
            dirnames.clear()
    return found


def test_o7_the_evals_harness_authors_into_a_tenant_draft_with_a_fake_forge_and_no_issuer(tmp_path):
    """O7 (evals): the harness drives the real lessons author against a draft, its commit landing
    on a tenant-shaped repo (`agent/lessons/<lesson>`) delivered to a fake forge, with no issuer
    configured and nothing written under a product-shaped `defender/lessons/` or `.worktrees/`.
    The model spawn is the only fake (assumed seam `run_author(tmp, *, invoke_agent=)`)."""
    scenario = tmp_path / "scenario"
    scenario.mkdir()
    (scenario / "findings.jsonl").write_text(
        json.dumps(S.finding_row("f1", run_id="f1")) + "\n", encoding="utf-8")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    env = {k: v for k, v in os.environ.items() if k in ("PATH", "LANG", "LC_ALL", "HOME")}
    env.update(PYTHONPATH=str(REPO_ROOT), PYTHONDONTWRITEBYTECODE="1",
               GIT_CONFIG_NOSYSTEM="1", GIT_AUTHOR_NAME="evals", GIT_AUTHOR_EMAIL="e@test.invalid",
               GIT_COMMITTER_NAME="evals", GIT_COMMITTER_EMAIL="e@test.invalid")

    proc = subprocess.run([sys.executable, "-c", _HARNESS_RUN, str(EVALUATIONS), str(scenario),
                           str(scratch)], env=env, capture_output=True, text=True, timeout=300,
                          check=False)

    assert proc.returncode == 0, proc.stderr[-4000:]
    run = json.loads(proc.stdout.strip().splitlines()[-1])
    assert run["rc"] == 0, run
    assert run["spawned"] == 1, run
    touched_paths = set()
    for repo in _repositories(scratch):
        if not git(repo, "for-each-ref", "--format=%(refname)"):
            continue  # a repository with no commit yet holds no landing
        log = git(repo, "log", "--all", "--no-renames", "--name-only", "--format=")
        touched_paths |= {line for line in log.splitlines() if line}
    assert "agent/lessons/harness-lesson.md" in touched_paths, sorted(touched_paths)
    assert not [p for p in touched_paths if p.startswith("defender/lessons")], sorted(touched_paths)
    assert not list(scratch.rglob(".worktrees")), "a product-repo worktree was cut"
    assert not (scratch / "defender" / "lessons").exists()
