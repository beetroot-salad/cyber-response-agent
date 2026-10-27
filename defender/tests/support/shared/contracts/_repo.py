"""The throwaway git repo the author/curator suites build, and the two ways they read it."""
from __future__ import annotations

import atexit
import shutil
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path

from defender import _git


#: Directory names a real filesystem and git accept and a naive reader gets wrong; each is a
#: class that has silently un-declared a system in this repo (#869):
#:
#:   "café"      non-ASCII: C-QUOTED by `git ls-tree --name-only` (quotes included), so a
#:               suffix test such as "ends in `/execution.md`" answers no.
#:   "my sys"    a space: NOT quoted, so a `.split()` of the listing TEARS it into two paths,
#:               the second well-formed at the wrong depth.
#:   'say"what'  a double quote: C-quoted too, and breaks any shell or pathspec concatenation.
#:
#: Quoting and tearing are independent: only `-z` READ as NUL-delimited handles all three
#: (git 2.47.3, default `core.quotePath=true`). `it's` is left out: it breaks neither reader.
HOSTILE_NAMES: tuple[str, ...] = ("café", "my sys", 'say"what')

_TEMPLATES: dict[str, Path] = {}


def build_once_copy(key: str, build: Callable[[Path], object], dest: Path) -> Path:
    """`build(dest)`'s tree at `dest`, built for real once per process and copied after.

    A seeded git repo costs six git children and most callers assert only on what they do to
    it, so each gets a byte-for-byte copy (links kept, `.git` included: a `git init` repo holds
    no path of its own) of the template built the first time `key` is asked for. `build` must
    put the same tree at any `dest`.
    """
    template = _TEMPLATES.get(key)
    if template is None:
        root = Path(tempfile.mkdtemp(prefix="repo-template-"))
        atexit.register(shutil.rmtree, root, ignore_errors=True)
        template = root / "repo"
        build(template)
        _TEMPLATES[key] = template
    # `*.lock` is skipped: git's background maintenance takes and drops `objects/maintenance.lock`
    # in the template while it is being read, and a lock file is never part of a repo's content.
    shutil.copytree(template, dest, symlinks=True, dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("*.lock"))
    return dest


def plant_named_dirs(
    parent: Path, names: tuple[str, ...] = HOSTILE_NAMES, *, filename: str = "execution.md"
) -> tuple[str, ...]:
    """Create `parent/<name>/<filename>` for each name; return the names, for the assertion.

    Returning the input is the point: the caller asserts against the names it PLANTED, never a
    second reading of the tree with the listing under test, an oracle that cannot disagree
    (#869; `tooling/lint/lint_shared_oracle.py` refuses that shape).
    """
    for name in names:
        d = parent / name
        d.mkdir(parents=True, exist_ok=True)
        (d / filename).write_text(f"# {name}\n", encoding="utf-8")
    return names


def seed_repo(
    repo: Path,
    *,
    add: str = "-A",
    message: str = "seed",
    email: str = "t@t",
    name: str = "t",
) -> Path:
    """`repo` becomes a git repo on `main` with one commit. Returns it, for chaining.

    Call it AFTER building the tree the test needs: that first commit is the thing under test.
    `add="README"` commits a one-line README instead of the tree, for suites whose subject is
    an uncommitted-corpus starting state.

    The identity is set per-repo rather than inherited: a contributor's global `user.email`
    would otherwise land in fixture commits, and two suites assert on commit trailers.
    """
    repo.mkdir(parents=True, exist_ok=True)
    _git.git(["init", "-q", "-b", "main"], cwd=repo)
    _git.git(["config", "user.email", email], cwd=repo)
    _git.git(["config", "user.name", name], cwd=repo)
    if add == "README":
        (repo / "README").write_text("seed\n", encoding="utf-8")
    _git.git(["add", add], cwd=repo)
    _git.git(["commit", "-q", "-m", message], cwd=repo)
    return repo


#: The stub adapter the seeded tree ships, so the fixture's `wazuh` really DECLARES verbs: the
#: commit gate resolves a promoted template's verb (and the `SKILL.md` identity rule) against
#: the tree's ADAPTERS, so a catalog with no adapter is a tree the real gate would refuse.
_WAZUH_ADAPTER = '''\
from __future__ import annotations

from defender.kit.verbs import VerbContext, verb


@verb()
def search(ctx: VerbContext, *, index: str = "", window: str = "24h") -> dict:
    return {"rows": []}


@verb()
def health_check(ctx: VerbContext) -> dict:
    return {"ok": True}


VERBS = {"search": search, "health-check": health_check}
'''


def seed_adapter_stubs(defender_dir: Path, systems: tuple[str, ...]) -> tuple[str, ...]:
    """Declare `systems` in `defender_dir`'s tree; return the names."""
    from defender.tests.support.runtime.engine._declared869 import ADAPTER_BODY, adapter_file

    adapters = defender_dir / "integrations"
    adapters.mkdir(parents=True, exist_ok=True)
    for system in systems:
        (adapters / adapter_file(Path("."), system).name).write_text(
            ADAPTER_BODY, encoding="utf-8"
        )
    return systems


def query_template(
    tid: str, status: str, *, body: str = "", covers: Sequence[str] = ()
) -> str:
    """A well-formed query template for the seeded `wazuh` system.

    A writer, never an oracle: one place spells the shape the content gate accepts. Pass
    `body` to stage a MALFORMED one on purpose, and `covers` for a file that accounts for
    coined `query_id`s.
    """
    query = body or "```query\nverb: search\nparams:\n  index: ${index}\n```"
    covers_line = f"covers: [{', '.join(covers)}]\n" if covers else ""
    return (
        f"---\nid: {tid}\nstatus: {status}\nverb: search\nparams: [index]\n{covers_line}---\n\n"
        f"## Goal\n\nwazuh auth events.\n\n## Query\n\n{query}\n"
    )


def seed_skills_repo(repo: Path) -> Path:
    """`_seed_skills_repo`'s tree at `repo` (built once per process, then copied)."""
    return build_once_copy("seed_skills_repo", _seed_skills_repo, repo)


def _seed_skills_repo(repo: Path) -> Path:
    """A committed skills tree standing in for a fresh ``lead-author/<id>`` worktree.

    An established template, a draft template, a skill with a surface declaration and a
    pending draft under it: the lead-author and pitfalls-curator suites both make working-tree
    edits over this clean HEAD and drive the loop's gate.
    """
    adapters = repo / "defender" / "integrations"
    adapters.mkdir(parents=True)
    # wazuh gets the real adapter shape: it owns every seeded catalog template, so the content
    # gate resolves its verbs. elastic owns no template and only has to EXIST, so that
    # `declared_systems` counts it.
    (adapters / "wazuh_adapter.py").write_text(_WAZUH_ADAPTER)
    (adapters / "elastic_adapter.py").write_text("VERBS = {}\n")
    catalog = repo / "defender" / "skills" / "gather" / "queries"
    (catalog / "wazuh" / "_draft").mkdir(parents=True)
    (catalog / "SCHEMA.md").write_text("# template schema\n")
    (catalog / "wazuh" / "auth-events.md").write_text(
        query_template("wazuh.auth-events", "established")
    )
    (catalog / "wazuh" / "_draft" / "newthing.md").write_text(
        query_template("wazuh.newthing", "draft")
    )
    skill = repo / "defender" / "skills" / "elastic"
    (skill / "_draft").mkdir(parents=True)
    (skill / "SKILL.md").write_text("---\nname: defender-elastic\n---\n# elastic\n")
    (skill / "_draft" / "README.md").write_text("# surface declaration\n")
    (skill / "_draft" / "falco-na.md").write_text(
        "---\nid: elastic.falco-na\nstatus: draft\n---\n# pending\n"
    )
    return seed_repo(repo, email="test@example.com", name="Test")


def head_files(repo: Path) -> list[str]:
    """Paths touched by HEAD (`git show --name-only`)."""
    return _git.git(
        ["show", "--name-only", "--pretty=format:", "HEAD"], cwd=repo
    ).split()


def head_message(repo: Path, *, path: str | None = None) -> str:
    """HEAD's full commit message, or that of the last commit touching `path`.

    The `path` form is not the same question: it answers "what did the commit that last
    touched this file say", which is what the per-corpus provenance assertions need when
    a run commits to more than one corpus.
    """
    args = ["log", "-1", "--pretty=%B"]
    args += ["--", path] if path is not None else ["HEAD"]
    return _git.git(args, cwd=repo)
