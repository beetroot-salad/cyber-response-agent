"""The throwaway git repo the author/curator suites build, and the two ways they read it.

Git is local and deterministic, so this tree exercises it for real rather than faking it
(`test_git.py`'s philosophy). The cost was that "make a repo with a seed commit" had been
hand-rolled at fourteen sites under five different placeholder identities, each spelling
its own `subprocess.run(["git", ...])` — which also meant fourteen sites outside the
`defender/_git.py` seam that owns git invocation everywhere else.

The seed differs in one real way between callers and that difference is a parameter, not
drift: some suites want the corpus tree they just built committed (`add="-A"`), others
want an empty first commit with only a `README` in it so their corpus dir shows up as an
untracked working-tree change (`add="README"`). Both are load-bearing for the suite that
picked them.

Underscore-prefixed so pytest does not collect it; it defines no tests.
"""
from __future__ import annotations

from pathlib import Path

from defender import _git


#: Directory names a real filesystem and a real git accept, and a naive reader gets wrong.
#: NOT decoration — each entry is a CLASS that has silently un-declared a system in this repo
#: (#869/#908), and the tuple is the corpus a `spec-graph claims` `alphabet:` is answered with:
#:
#:   "café"      non-ASCII. C-QUOTED by `git ls-tree --name-only`: the entry arrives as
#:               `"defender/skills/caf\303\251/execution.md"`, quotes included, so it no
#:               longer ends in `/execution.md` and every suffix test on it answers no.
#:   "my sys"    a space. NOT quoted — a `.split()` of the listing TEARS it into
#:               `defender/skills/my` and `sys/execution.md`, and the second half is a
#:               well-formed path that a suffix test happily accepts at the wrong depth.
#:   'say"what'  a double quote. C-quoted like the non-ASCII case, and the classic breaker of
#:               any reader that re-enters a shell or builds a pathspec by concatenation.
#:
#: The two mechanisms are INDEPENDENT, which is why the corpus carries both: `-z` alone fixes
#: the quoting and not the tearing, a NUL split alone fixes the tearing and not the quoting.
#: Only `-z` READ as NUL-delimited answers for all three. Measured on git 2.47.3 with the
#: default `core.quotePath=true`; `test_hostile_names.py` is the executed probe and re-grounds
#: this comment on every run. Deliberately NOT in the corpus: `it's` (a single quote is not
#: quoted and contains no whitespace, so it breaks neither reader and only pads the fixture).
#:
#: A tree reader that answers correctly over these three answers correctly over the names
#: models and humans actually choose. One that is only ever handed `elastic` has not been
#: probed — it has been agreed with.
HOSTILE_NAMES: tuple[str, ...] = ("café", "my sys", 'say"what')


def plant_named_dirs(
    parent: Path, names: tuple[str, ...] = HOSTILE_NAMES, *, filename: str = "execution.md"
) -> tuple[str, ...]:
    """Create `parent/<name>/<filename>` for each name; return the names, for the assertion.

    Returning the input is the point, not a convenience: the caller asserts against the names
    it PLANTED, never against a second reading of the tree. An oracle that re-derives the
    expected set with the same listing the code under test runs cannot disagree with it —
    which is how #869's three misreads passed 57 tests — and `scripts/lint/lint_shared_oracle.py`
    now refuses the shape at the gate.
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

    Call it AFTER building whatever tree the test needs — every caller does, because what
    is in that first commit is the thing under test. `add="README"` writes and commits a
    one-line README instead of the tree, for suites whose subject is an
    uncommitted-corpus starting state.

    The identity is set per-repo rather than inherited: a contributor's global
    `user.email` would otherwise land in fixture commits, and two of these suites assert
    on commit trailers.
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


#: The stub adapter the seeded tree ships, so the fixture's `wazuh` is a system that really
#: DECLARES verbs. Since #901 the loop's commit gate resolves a promoted template's verb — and
#: the per-system `SKILL.md` identity rule — against the ADAPTERS of the tree it is committing,
#: so a seed with a catalog and no adapter is not a cheaper fixture — it is a tree the real gate
#: would refuse, and every test built on it would be asserting about a repo the loop cannot
#: produce.
_WAZUH_ADAPTER = '''\
from __future__ import annotations

from defender.runtime.verbs import VerbContext, verb


@verb()
def search(ctx: VerbContext, *, index: str = "", window: str = "24h") -> dict:
    return {"rows": []}


@verb()
def health_check(ctx: VerbContext) -> dict:
    return {"ok": True}


VERBS = {"search": search, "health-check": health_check}
'''


def seed_adapter_stubs(defender_dir: Path, systems: tuple[str, ...]) -> tuple[str, ...]:
    """Declare `systems` in `defender_dir`'s tree; return the names.

    THE way a synthetic worktree declares its systems, now that the lead author's WRITE gate
    reads `declared_systems.adapter_declared_systems` the way its commit gate reads
    `declared_systems` (#772). A tree with a `skills/elastic/` and no `elastic_adapter.py` is
    not a cheaper fixture — it is a tree in which `elastic` is not a system, so `bind` compiles
    no per-system write lane there and refuses outright.

    Borrows `_declared869`'s FILENAME rule (`.name` off `adapter_file`) rather than copying
    it: that module owns the inverse of `verbs._system_of` — a hyphenated system is an
    underscored file — and a second copy of that mapping is a fixture that can silently declare
    a system nobody asked for. What it does NOT borrow is that helper's rooting, which starts
    from a repo root; this writes under the `defender_dir` it was handed, so a tree that is not
    literally named `defender` declares its own systems instead of a sibling's (the same
    footgun `_systems_or_raise` closes on the production side, #772).

    Returning the input is the point, the same reason `plant_named_dirs` does: the caller
    asserts against the systems it DECLARED, never against a second reading of the adapters
    dir with the glob the code under test runs (`scripts/lint/lint_shared_oracle.py`).
    """
    from defender.tests._declared869 import ADAPTER_BODY, adapter_file

    adapters = defender_dir / "scripts" / "adapters"
    adapters.mkdir(parents=True, exist_ok=True)
    for system in systems:
        (adapters / adapter_file(Path("."), system).name).write_text(
            ADAPTER_BODY, encoding="utf-8"
        )
    return systems


def query_template(tid: str, status: str, *, body: str = "") -> str:
    """A well-formed query template for the seeded `wazuh` system.

    A writer, never an oracle: tests that stage a promotion need a file the content gate
    accepts, and hand-spelling that shape at each site is how a fixture drifts from the schema
    it is standing in for. Pass `body` to stage a MALFORMED one on purpose.
    """
    query = body or "```query\nverb: search\nparams:\n  index: ${index}\n```"
    return (
        f"---\nid: {tid}\nstatus: {status}\nverb: search\nparams: [index]\n---\n\n"
        f"## Goal\n\nwazuh auth events.\n\n## Query\n\n{query}\n"
    )


def seed_skills_repo(repo: Path) -> Path:
    """A committed skills tree standing in for a fresh ``lead-author/<id>`` worktree.

    Both the lead-author and the pitfalls-curator suites need exactly this starting
    state — an established template, a draft template, a skill with a surface
    declaration, and a pending draft under it — because both subjects run no git and are
    asserted on by making *working-tree* edits over a clean HEAD and driving the loop's
    gate. The two fixtures that built it were byte-identical apart from their docstrings,
    which is the one part that should differ: each names its own subject. Those stay with
    their fixtures.
    """
    adapters = repo / "defender" / "scripts" / "adapters"
    adapters.mkdir(parents=True)
    # wazuh gets the real adapter shape (#901): it owns every seeded catalog template, so the
    # content gate resolves its verbs. elastic owns no template here and only has to EXIST, so
    # that `declared_systems` counts it among the declared systems (#869).
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
    """Paths touched by HEAD — the `show --name-only` five suites spell by hand."""
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
