"""Substrate for the issue-869 executable spec (`spec-flow/specs/spec_graph_869.yaml`).

Pre-implementation. `defender.learning.leads.declared_systems` does NOT exist at the base
commit, and every seam listed below either does not exist or has a different signature — so
this suite is RED by construction. That is what a spec written before the code looks like.

**The seam contract this spec pins** (write-code-from-spec implements it). The graph's header
mints three of these names verbatim; the rest are the threading M2 demands, and a suite that
did not name them would leave the seam unpinned:

* `defender/learning/leads/declared_systems.py` — NEW, learning-side (FK-11), importing
  `ADAPTER_SUFFIX` / `_system_of` from `defender.runtime.verbs` at MODULE level (C27).
  - `declared_systems(repo_root: Path) -> frozenset[str]` — the ASYMMETRIC union (NF1):
    the adapter glob `<repo_root>/defender/scripts/adapters/*_adapter.py` read from the
    WORKING tree, unioned with the `<repo_root>/defender/skills/<name>/execution.md` marker
    read from the COMMITTED tree, at EXACTLY ONE directory of depth — `<name>` is the
    segment directly under `defender/skills/`, never a nested one. Either source
    unresolvable RAISES `LeadAuthorError` (`lead_extraction.LeadAuthorError`, which per J2
    must not be an `OSError` subclass). Both present and the union empty returns
    `frozenset()` plus one log line naming BOTH directories. Every emitted name has passed
    `verbs.is_system_name`, and each refusal is logged with the source it came from (FK-5).
  - `adapter_declared_systems(repo_root: Path) -> frozenset[str]` — NF2's SECOND
    RESOLUTION POINT, and the value the PITFALLS lane is handed: the adapter half ALONE.
    Named here because NF2 requires a different value at that lane and no input named the
    call that produces it (phase F's F4). Three properties ride on it and none of them is
    inherited from the union resolver: (a) it does NOT consult the marker source, so an
    unresolvable marker source is not its fault to raise — only an unresolvable ADAPTER
    source is; (b) emptiness is measured on the ADAPTER HALF, so a tree with committed
    markers and no adapters refuses the whole pitfalls lane while genuinely declaring
    systems; (c) it applies FK-5's `verbs.is_system_name` filter and logs one line per refusal
    naming the source, which is the only thing closing R6's log sink on this path.
  - the shape half is `runtime.verbs.is_system_name(name: str) -> bool` — #868's check, which
    #914 folded into the ONE system-name predicate the dispatch seam already had, so a name
    this resolver declares is a name `_adapter_path` will also resolve. Lowercase letters,
    digits and hyphens, bounded by `verbs.SYSTEM_MAX_LEN`; membership stays a separate
    question, so `gather` and `fakesys` are well-formed and simply undeclared.
* `defender/_paths.py::DefenderPaths` gains `adapters_dir` (and its `adapters_rel` spelling),
  so a worktree-rooted `LoopPaths` answers for the worktree at BOTH source directories.
* `pitfalls_curator._build_pitfalls_handoffs(rows, *, systems: frozenset[str])` and
  `pitfalls_curator._pitfalls_path_rule(xy, path, *, systems: frozenset[str])` — the
  `skills_dir` / `repo_root` probes are REPLACED by the threaded value (M2/M6), and
  `_is_real_system` is deleted along with the two stale justifications C34 refuted.
* `lead_author._skills_path_rule(repo_root, xy, path, *, systems: frozenset[str])` (M5/RF2)
  and `lead_author.discover_system_drafts(*, skills_dir, systems: frozenset[str])` (FK-4).
* the two composed gates take the same threaded value rather than re-deriving one behind
  their callers' backs: `lead_author._verify_skills_state(repo_root, baseline_stray, *,
  systems)` and `pitfalls_curator._verify_pitfalls_state(repo_root, baseline_stray, *,
  systems)`.
* `draft_synthesis.synthesize_drafts(executed, *, catalog_dir, catalog, systems)` (M4/FK-3).
* `LeadAuthorDeps` carries the resolved `systems: frozenset[str]`, built once in
  `build_lead_author_deps` from `paths` — the UNION on this lane (NF2).
* `persist.rotate_pitfalls(batch_ids, commit_sha, *, paths, category=...)` — FK-2 splits the
  batch AT THE CALL SITE, so the rotation takes the category it stamps rather than hardcoding
  `consumed_committed` (47's red flag 4: it is not a string rename).

Project idioms this file obeys, because CI ratchets them: fakes enter through the entry
point's own injection seams (`invoke=`, `deps=`, `verbs=`, a constructor argument), never
`monkeypatch.setattr`; the fakes inject faults and record what they were handed, and they
classify nothing.

Underscore-prefixed so pytest does not collect it; it defines no tests.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from defender import _git
#: Re-exported so the #869 suites keep importing the shape predicate from the one module that
#: states this seam's contract, rather than each reaching into `runtime.verbs` themselves.
from defender.runtime.verbs import is_system_name  # noqa: F401  (re-exported)

# ---- THE SURFACE UNDER TEST — it does not exist on this base (RED by construction) ----
try:  # pragma: no cover — the post-implementation branch
    from defender.learning.leads.declared_systems import (  # type: ignore[import-not-found]
        adapter_declared_systems,
        declared_systems,
    )
except ImportError as _err:  # pragma: no cover — the pre-implementation state
    # Rebound out of the `except` name, which Python unbinds at the end of the block — a
    # closure that read it there would raise NameError and hide the real diagnosis.
    _missing_target = _err

    def _not_yet_written(symbol: str):
        """Stand in for one not-yet-written symbol.

        NOT a skip and NOT a soften: calling it raises, so each test fails loudly on its
        own. The indirection exists only so a missing target does not abort pytest's whole
        collection and take the rest of the tree's suite down with it."""

        def _raise(*_a, **_k):
            raise ImportError(
                f"defender.learning.leads.declared_systems.{symbol} does not exist yet — "
                f"this suite is the executable spec for it (spec_graph_869.yaml). "
                f"Original: {_missing_target}"
            )

        return _raise

    declared_systems = _not_yet_written("declared_systems")  # type: ignore[assignment]
    adapter_declared_systems = _not_yet_written(  # type: ignore[assignment]
        "adapter_declared_systems"
    )


#: The two source directories, spelled here once so a fixture cannot disagree with the
#: resolver about where it reads.
ADAPTERS_REL = "defender/scripts/adapters/"
SKILLS_REL = "defender/skills/"
CATALOG_REL = "defender/skills/gather/queries/"

#: The two NESTED `execution.md` addresses phase F found admitted at the commit gate (F1) —
#: an `execution.md` whose parent directory name is entirely model-chosen, one under a
#: system's `_draft/` and one under the catalog. Spelled once here because two demands are
#: about the same two addresses from opposite ends (the resolver must not read them as
#: markers; the commit gate must not let them land) and a drift between the two spellings
#: would leave the composition open with both tests green.
NESTED_MARKER_RELS = (
    "defender/skills/elastic/_draft/mcpsys/execution.md",
    "defender/skills/gather/queries/elastic/mcpsys/execution.md",
)

#: The directory name a recursive, basename-filtered marker read would declare from either
#: path above — the obvious implementation's answer, and the one the depth rule refuses.
NESTED_MARKER_PARENT = "mcpsys"

#: What `defender/learning/`'s mutable state must never look like to `git status`: the
#: corpus-scope walk raises on ANY change outside `defender/skills/**.md`, so a queue file
#: inside the fixture repo would be read as a stray rather than as state. Every builder here
#: puts the state root outside the repo instead, and this is the belt for the paths that
#: cannot be moved.
GIT_IGNORE = (
    "defender/learning/_pending/\n"
    "defender/learning/_pending_leads/\n"
    "defender/learning/_pending_pitfalls/\n"
    "defender/learning/runs/\n"
    "state/\n"
)

#: An adapter module body that is IMPORT-SAFE. The resolver must never import one (C2/G1), so
#: `RAISING_ADAPTER_BODY` below is the fault that proves it; this is the ordinary case.
ADAPTER_BODY = "VERBS = {}\n"

#: An adapter module whose import RAISES. `declared_systems` must still yield its system name:
#: the adapter half is a cold glob over filenames, never a load (C2, G1).
RAISING_ADAPTER_BODY = 'raise RuntimeError("this adapter must never be imported")\n'


def git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=check
    )


def adapter_file(repo: Path, system: str) -> Path:
    """Where an adapter for `system` lands.

    The inverse of `verbs._system_of`, which is `name[:-len(SUFFIX)].replace("_", "-")` — so
    a hyphenated system (`change-mgmt`) is an underscored filename. Spelled here so a fixture
    for `change-mgmt` cannot silently seed a system called `change_mgmt`."""
    return repo / ADAPTERS_REL / f"{system.replace('-', '_')}_adapter.py"


def marker_file(repo: Path, system: str) -> Path:
    return repo / SKILLS_REL / system / "execution.md"


def skill_md(repo: Path, system: str) -> Path:
    return repo / SKILLS_REL / system / "SKILL.md"


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def write_adapter(repo: Path, system: str, *, body: str = ADAPTER_BODY) -> Path:
    return write(adapter_file(repo, system), body)


def write_marker(repo: Path, system: str, *, body: str = "# execution\n") -> Path:
    return write(marker_file(repo, system), body)


def write_skill_md(repo: Path, system: str, *, name: str | None = None) -> Path:
    front = f"---\nname: defender-{system if name is None else name}\n---\n"
    return write(skill_md(repo, system), f"{front}# {system}\n")


def write_template(
    repo: Path, system: str, stem: str, *, tid: str | None = None,
    status: str = "established", draft: bool = False,
) -> Path:
    """One catalog template under `gather/queries/<system>/` (or its `_draft/`).

    `tid` defaults to the directory-agreeing id — the invariant C35 measured 34/34 — so a
    test that wants a DISAGREEING one has to say so out loud."""
    parent = repo / CATALOG_REL / system / ("_draft" if draft else "")
    ident = f"{system}.{stem}" if tid is None else tid
    return write(
        parent / f"{stem}.md",
        f"---\nid: {ident}\nstatus: {status}\n---\n\n## Goal\n\nprobe\n\n## Query\n\nx\n",
    )


def init_git(repo: Path) -> Path:
    repo.mkdir(parents=True, exist_ok=True)
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "user.email", "t@t")
    git(repo, "config", "user.name", "t")
    return repo


def commit_all(repo: Path, message: str = "seed") -> str:
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)
    return _git.git_head_sha(repo)


def commit_paths(repo: Path, *paths: Path, message: str = "mid-tick") -> str:
    """Commit exactly these paths and nothing else.

    `git add -A` would sweep in whatever else the drive has put in the worktree, which for
    the ordering demands is the very thing under observation."""
    git(repo, "add", "--", *(str(p.relative_to(repo)) for p in paths))
    git(repo, "commit", "-q", "-m", message)
    return _git.git_head_sha(repo)


def head_files(repo: Path) -> list[str]:
    return git(repo, "show", "--name-only", "--pretty=format:", "HEAD").stdout.split()


def head_sha(repo: Path) -> str:
    return _git.git_head_sha(repo)


def seed_tree(
    tmp_path: Path,
    *,
    adapters: tuple[str, ...] = ("elastic",),
    markers: tuple[str, ...] = ("elastic",),
    skills: tuple[str, ...] = ("elastic",),
    catalog: tuple[str, ...] = ("elastic",),
    non_systems: tuple[str, ...] = (),
    name: str = "repo",
    commit: bool = True,
) -> Path:
    """A committed git repo standing in for a fresh `lead-author/<id>` worktree.

    The four source axes are separate parameters ON PURPOSE. Under the asymmetric union a
    fixture that seeds an adapter and a marker for every system can never see the split NF1
    and NF2 turn on, and every demand that drives one half alone would pass through the
    other. `adapters` is the working-tree half; `markers` is the committed half (so a
    marker-only system means `commit=True` — a marker merely written to disk declares
    NOTHING, which is the whole of NF1); `skills` seeds `SKILL.md` files, which under M6
    declare nothing at all any more; `non_systems` seeds a directory with a `SKILL.md` and
    NO adapter and NO marker — the six real ones this issue is named after.
    """
    repo = tmp_path / name
    init_git(repo)
    write(repo / ".gitignore", GIT_IGNORE)
    # Always present, even when it declares nothing: in production `branch.start_batch` cuts
    # an ordinary worktree off origin/main, so the directory is there and the ABSENT state is
    # a thing a test has to arrange on purpose (D5). A builder that only created it when it
    # had files in it would make every empty-source fixture an absent-source fixture, and the
    # two are different demands.
    (repo / ADAPTERS_REL).mkdir(parents=True, exist_ok=True)
    for system in adapters:
        write_adapter(repo, system)
    for system in markers:
        write_marker(repo, system)
    for system in (*skills, *non_systems):
        write_skill_md(repo, system)
    for system in catalog:
        write_template(repo, system, "auth-events")
    write(repo / CATALOG_REL / "SCHEMA.md", "# template schema\n")
    if commit:
        commit_all(repo, "seed")
    return repo


def read_rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()]


def pitfall_row(pid: str, system: str, *, digest: str | None = None, **extra) -> dict:
    """One queued pitfalls row.

    `stderr_digest` is distinct per row by default because #840 collapses rows sharing a
    digest into ONE record and the curation threshold counts records — a fixture that reused
    one digest would seed N rows worth one unit of work."""
    return {
        "schema_version": 1,
        "pitfall_id": pid,
        "source_run": "r",
        "system": system,
        "query_id": f"{system}.esql",
        "goal": "g",
        "executed_query": "bad pipe",
        "stderr_digest": digest if digest is not None else f"exit=1; mismatched input ({pid})",
        "error_class": "agent-fixable",
        **extra,
    }


def seed_executed_query(
    run_dir: Path, *, query_id: str, lead_id: str = "l-001", system: str = "elastic",
    verb: str = "esql", goal: str = "probe the thing",
) -> dict:
    """Append one row to the run's queries table THROUGH THE PRODUCTION WRITER.

    The table is append-only and read by later ticks, so "a row recorded before the writer
    rule existed" is not a hypothetical shape — it is whatever `append_query_row` wrote at
    the time. Seeding through that function rather than by hand is what keeps this fixture a
    real historical row instead of the test's own idea of one."""
    from defender._run_paths import RunPaths
    from defender.scripts.gather_tools.record_query import append_query_row

    gather = RunPaths(run_dir).gather_raw
    gather.mkdir(parents=True, exist_ok=True)
    write(
        gather / f"{lead_id}.lead.json",
        json.dumps({"goal": goal, "what_to_summarize": []}) + "\n",
    )
    return append_query_row(
        run_dir, lead_id=lead_id, system=system, verb=verb, query_id=query_id,
        params={"query": "FROM logs"}, raw_command=f"{system} {verb}",
        payload_text="[]", exit_code=0, payload_status="ok", payload_digest="2 bytes",
    )


class Spawn:
    """The curator/author spawn, faked at the entry point's own `invoke=` / `invoke_agent=`
    seam. It RECORDS what it was handed and then runs `edit` against the worktree.

    The recording half is what makes the ordering demands observable: `handoffs` is the value
    the entry point computed BEFORE the spawn, so a lane that re-resolved membership after
    the agent ran would have to disagree with it. The fake decides nothing — it does not
    filter, does not classify, and returns whatever `rc` it was built with."""

    def __init__(self, edit=None, *, rc: int = 0):
        self.edit = edit
        self.rc = rc
        self.calls: list[dict] = []

    @property
    def handoffs(self) -> list[dict]:
        assert self.calls, "the spawn was never reached, so its record is vacuous"
        return self.calls[-1]["handoffs"]

    @property
    def systems_seen(self) -> list[str]:
        return [h["system"] for h in self.handoffs]

    def __call__(self, handoffs, *args, repo_root: Path | None = None, box=None, **kwargs):
        # The pitfalls seam: `invoke(handoffs, *, repo_root, box)`. The lead-author seam has a
        # different positional shape and is `LeadAuthorSpawn` below.
        self.calls.append(
            {"handoffs": list(handoffs or []), "args": args, "repo_root": repo_root,
             "kwargs": kwargs}
        )
        if self.edit is not None and repo_root is not None:
            self.edit(Path(repo_root))
        return self.rc


class LeadAuthorSpawn(Spawn):
    """`invoke_agent(run_dir, handoffs, pending_drafts, *, box=None)` — the lead-author lane's
    spawn seam, whose positional shape differs from the pitfalls one."""

    def __call__(self, run_dir, handoffs, pending_drafts=None, *, box=None, **kwargs):  # type: ignore[override]
        self.calls.append(
            {"handoffs": list(handoffs or []), "pending_drafts": list(pending_drafts or []),
             "run_dir": run_dir, "repo_root": None, "args": (), "kwargs": kwargs}
        )
        if self.edit is not None:
            self.edit(Path(run_dir))
        return self.rc


def loop_log(capsys) -> str:
    """Everything the loop said on this drive.

    Both streams, joined: `config.make_logger` writes to stderr and a few of the surfaces
    these demands bind print to stdout, and which descriptor a line lands on is not what any
    demand here is about — that a line naming the refusal EXISTS is."""
    captured = capsys.readouterr()
    return captured.err + captured.out


def log_lines_naming(log: str, *needles: object) -> list[str]:
    """The log lines carrying every one of `needles` at once.

    Per-LINE rather than per-log, because "each refusal is named with the source it came
    from" (FK-5) is a claim about the pairing: two lines, one naming the name and another
    naming a directory, satisfy a whole-log substring test while telling an operator
    nothing about which source produced which name."""
    wanted = [str(n) for n in needles]
    return [ln for ln in log.splitlines() if all(w in ln for w in wanted)]


def unreadable_dir_verdict(root: Path, target: Path) -> bool:
    """Does `declared_systems(root)` RAISE when `target` is a directory it cannot read?

    Level (1) of the fault hierarchy — a real unreadable directory driven through the real
    resolver — with the instrument chosen from the uid the test actually runs as, because
    the fault itself is uid-dependent and P2 measured both sides:

    * as a non-root uid, `chmod 0o000` IS the fault: `os.scandir` raises `PermissionError`
      and `Path.glob` swallows it into `[]`;
    * as uid 0, permission bits are bypassed entirely (P2: uid 0 listed a mode-000 dir), so
      the same chmod produces NO fault at all and a test built on it would be green against
      a resolver with no check in it. P2's own instrument is reused instead: fork a child,
      drop to `nobody`, and let the child run the real resolver against the real directory.

    Returns True iff the resolver refused. The child reports through its exit status because
    an exception raised after `setuid` cannot cross back any other way.
    """
    from defender.learning.leads.lead_extraction import LeadAuthorError

    def _probe() -> bool:
        try:
            declared_systems(root)
        except LeadAuthorError:
            return True
        return False

    if os.geteuid() != 0:
        mode = target.stat().st_mode
        target.chmod(0o000)
        try:
            return _probe()
        finally:
            target.chmod(mode & 0o7777)

    _hand_tree_to_nobody(root)
    target.chmod(0o000)
    try:
        code = _verdict_from_child(_probe)
    finally:
        target.chmod(0o755)
        _reclaim_tree(root)
    assert code in (0, 1), (
        f"the unreadable-source probe child failed to set up (exit {code}); it never reached "
        f"the resolver, so neither answer would be about the resolver"
    )
    return code == 0


#: `nobody`, the uid P2 dropped to. Named rather than repeated, because the chown and the
#: setuid have to agree or the child fails setup instead of meeting the fault.
_NOBODY = 65534


def _hand_tree_to_nobody(root: Path) -> None:
    """Open the path down to `root` and hand the tree itself to `nobody`.

    Handed over outright rather than merely opened up, because the child also runs the
    COMMITTED-tree half of the resolver and git refuses a repository whose directory it does
    not own ("dubious ownership") — which would make the child fail before it ever reached
    the source under test, and a setup failure is not a refusal."""
    for parent in (root, *root.parents):
        if parent == Path(parent.root):
            break
        try:
            parent.chmod(0o755)
        except OSError:  # noqa: PERF203 — a path we do not own is a path we need not open
            break
    for path in (root, *root.rglob("*")):
        os.chown(path, _NOBODY, _NOBODY)


def _reclaim_tree(root: Path) -> None:
    for path in (root, *root.rglob("*")):
        os.chown(path, 0, 0)


def _verdict_from_child(probe) -> int:
    """Run `probe` as `nobody` in a forked child; return its exit status.

    0 = the resolver refused, 1 = it returned, 2 = the child never got that far. The child
    reports through its exit status because an exception raised after `setuid` cannot cross
    back any other way."""
    pid = os.fork()
    if pid == 0:  # pragma: no cover — the child never returns to pytest
        code = 2
        try:
            os.setgroups([])
            os.setgid(_NOBODY)
            os.setuid(_NOBODY)
            code = 0 if probe() else 1
        except BaseException:  # noqa: BLE001 — the child reports through its exit status
            code = 2
        finally:
            os._exit(code)
    _, status = os.waitpid(pid, 0)
    assert os.WIFEXITED(status), f"the unreadable-source probe child did not exit: {status}"
    return os.WEXITSTATUS(status)
