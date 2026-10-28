"""Fixture repos, spawn fakes and log readers for the #869 declared-systems suites."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_runs_base

import json
import os
import subprocess
from pathlib import Path

from defender import _git
#: Re-exported: the #869 suites import the shape predicate from here.
from defender.systems.verbs import is_system_name  # noqa: F401  (re-exported)

#: Re-exported: the #869 suites import the resolver under test from here.
from defender.learning.leads.declared_systems import (  # noqa: F401  (re-exported)
    adapter_declared_systems,
    declared_systems,
)


#: The source directories, spelled once so a fixture cannot disagree with the resolver about
#: where it reads.
ADAPTERS_REL = "defender/integrations/"
SKILLS_REL = "defender/skills/"
CATALOG_REL = "defender/skills/gather/queries/"

#: The same directories as a tenant repo or batch draft (`<T>/drafts/<id>/`, holding `agent/`)
#: spells them; adapters stay in the product checkout (`ADAPTERS_REL`).
AGENT_SKILLS_REL = "agent/skills/"
AGENT_CATALOG_REL = "agent/skills/gather/queries/"
#: Two nested `execution.md` addresses whose parent directory name is model-chosen (one under a
#: system's `_draft/`, one under the catalog): the resolver must not read them as markers.
AGENT_NESTED_MARKER_RELS = (
    "agent/skills/elastic/_draft/mcpsys/execution.md",
    "agent/skills/gather/queries/elastic/mcpsys/execution.md",
)

#: The directory name a recursive, basename-filtered marker read would declare from either
#: path above — the obvious implementation's answer, and the one the depth rule refuses.
NESTED_MARKER_PARENT = "mcpsys"

#: Hides the learning lane's mutable state from `git status`: the corpus-scope walk raises on
#: any change outside `defender/skills/**.md`, so a queue file in the fixture repo would read as
#: a stray. Builders put the state root outside the repo; this covers paths that cannot move.
GIT_IGNORE = (
    "defender/learning/_pending/\n"
    "defender/learning/_pending_leads/\n"
    "defender/learning/_pending_pitfalls/\n"
    "defender/learning/runs/\n"
    "state/\n"
)

#: An import-safe adapter body.
ADAPTER_BODY = "VERBS = {}\n"


def git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=check
    )


def adapter_file(repo: Path, system: str) -> Path:
    """Where an adapter for `system` lands: the inverse of `verbs._system_of`, so a hyphenated
    system (`change-mgmt`) gets an underscored filename."""
    return repo / ADAPTERS_REL / f"{system.replace('-', '_')}_adapter.py"


def marker_file(repo: Path, system: str) -> Path:
    return repo / SKILLS_REL / system / "execution.md"


def skill_md(repo: Path, system: str) -> Path:
    return repo / SKILLS_REL / system / "SKILL.md"


def agent_marker_file(root: Path, system: str) -> Path:
    """`marker_file` in a tenant repo (or draft) rooted at `root`: `agent/skills/<system>/execution.md`."""
    return root / AGENT_SKILLS_REL / system / "execution.md"


def agent_skill_md(root: Path, system: str) -> Path:
    return root / AGENT_SKILLS_REL / system / "SKILL.md"


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def write_adapter(repo: Path, system: str, *, body: str = ADAPTER_BODY) -> Path:
    return write(adapter_file(repo, system), body)


def write_marker(repo: Path, system: str, *, body: str = "# execution\n") -> Path:
    return write(marker_file(repo, system), body)


def _skill_md_text(system: str) -> str:
    return f"---\nname: defender-{system}\n---\n# {system}\n"


def _template_text(system: str, stem: str) -> str:
    """An established catalog template whose id agrees with its directory."""
    return f"---\nid: {system}.{stem}\nstatus: established\n---\n\n## Goal\n\nprobe\n\n## Query\n\nx\n"


def write_skill_md(repo: Path, system: str) -> Path:
    return write(skill_md(repo, system), _skill_md_text(system))


def write_template(repo: Path, system: str, stem: str) -> Path:
    """One catalog template under `gather/queries/<system>/`."""
    return write(repo / CATALOG_REL / system / f"{stem}.md", _template_text(system, stem))


def write_agent_marker(root: Path, system: str, *, body: str = "# execution\n") -> Path:
    return write(agent_marker_file(root, system), body)


def write_agent_skill_md(root: Path, system: str) -> Path:
    return write(agent_skill_md(root, system), _skill_md_text(system))


def write_agent_template(root: Path, system: str, stem: str) -> Path:
    """`write_template` under `agent/skills/gather/queries/<system>/` of `root`."""
    return write(root / AGENT_CATALOG_REL / system / f"{stem}.md", _template_text(system, stem))


def seed_agent_files(
    *,
    markers: tuple[str, ...] = ("elastic",),
    skills: tuple[str, ...] = ("elastic",),
    catalog: tuple[str, ...] = ("elastic",),
    non_systems: tuple[str, ...] = (),
) -> dict[str, str]:
    """`seed_tree`'s tenant half as agent-relative files (`skills/...`), for
    `_curator1134.draft_lane(files=...)`: markers, system skills and catalog templates. The
    adapters are the product half (`seed_product`)."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for system in markers:
            write_agent_marker(root, system)
        for system in (*skills, *non_systems):
            write_agent_skill_md(root, system)
        for system in catalog:
            write_agent_template(root, system, "auth-events")
        agent = root / "agent"
        return {str(p.relative_to(agent)): p.read_text(encoding="utf-8")
                for p in sorted(agent.rglob("*")) if p.is_file()}


def seed_product(tmp_path: Path, *, adapters: tuple[str, ...] = ("elastic",),
                 name: str = "product") -> Path:
    """`seed_tree`'s product half: a committed checkout holding only `defender/integrations/`
    adapters — no corpus, no skills."""
    repo = tmp_path / name
    init_git(repo)
    (repo / ADAPTERS_REL).mkdir(parents=True, exist_ok=True)
    for system in adapters:
        write_adapter(repo, system)
    write(repo / ".gitignore", GIT_IGNORE)
    commit_all(repo, "seed product")
    return repo


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
    """Commit exactly these paths: `git add -A` would sweep in the other worktree changes the
    ordering tests observe."""
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
) -> Path:
    """A committed git repo standing in for a fresh `lead-author/<id>` worktree."""
    repo = tmp_path / name
    init_git(repo)
    write(repo / ".gitignore", GIT_IGNORE)
    # Always present, even empty: a production worktree has it, so an ABSENT directory is
    # something a test arranges on purpose (empty and absent are different cases).
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
    commit_all(repo, "seed")
    return repo


def read_rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()]


def pitfall_row(pid: str, system: str, *, digest: str | None = None, **extra) -> dict:
    """One queued pitfalls row. `stderr_digest` is distinct per row by default: rows sharing a
    digest collapse into one record (#840), and the curation threshold counts records."""
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
    verb: str = "esql",
) -> dict:
    """Append one row to the run's queries table through the production writer
    (`append_query_row`), so it is a real historical row, not the test's idea of one."""
    from defender._io import read_jsonl_rows
    from defender.records import Run, RunPaths
    from defender.investigation.run_state import RunState
    from defender.investigation.record_query import append_query_row

    gather = RunPaths(run_dir).gather_raw
    gather.mkdir(parents=True, exist_ok=True)
    write(
        gather / f"{lead_id}.lead.json",
        json.dumps({"goal": "probe the thing", "what_to_summarize": []}) + "\n",
    )
    # The writer takes its seq from the run's state, which must hold the rows already in the
    # table as an inherited prefix.
    state = RunState(run_dir, "r869-historical")
    state.inherit_rows(read_jsonl_rows(RunPaths(run_dir).executed_queries))
    return append_query_row(
        state, run=Run.under(fixture_runs_base(run_dir.parent), run_dir.name),
        lead_id=lead_id, system=system, verb=verb, query_id=query_id,
        params={"query": "FROM logs"}, raw_command=f"{system} {verb}",
        payload_text="[]", exit_code=0, payload_status="ok", payload_digest="2 bytes",
        # `system` is the dispatched name here, so the row keys as itself and the fingerprint
        # column is empty.
        system_key="",
    )


class Spawn:
    """The curator/author spawn, faked at the entry point's `invoke=` / `invoke_agent=` seam: it
    records what it was handed, then runs `edit` against the worktree. `handoffs` is what the
    entry point computed BEFORE the spawn, so a lane that re-resolved membership after the agent
    ran would disagree with it. It decides nothing and returns `rc`."""

    def __init__(self, edit=None, *, rc: int = 0, root: Path | None = None):
        self.edit = edit
        self.rc = rc
        #: Where `edit` runs when set (a batch draft's root, which holds `agent/`), instead of
        #: the `repo_root` (pitfalls) or `run_dir` (lead author) the seam hands in.
        self.root = root
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
        if self.edit is not None and (self.root is not None or repo_root is not None):
            self.edit(Path(self.root if self.root is not None else repo_root))
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
            self.edit(Path(self.root if self.root is not None else run_dir))
        return self.rc


def loop_log(capsys) -> str:
    """Everything the loop said on this drive, stderr and stdout joined: which stream a line
    lands on does not matter, only that it exists."""
    captured = capsys.readouterr()
    return captured.err + captured.out


def log_lines_naming(log: str, *needles: object) -> list[str]:
    """The log lines carrying every one of `needles` at once. Per line, not per log: a refusal
    must be named together with its source, and two separate lines would pass a whole-log test."""
    wanted = [str(n) for n in needles]
    return [ln for ln in log.splitlines() if all(w in ln for w in wanted)]


#: `nobody`. Named once because the chown and the setuid must agree, or the child fails setup
#: instead of meeting the fault.
_NOBODY = 65534


def _hand_tree_to_nobody(root: Path) -> None:
    """Open the path down to `root` and hand the tree to `nobody` outright: the child also runs
    the committed-tree half of the resolver, and git refuses a repository it does not own
    ("dubious ownership"), a setup failure rather than a refusal."""
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
