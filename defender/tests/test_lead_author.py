"""Lead-author driver — extraction shape, handoff shape, lock/sentinel paths.

Scope (minimal, per defender/CLAUDE.md): pin algorithmic invariants that
would silently drift (lead extraction, handoff JSON shape, composite-kind
inference) plus the gating logic that prevents the driver from spawning
``claude`` when it shouldn't. We do NOT exhaustively mock ``claude`` —
the post-flight scope check is shell-and-git logic verifiable by reading
the code.
"""
from __future__ import annotations

import json
import re
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from defender.learning.leads import lead_author  # type: ignore[import-not-found]
from defender.learning.core.config import LoopPaths  # type: ignore[import-not-found]
from defender.tests._repo import query_template, seed_skills_repo


def _ensure_declarable(repo_root: Path) -> None:
    """`build_lead_author_deps` resolves `declared_systems` at its own boundary (#869) —
    every caller needs a real, committed adapter for that resolution to answer from rather
    than raise. Idempotent, so a caller that already seeded (or committed) its own tree is
    left alone; `elastic` is the name every other fixture in this file already assumes."""
    adapters = repo_root / "defender" / "scripts" / "adapters"
    if not adapters.is_dir():
        adapters.mkdir(parents=True)
        (adapters / "elastic_adapter.py").write_text("VERBS = {}\n")
    skills = repo_root / "defender" / "skills"
    skills.mkdir(parents=True, exist_ok=True)
    if not any(skills.rglob("*")):
        (skills / ".gitkeep").write_text("")
    if not (repo_root / ".git").is_dir():
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo_root, check=True)
        subprocess.run(["git", "config", "user.email", "t@t"], cwd=repo_root, check=True)
        subprocess.run(["git", "config", "user.name", "t"], cwd=repo_root, check=True)
    subprocess.run(["git", "add", "-A"], cwd=repo_root, check=True)
    subprocess.run(
        ["git", "commit", "-q", "-m", "seed", "--allow-empty"], cwd=repo_root, check=False,
    )


def _deps(tmp_path: Path, **overrides):
    """Production lead-author deps rooted at a tmp tree, with leaf collaborators
    overridden by keyword — replaces monkeypatching lead_author's own functions."""
    _ensure_declarable(tmp_path)
    return replace(lead_author.build_lead_author_deps(LoopPaths(repo_root=tmp_path)), **overrides)


def _executed_lead(**kw):
    """A minimal ``ExecutedLead`` for flow + collection tests. Defaults to an
    ``ok`` lead (``error_class=None``) so ``collect_general_failures`` is a no-op
    unless a test opts into a failure via ``error_class=`` / ``query_id=``."""
    base = dict(
        lead_id="l-001", query_index=0, is_multi_query=False, entry_index=0,
        query_id="elastic.esql", system="elastic", verb="esql", params={}, raw_command="cli",
        goal_text="", what_to_summarize=(), raw_ref=None,
        payload_status="ok", payload_digest="", error_class=None,
    )
    base.update(kw)
    return lead_author.ExecutedLead(**base)




def _write_lead_meta(run_dir: Path, lead_id: str, goal: str, wts=()) -> None:
    raw = run_dir / "gather_raw"
    raw.mkdir(exist_ok=True)
    (raw / f"{lead_id}.lead.json").write_text(
        json.dumps({"goal": goal, "what_to_summarize": list(wts)})
    )


def _write_query(  # noqa: PLR0913 — a queries-row builder mirrors the table's columns
    run_dir: Path,
    lead_id: str,
    seq: int,
    query_id: str,
    params: dict | None = None,
    *,
    verb: str | None = None,
    payload: str | None = "{}",
    payload_status: str = "ok",
    payload_digest: str = "ok digest",
) -> None:
    """Append one queries-table row + (optionally) its by-ref payload.

    ``verb`` is the honest registry verb the row freezes (#620); it defaults to the query_id
    suffix (the untagged shape) — pass it explicitly to exercise an engine verb or a coined id
    whose suffix is not the verb."""
    raw = run_dir / "gather_raw"
    raw.mkdir(exist_ok=True)
    rel = None
    if payload is not None:
        ld = raw / lead_id
        ld.mkdir(exist_ok=True)
        (ld / f"{seq}.json").write_text(payload)
        rel = f"gather_raw/{lead_id}/{seq}.json"
    row = {
        "lead_id": lead_id,
        "seq": seq,
        "system": query_id.split(".", 1)[0] if "." in query_id else query_id,
        "verb": verb if verb is not None else query_id.split(".", 1)[-1],
        "query_id": query_id,
        "params": params or {},
        "raw_command": "cli",
        "payload_path": rel,
        "exit_code": 0 if payload_status != "error" else 1,
        "payload_status": payload_status,
        "payload_digest": payload_digest,
    }
    with (run_dir / "executed_queries.jsonl").open("a") as fh:
        fh.write(json.dumps(row) + "\n")


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    rd = tmp_path / "test-run-001"
    rd.mkdir()
    (rd / "gather_raw").mkdir()
    return rd


@pytest.fixture
def catalog(tmp_path: Path) -> Path:
    """Self-contained query catalog so build_handoff resolves ids without
    depending on the live, environment-specific on-disk catalog (v2 ships an
    elastic/host-state/cmdb catalog; main ships wazuh). Returns the catalog dir;
    tests pass it as ``build_handoff(..., repo_root=catalog.parent, catalog_dir=catalog)``
    (the read root + the relative-path anchor), so no module-global patch is needed."""
    cat = tmp_path / "queries"
    (cat / "elastic").mkdir(parents=True)
    (cat / "host-state").mkdir(parents=True)
    (cat / "elastic" / "auth-events.md").write_text(
        "---\nid: elastic.auth-events\nstatus: established\n---\n\n"
        "## Goal\nAuthentication events for a host over a window.\n\n"
        "## Query\n\n```\nelastic_adapter.py query --window ${window} ${host_clause}\n```\n"
    )
    (cat / "host-state" / "process-list.md").write_text(
        "---\nid: host-state.process-list\nstatus: established\n---\n\n"
        "## Goal\nRunning processes matching a pattern.\n\n"
        "## Query\n\n```\nhost_state_adapter.py process-list ${pattern}\n```\n"
    )
    return cat




def test_extract_single_query_per_entry(run_dir: Path):
    _write_lead_meta(run_dir, "l-001", "list auth events", ["src_ip", "user"])
    _write_query(run_dir, "l-001", 0, "wazuh.auth-events", {"host": "h1", "window": "1h"})
    _, leads = lead_author.extract(run_dir)
    assert len(leads) == 1
    lead = leads[0]
    assert lead.lead_id == "l-001"
    assert lead.query_index == 0
    assert lead.is_multi_query is False
    assert lead.query_id == "wazuh.auth-events"
    assert lead.params == {"host": "h1", "window": "1h"}
    assert lead.goal_text == "list auth events"
    assert lead.what_to_summarize == ("src_ip", "user")
    assert lead.raw_ref == run_dir / "gather_raw" / "l-001" / "0.json"
    assert lead.payload_status == "ok"


def test_extract_multi_query_fans_out(run_dir: Path):
    _write_lead_meta(run_dir, "l-001", "fan out")
    _write_query(run_dir, "l-001", 0, "wazuh.auth-events")
    _write_query(run_dir, "l-001", 1, "wazuh.sudo-commands")
    _, leads = lead_author.extract(run_dir)
    assert len(leads) == 2
    assert leads[0].query_index == 0
    assert leads[0].is_multi_query is True
    assert leads[0].raw_ref.name == "0.json"
    assert leads[1].query_index == 1
    assert leads[1].query_id == "wazuh.sudo-commands"
    assert leads[1].raw_ref.name == "1.json"


def test_extract_skips_query_with_no_payload(run_dir: Path):
    _write_lead_meta(run_dir, "l-001", "x")
    _write_query(run_dir, "l-001", 0, "wazuh.auth-events", payload=None)
    assert lead_author.extract(run_dir)[1] == []


def test_extract_multi_query_skips_missing_payload(run_dir: Path):
    _write_lead_meta(run_dir, "l-001", "partial fan-out")
    _write_query(run_dir, "l-001", 0, "wazuh.auth-events")
    _write_query(run_dir, "l-001", 1, "wazuh.sudo-commands", payload=None)
    _, leads = lead_author.extract(run_dir)
    assert len(leads) == 1
    assert leads[0].query_id == "wazuh.auth-events"


def test_extract_missing_payload_status_raises(run_dir: Path):
    """An empty payload_status (no row status) is a loud failure."""
    _write_lead_meta(run_dir, "l-001", "x")
    _write_query(run_dir, "l-001", 0, "wazuh.auth-events", payload_status="")
    with pytest.raises(lead_author.LeadAuthorError, match="payload_status"):
        lead_author.extract(run_dir)


def test_extract_invalid_payload_status_raises(run_dir: Path):
    _write_lead_meta(run_dir, "l-001", "x")
    _write_query(run_dir, "l-001", 0, "wazuh.auth-events", payload_status="weird")
    with pytest.raises(lead_author.LeadAuthorError, match="payload_status"):
        lead_author.extract(run_dir)




def test_build_handoff_groups_by_template(run_dir: Path, catalog: Path):
    """Same template invoked across 3 leads → one handoff with 3 invocations."""
    for i in range(3):
        lid = f"l-00{i + 1}"
        _write_lead_meta(run_dir, lid, f"call {i}")
        _write_query(run_dir, lid, 0, "elastic.auth-events", {"host": f"h{i}"},
                     payload_digest=f"call-{i}")
    _, leads = lead_author.extract(run_dir)
    handoffs = lead_author.build_handoff(
        run_dir, leads, repo_root=catalog.parent, catalog_dir=catalog
    )
    assert len(handoffs) == 1
    h = handoffs[0]
    assert h["query_id"] == "elastic.auth-events"
    assert h["status"] == "established"
    assert h["executed_template_path"].endswith("elastic/auth-events.md")
    assert len(h["invocations"]) == 3
    assert [inv["payload_digest"] for inv in h["invocations"]] == [
        "call-0", "call-1", "call-2",
    ]
    json.dumps(h)


def test_build_handoff_includes_rendered_query_and_status(run_dir: Path, catalog: Path):
    _write_lead_meta(run_dir, "l-001", "x")
    _write_query(
        run_dir, "l-001", 0, "elastic.auth-events",
        {"host": "bastion-01", "window": "1h"},
        payload_status="suspect_empty",
        payload_digest="0 events; data.srcip is IP-typed",
    )
    _, leads = lead_author.extract(run_dir)
    handoffs = lead_author.build_handoff(
        run_dir, leads, repo_root=catalog.parent, catalog_dir=catalog
    )
    assert len(handoffs) == 1
    inv = handoffs[0]["invocations"][0]
    assert inv["payload_status"] == "suspect_empty"
    assert "data.srcip" in inv["payload_digest"]
    assert inv["result_refs"] == ["gather_raw/l-001/0.json"]
    assert inv["rendered_query"]
    assert "--window 1h" in inv["rendered_query"]
    assert "${host_clause}" in inv["rendered_query"]


def test_build_handoff_surfaces_literal_esql_query(run_dir: Path, catalog: Path):
    """For an ES|QL invocation the whole query is the verbatim `query` body param — so the
    handoff carries the literal pipe as `executed_query` (the canonical record), not a
    `${param}` re-render that drops the values."""
    pipe = 'FROM logs-system.auth-* | WHERE host.name == "db-1" | STATS c = COUNT(*)'
    _write_lead_meta(run_dir, "l-001", "x")
    _write_query(run_dir, "l-001", 0, "elastic.auth-events", {"query": pipe}, verb="esql")
    _, leads = lead_author.extract(run_dir)
    inv = lead_author.build_handoff(
        run_dir, leads, repo_root=catalog.parent, catalog_dir=catalog
    )[0]["invocations"][0]
    assert inv["executed_query"] == pipe


def test_build_handoff_drops_unresolved_query_id(run_dir: Path, catalog: Path):
    """Unresolved query_id ⇒ skip with a corpus-health warning, don't crash."""
    _write_lead_meta(run_dir, "l-001", "novel")
    _write_query(run_dir, "l-001", 0, "elastic.does-not-exist")
    _write_lead_meta(run_dir, "l-002", "real one")
    _write_query(run_dir, "l-002", 0, "elastic.auth-events")
    _, leads = lead_author.extract(run_dir)
    assert len(leads) == 2
    handoffs = lead_author.build_handoff(
        run_dir, leads, repo_root=catalog.parent, catalog_dir=catalog
    )
    assert len(handoffs) == 1
    assert handoffs[0]["query_id"] == "elastic.auth-events"


def test_build_handoff_drops_ad_hoc_empty_query_id(run_dir: Path):
    _write_lead_meta(run_dir, "l-001", "ad-hoc")
    _write_query(run_dir, "l-001", 0, "")
    _, leads = lead_author.extract(run_dir)
    handoffs = lead_author.build_handoff(run_dir, leads)
    assert handoffs == []


def test_build_handoff_one_handoff_per_template_cross_system(run_dir: Path, catalog: Path):
    """A multi-query, cross-system lead yields one handoff per executed template."""
    _write_lead_meta(run_dir, "l-001", "cross-system")
    _write_query(run_dir, "l-001", 0, "elastic.auth-events")
    _write_query(run_dir, "l-001", 1, "host-state.process-list", {"pattern": "x"})
    _, leads = lead_author.extract(run_dir)
    handoffs = lead_author.build_handoff(
        run_dir, leads, repo_root=catalog.parent, catalog_dir=catalog
    )
    assert len(handoffs) == 2
    by_id = {h["query_id"]: h for h in handoffs}
    assert set(by_id) == {"elastic.auth-events", "host-state.process-list"}
    assert len(by_id["elastic.auth-events"]["invocations"]) == 1




def _claude_should_not_be_called(*args, **kwargs):
    raise AssertionError("claude was spawned despite gating check")


def test_run_missing_run_dir(tmp_path: Path):
    assert lead_author.run(tmp_path / "nope") == 2


def test_run_held_queue_lock_reports_a_skip_not_a_serve(run_dir: Path):
    """A held queue lock spawns nothing AND says so distinguishably (#852 F-03).

    It used to return 0 — the value a completed curation returns — and the lead-author drain
    reads that rc as "served, unlink the marker". The whole claimed batch was deleted with no
    work done and no dead letter. The agent still must not be spawned; what changed is that
    the caller can now tell the two apart."""
    deps = _deps(
        run_dir.parent,
        acquire_queue_lock=lambda: None,
        invoke_agent=_claude_should_not_be_called,
    )
    rc = lead_author.run(run_dir, deps=deps)
    assert rc == lead_author.QUEUE_LOCK_SKIP_RC
    assert rc != 0


def test_run_done_sentinel_short_circuits(run_dir: Path):
    state = run_dir / "lead_author"
    state.mkdir()
    (state / "done").write_text("ok")
    deps = _deps(
        run_dir.parent,
        acquire_queue_lock=lambda: object(),
        release_queue_lock=lambda fh: None,
        invoke_agent=_claude_should_not_be_called,
    )
    assert lead_author.run(run_dir, deps=deps) == 0




def test_under_draft_classifier():
    assert lead_author._under_draft("defender/skills/gather/queries/wazuh/_draft/x.md")
    assert lead_author._under_draft("defender/skills/gather/queries/host-query/_draft/y.md")
    assert not lead_author._under_draft("defender/skills/gather/queries/wazuh/auth-events.md")
    assert not lead_author._under_draft("defender/lessons/x.md")


def test_is_system_skill_md_classifier():
    assert lead_author._is_system_skill_md("defender/skills/elastic/SKILL.md")
    assert lead_author._is_system_skill_md("defender/skills/wazuh/SKILL.md")
    assert not lead_author._is_system_skill_md(
        "defender/skills/gather/queries/wazuh/auth-events.md"
    )
    assert not lead_author._is_system_skill_md(
        "defender/skills/gather/queries/SCHEMA.md"
    )
    assert not lead_author._is_system_skill_md(
        "defender/skills/elastic/_draft/foo.md"
    )


def test_is_system_skill_draft_classifier():
    assert lead_author._is_system_skill_draft("defender/skills/elastic/_draft/foo.md")
    assert lead_author._is_system_skill_draft("defender/skills/cmdb/_draft/bar.md")
    assert not lead_author._is_system_skill_draft(
        "defender/skills/gather/queries/elastic/_draft/foo.md"
    )
    assert not lead_author._is_system_skill_draft("defender/skills/elastic/SKILL.md")


def test_is_in_scope_covers_both_surfaces():
    assert lead_author._is_in_scope("defender/skills/gather/queries/wazuh/auth-events.md")
    assert lead_author._is_in_scope("defender/skills/elastic/SKILL.md")
    assert lead_author._is_in_scope("defender/skills/elastic/_draft/foo.md")
    assert not lead_author._is_in_scope("defender/lessons/x.md")
    assert not lead_author._is_in_scope("defender/other/stray.md")


def test_discover_system_drafts_finds_files_excluding_readme(tmp_path):
    """README.md and _TEMPLATE.md are surface declarations, not drafts."""
    skills = tmp_path / "defender" / "skills"
    (skills / "elastic" / "_draft").mkdir(parents=True)
    (skills / "elastic" / "_draft" / "README.md").write_text("surface declaration\n")
    (skills / "elastic" / "_draft" / "real-draft.md").write_text("---\nstatus: draft\n---\n")
    (skills / "elastic" / "SKILL.md").write_text("# elastic\n")
    (skills / "wazuh").mkdir()
    (skills / "wazuh" / "SKILL.md").write_text("# wazuh\n")
    (skills / "gather" / "queries" / "elastic" / "_draft").mkdir(parents=True)
    (skills / "gather" / "queries" / "elastic" / "_draft" / "ignore.md").write_text("ignore\n")
    (skills / "cmdb" / "_draft").mkdir(parents=True)
    (skills / "cmdb" / "_draft" / "_TEMPLATE.md").write_text("template\n")

    found = lead_author.discover_system_drafts(
        skills_dir=skills, systems=frozenset({"elastic", "wazuh", "cmdb"}))
    rel = [str(p.relative_to(tmp_path)) for p in found]
    assert rel == ["defender/skills/elastic/_draft/real-draft.md"]


def test_build_system_draft_handoffs_emits_triple(tmp_path):
    skills = tmp_path / "defender" / "skills"
    (skills / "elastic" / "_draft").mkdir(parents=True)
    draft = skills / "elastic" / "_draft" / "falco-na.md"
    draft.write_text("---\nstatus: draft\n---\n")
    handoffs = lead_author.build_system_draft_handoffs([draft], repo_root=tmp_path)
    assert handoffs == [{
        "draft_path": "defender/skills/elastic/_draft/falco-na.md",
        "system": "elastic",
        "skill_path": "defender/skills/elastic/SKILL.md",
    }]




def _run_git(cwd: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd,
                          capture_output=True, text=True, check=True)


_CATALOG = "defender/skills/gather/queries"

#: `tests/_repo.seed_skills_repo`'s adapter-declared systems (#869) — threaded explicitly,
#: since every consumer answers from the value it is handed rather than re-deriving the tree.
DECLARED = frozenset({"elastic", "wazuh"})


@pytest.fixture
def tmp_git_repo(tmp_path: Path) -> Path:
    """A clean git repo with a seeded skills tree (committed) — stands in for a fresh
    ``lead-author/<id>`` worktree. The agent runs no git, so tests then make *working-tree*
    edits and call ``_verify_skills_state`` / drive ``run`` over them, asserting the loop's
    gate + commit behavior."""
    return seed_skills_repo(tmp_path / "repo")


def test_verify_skills_state_accepts_in_scope_edits(tmp_git_repo: Path):
    """Fold an established template, promote a draft (write established + rm draft), and
    lift a system skill (edit SKILL.md + rm draft) — all in-scope; returns changed paths."""
    repo = tmp_git_repo
    (repo / _CATALOG / "wazuh" / "auth-events.md").write_text(
        query_template("wazuh.auth-events", "established") + "\n# folded\n"
    )
    (repo / _CATALOG / "wazuh" / "newthing.md").write_text(
        query_template("wazuh.newthing", "established")
    )
    (repo / _CATALOG / "wazuh" / "_draft" / "newthing.md").unlink()
    skill = repo / "defender" / "skills" / "elastic" / "SKILL.md"
    skill.write_text(skill.read_text() + "\n## Falco quirk\nworkaround\n")
    (repo / "defender" / "skills" / "elastic" / "_draft" / "falco-na.md").unlink()

    changed = lead_author._verify_skills_state(repo, baseline_stray=[], systems=DECLARED)
    assert "defender/skills/gather/queries/wazuh/auth-events.md" in changed
    assert "defender/skills/gather/queries/wazuh/newthing.md" in changed
    assert "defender/skills/elastic/SKILL.md" in changed


def test_verify_skills_state_rejects_stray_outside_skills(tmp_git_repo: Path):
    (tmp_git_repo / "defender" / "other").mkdir(parents=True)
    (tmp_git_repo / "defender" / "other" / "stray.md").write_text("stray")
    with pytest.raises(lead_author.LeadAuthorError, match="outside"):
        lead_author._verify_skills_state(tmp_git_repo, baseline_stray=[], systems=DECLARED)


def _append(path: Path, text: str) -> None:
    path.write_text(path.read_text() + text)


# Every row mutates the seeded worktree ONE way the write lane admits, then asserts the
# post-flight refuses it and says why. The `match` is load-bearing: these refusals land in a
# batch's stderr, and "which rule" is the only thing that tells the loop what to revert.
@pytest.mark.parametrize(("case", "mutate", "match"), [
    # a non-*.md file under defender/skills/ is a stray — the corpus is *.md
    ("non-md-under-skills",
     lambda r: (r / "defender" / "skills" / "junk.json").write_text("{}"), "outside"),

    # deleting an ESTABLISHED template, and deleting a system's SKILL.md, are both the
    # delete-prohibition: a promote writes, it never removes what another run relies on
    ("established-template-deletion",
     lambda r: (r / _CATALOG / "wazuh" / "auth-events.md").unlink(), "delete-prohibition"),
    ("skill-md-deletion",
     lambda r: (r / "defender" / "skills" / "elastic" / "SKILL.md").unlink(),
     "delete-prohibition"),

    # the `_draft/README.md` is scaffold the lane may not author over
    ("draft-readme-mutation",
     lambda r: _append(r / "defender" / "skills" / "elastic" / "_draft" / "README.md",
                       "\nstomped\n"),
     "protected surface"),

    # A promote that writes the established template but never ``rm``s its ``_draft/`` twin
    # leaves both on disk. The surviving draft is UNCHANGED ⇒ not in ``git status`` ⇒ the
    # records-only checks cannot see it; the filesystem twin probe must catch the half-promote
    # rather than letting the loop commit established + draft together.
    ("half-promote",
     lambda r: (r / _CATALOG / "wazuh" / "newthing.md").write_text(
         query_template("wazuh.newthing", "established")), "half-promote"),

    # The lift writes `skills/{system}/SKILL.md`, so the frontmatter identity `connect` checks
    # at scaffold time is an invariant this lane can break — `read_description` and the roster
    # audit both key on the DIRECTORY, so a SKILL.md that calls itself another system is a
    # per-system prompt injected under the wrong system's name.
    ("skill-md-naming-another-system",
     lambda r: (r / "defender" / "skills" / "elastic" / "SKILL.md").write_text(
         "---\nname: defender-cmdb\n---\n# elastic\n"), "defender-elastic"),
], ids=lambda v: v if isinstance(v, str) and len(v) < 50 and " " not in v else "")
def test_verify_skills_state_rejects_a_tree_the_write_lane_could_produce(
    tmp_git_repo: Path, case, mutate, match
):
    """The write lane admits any `{system}/{name}.md`, so the post-flight is the only thing
    standing between a well-formed but illegitimate edit and a commit. Each row is one such
    edit — a stray, a deletion, a protected surface, a half-finished promote, a misnamed
    identity — and each is refused by the rule that owns it."""
    mutate(tmp_git_repo)
    with pytest.raises(lead_author.LeadAuthorError, match=match):
        lead_author._verify_skills_state(tmp_git_repo, baseline_stray=[], systems=DECLARED)


def test_verify_skills_state_rejects_out_of_scope_skills_md(tmp_git_repo: Path):
    """A skills *.md that is neither catalog, SKILL.md, nor _draft is out of scope.

    Not `execution.md` (#869): that basename is refused at every depth for its own,
    more specific reason (`marker_is_not_agent_committable`), asserted separately."""
    (tmp_git_repo / "defender" / "skills" / "elastic" / "notes.md").write_text("x")
    with pytest.raises(lead_author.LeadAuthorError, match="out-of-scope"):
        lead_author._verify_skills_state(tmp_git_repo, baseline_stray=[], systems=DECLARED)


def test_verify_skills_state_rejects_execution_md(tmp_git_repo: Path):
    """`execution.md` is the one per-system file the lead-author lane can never get
    committed (#869 C32/F1) — under NF1 the commit gate IS the marker's integrity."""
    (tmp_git_repo / "defender" / "skills" / "elastic" / "execution.md").write_text("x")
    with pytest.raises(lead_author.LeadAuthorError, match="execution.md"):
        lead_author._verify_skills_state(tmp_git_repo, baseline_stray=[], systems=DECLARED)


def _stage_covered_draft(repo: Path, query_id: str) -> Path:
    """Commit a `wazuh` draft that accounts for `query_id`, as the mint would write it.

    Committed, not merely written, because the invariants under test read the draft's PRE-IMAGE
    out of `git show HEAD:…` — a draft that only ever existed in the working tree carries no
    identities to orphan when the agent deletes it.
    """
    draft = repo / _CATALOG / "wazuh" / "_draft" / f"{lead_author._draft_basename(query_id)}.md"
    draft.write_text(query_template(f"wazuh.{lead_author._draft_basename(query_id)}",
                                    "draft", covers=[query_id]))
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "mint"], cwd=repo, check=True)
    return draft


def test_a_promote_that_carries_covers_is_accepted(tmp_git_repo: Path):
    """The disposition the rule is shaped around: the author names the file for what it
    measures and carries the coined identity onto it.

    The name is deliberately unrelated to the draft's — that is the whole point of deriving the
    draft's basename — so nothing but `covers:` connects the two files."""
    repo = tmp_git_repo
    draft = _stage_covered_draft(repo, "wazuh.hunt-failed-logins")
    (repo / _CATALOG / "wazuh" / "auth-failure-rate.md").write_text(
        query_template("wazuh.auth-failure-rate", "established",
                       covers=["wazuh.hunt-failed-logins"])
    )
    draft.unlink()

    changed = lead_author._verify_skills_state(repo, baseline_stray=[], systems=DECLARED)
    assert "defender/skills/gather/queries/wazuh/auth-failure-rate.md" in changed


def test_a_discard_into_widen_that_carries_covers_is_accepted(tmp_git_repo: Path):
    """The PREFERRED disposition (`lead_author.md`: discard-into-widen > skip > promote), and
    the one the old basename link could never have expressed — the identity lands on a template
    that already existed under an unrelated name."""
    repo = tmp_git_repo
    draft = _stage_covered_draft(repo, "wazuh.hunt-failed-logins")
    (repo / _CATALOG / "wazuh" / "auth-events.md").write_text(
        query_template("wazuh.auth-events", "established",
                       covers=["wazuh.hunt-failed-logins"]) + "\n# widened\n"
    )
    draft.unlink()

    changed = lead_author._verify_skills_state(repo, baseline_stray=[], systems=DECLARED)
    assert "defender/skills/gather/queries/wazuh/auth-events.md" in changed


def test_a_bare_discard_of_a_covered_draft_is_refused(tmp_git_repo: Path):
    """Deleting a draft without attributing it is the silent, self-repeating failure.

    Nothing observable happens: the batch commits, and the identity is minted again the next
    time a run coins it, discarded again, forever. The refusal names the alternative the prompt
    already gives — a draft that fits no template is one to SKIP."""
    repo = tmp_git_repo
    draft = _stage_covered_draft(repo, "wazuh.hunt-failed-logins")
    draft.unlink()

    with pytest.raises(lead_author.LeadAuthorError, match="wazuh.hunt-failed-logins"):
        lead_author._verify_skills_state(repo, baseline_stray=[], systems=DECLARED)


def _mint_uncommitted_draft(repo: Path, query_id: str) -> Path:
    """A `wazuh` draft written but NOT committed — what `synthesize_drafts` leaves behind, and
    what the same tick then hands to the author.

    `covers:` carries BOTH identities the real mint writes: the draft's own derived id (which
    `template_search` publishes and gather may bind) and the coined `query_id`. A fixture that
    wrote only one would test a file the loop never produces."""
    draft_id = f"wazuh.{lead_author._draft_basename(query_id)}"
    draft = repo / _CATALOG / "wazuh" / "_draft" / f"{lead_author._draft_basename(query_id)}.md"
    draft.write_text(query_template(draft_id, "draft", covers=[draft_id, query_id]))
    return draft


def test_a_bare_discard_of_a_draft_minted_this_tick_is_refused(tmp_git_repo: Path):
    """The transfer rule's DOMINANT case, and the one git cannot report.

    `_run_locked` mints and then hands the same draft to the author in the same tick (it
    reloads the catalog after the mint precisely so the row resolves), so the draft the author
    bare-discards is almost always one that was never committed: no `D` porcelain record, no
    `git show HEAD:` pre-image, nothing for a gate reading only git to see. The identities are
    captured between the mint and the agent instead."""
    repo = tmp_git_repo
    draft = _mint_uncommitted_draft(repo, "wazuh.hunt-failed-logins")
    minted = lead_author._minted_identities([draft])
    draft.unlink()

    with pytest.raises(lead_author.LeadAuthorError, match="wazuh.hunt-failed-logins"):
        lead_author._verify_skills_state(
            repo, baseline_stray=[], systems=DECLARED, minted=minted
        )


def test_a_promote_of_a_draft_minted_this_tick_is_accepted(tmp_git_repo: Path):
    """The positive control for the rule above — the identity lands, so the delete costs
    nothing and the batch commits."""
    repo = tmp_git_repo
    draft = _mint_uncommitted_draft(repo, "wazuh.hunt-failed-logins")
    minted = lead_author._minted_identities([draft])
    (repo / _CATALOG / "wazuh" / "auth-failure-rate.md").write_text(
        query_template("wazuh.auth-failure-rate", "established",
                       covers=[draft.stem.join(("wazuh.", "")), "wazuh.hunt-failed-logins"])
    )
    draft.unlink()

    changed = lead_author._verify_skills_state(
        repo, baseline_stray=[], systems=DECLARED, minted=minted
    )
    assert "defender/skills/gather/queries/wazuh/auth-failure-rate.md" in changed


def test_a_draft_minted_this_tick_and_left_alone_is_not_a_departure(tmp_git_repo: Path):
    """SKIP is a legal disposition, and it is the one the prompt names for a draft that fits
    nowhere — the rule must fire on the `rm`, never on the file still being there."""
    repo = tmp_git_repo
    draft = _mint_uncommitted_draft(repo, "wazuh.hunt-failed-logins")
    minted = lead_author._minted_identities([draft])

    changed = lead_author._verify_skills_state(
        repo, baseline_stray=[], systems=DECLARED, minted=minted
    )
    assert changed == [draft.relative_to(repo).as_posix()]


def test_a_promote_that_leaves_the_draft_behind_is_refused(tmp_git_repo: Path):
    """The half-promote, now that no basename links the two files.

    `_skills_content_rule`'s twin probe derives `_draft/{name}.md` from the established file's
    own name, which was the link while a promote was `_draft/{id}.md` -> `{id}.md`. A digest
    basename and an author-chosen name share nothing, so that probe cannot fire on any real
    promote — and the surviving draft is UNCHANGED, so no `git status` record carries it
    either. `covers:` is the link that is left: the identity landed on an established template
    while the draft that records it is still on disk."""
    repo = tmp_git_repo
    _stage_covered_draft(repo, "wazuh.hunt-failed-logins")
    (repo / _CATALOG / "wazuh" / "auth-failure-rate.md").write_text(
        query_template("wazuh.auth-failure-rate", "established",
                       covers=["wazuh.hunt-failed-logins"])
    )
    # …and no `rm` of the draft.
    with pytest.raises(lead_author.LeadAuthorError, match="half-promote"):
        lead_author._verify_skills_state(repo, baseline_stray=[], systems=DECLARED)


def test_a_discard_is_accepted_when_an_untouched_template_already_covers_it(
    tmp_git_repo: Path,
):
    """Transfer is a question about the TREE, not about this batch's diff.

    An identity a template took over in an earlier tick is one `synthesize_drafts` will not
    re-mint, so deleting its leftover draft costs nothing — and scoring the rule against the
    batch alone would refuse that delete and discard every other edit in the tick with it."""
    repo = tmp_git_repo
    draft = _stage_covered_draft(repo, "wazuh.hunt-failed-logins")
    established = repo / _CATALOG / "wazuh" / "auth-events.md"
    established.write_text(
        query_template("wazuh.auth-events", "established", covers=["wazuh.hunt-failed-logins"])
    )
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "widened last tick"], cwd=repo, check=True)

    draft.unlink()
    changed = lead_author._verify_skills_state(repo, baseline_stray=[], systems=DECLARED)
    assert changed == ["defender/skills/gather/queries/wazuh/_draft/"
                       f"{lead_author._draft_basename('wazuh.hunt-failed-logins')}.md"]


def test_repairing_an_id_that_disagrees_with_its_directory_is_not_a_clobber(
    tmp_git_repo: Path
):
    """The two rules deadlocked, and the deadlock had no exit.

    A template filed under `wazuh/` while calling itself `elastic.…` is refused by
    `check_template`'s `id-system-mismatch` on every edit, with a message telling the author to
    make the id start with `wazuh`. Doing that was then refused by the monotonicity rule as
    "rewriting the identity of an established template", and moving the file instead is refused
    by the delete-prohibition — so every tick that touched the file discarded its whole batch
    while following two contradictory instructions."""
    repo = tmp_git_repo
    broken = repo / _CATALOG / "wazuh" / "auth-events.md"
    broken.write_text(query_template("elastic.auth-events", "established"))
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "a mismatched id"], cwd=repo, check=True)

    broken.write_text(query_template("wazuh.auth-events", "established"))
    changed = lead_author._verify_skills_state(repo, baseline_stray=[], systems=DECLARED)
    assert "defender/skills/gather/queries/wazuh/auth-events.md" in changed


def test_a_draft_folded_into_another_draft_is_attributed(tmp_git_repo: Path):
    """A draft is a legal home for a transferred identity, because the MINT thinks so.

    `top_k_neighbors` iterates the whole catalog and `lead_author.md` calls a coined draft a
    possible wide neighbor, so folding a narrow draft into a wider one is real curation. The
    transfer rule scored attribution against established templates' `covers:` alone, which is a
    narrower set than the `answered_identities` the mint actually reads — so a delete that could
    never cause a re-mint was refused, and the tick's every other edit went with it."""
    repo = tmp_git_repo
    narrow = _mint_uncommitted_draft(repo, "wazuh.narrow-probe")
    wide = _mint_uncommitted_draft(repo, "wazuh.wide-probe")
    minted = lead_author._minted_identities([narrow, wide])

    # The survivor absorbs the narrow one's identities; the narrow one goes.
    wide.write_text(query_template(
        f"wazuh.{lead_author._draft_basename('wazuh.wide-probe')}", "draft",
        covers=[
            f"wazuh.{lead_author._draft_basename('wazuh.wide-probe')}", "wazuh.wide-probe",
            f"wazuh.{lead_author._draft_basename('wazuh.narrow-probe')}", "wazuh.narrow-probe",
        ],
    ))
    narrow.unlink()

    changed = lead_author._verify_skills_state(
        repo, baseline_stray=[], systems=DECLARED, minted=minted
    )
    assert wide.relative_to(repo).as_posix() in changed


def test_a_draft_with_no_covers_is_still_freely_discardable(tmp_git_repo: Path):
    """The control. A hand-authored draft carries no minted identity, so there is nothing to
    orphan and the transfer rule must not invent an obligation — the seeded tree's own
    `_draft/newthing.md` is exactly that shape, and every promotion test in this file depends
    on it staying discardable."""
    repo = tmp_git_repo
    (repo / _CATALOG / "wazuh" / "_draft" / "newthing.md").unlink()
    changed = lead_author._verify_skills_state(repo, baseline_stray=[], systems=DECLARED)
    assert "defender/skills/gather/queries/wazuh/_draft/newthing.md" in changed


def test_an_established_template_may_not_lose_the_identities_it_covers(tmp_git_repo: Path):
    """Monotonicity — the collision detector.

    The L1 write lane admits ANY `{system}/{name}.md` and overwriting an established template
    is a legal fold, so an author who picks a name that already exists gets no error: the write
    silently replaces a different measurement. Dropping that template's `covers:` is what
    separates a clobber from a widen, and it is what the clobbered measurement's future
    re-mints depended on."""
    repo = tmp_git_repo
    established = repo / _CATALOG / "wazuh" / "auth-events.md"
    established.write_text(
        query_template("wazuh.auth-events", "established", covers=["wazuh.old-probe"])
    )
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "covered"], cwd=repo, check=True)

    established.write_text(query_template("wazuh.auth-events", "established"))
    with pytest.raises(lead_author.LeadAuthorError, match="wazuh.old-probe"):
        lead_author._verify_skills_state(repo, baseline_stray=[], systems=DECLARED)


def test_an_established_template_may_not_have_its_id_rewritten(tmp_git_repo: Path):
    """The other half of the clobber: a promote writes a NEW file, so an edit that replaces an
    existing template's `id:` is a name collision that has already overwritten a different
    measurement. Refused by identity rather than by content, because the content of a clobber
    is perfectly well-formed — it is a valid template, just not the one that was there.

    This is also the bound on the repair exemption above: that exemption only forgives an id
    that was WRONG before and right after, so a swap between two WELL-FORMED ids gets no
    relief from it — it is exactly the name collision the monotonicity rule exists to catch."""
    repo = tmp_git_repo
    (repo / _CATALOG / "wazuh" / "auth-events.md").write_text(
        query_template("wazuh.something-else", "established")
    )
    with pytest.raises(lead_author.LeadAuthorError, match="rewrote the identity"):
        lead_author._verify_skills_state(repo, baseline_stray=[], systems=DECLARED)


def test_verify_skills_state_rejects_schema_mutation(tmp_git_repo: Path):
    schema = tmp_git_repo / _CATALOG / "SCHEMA.md"
    schema.write_text(schema.read_text() + "\nstomped\n")
    with pytest.raises(lead_author.LeadAuthorError, match="protected surface"):
        lead_author._verify_skills_state(tmp_git_repo, baseline_stray=[], systems=DECLARED)


def test_verify_skills_state_accepts_draft_discard(tmp_git_repo: Path):
    (tmp_git_repo / _CATALOG / "wazuh" / "_draft" / "newthing.md").unlink()
    changed = lead_author._verify_skills_state(tmp_git_repo, baseline_stray=[], systems=DECLARED)
    assert changed == ["defender/skills/gather/queries/wazuh/_draft/newthing.md"]


def test_verify_skills_state_rejects_a_promotion_whose_placeholder_is_not_a_param(
    tmp_git_repo: Path,
):
    """#901's negative control, at this lane's own seam.

    Until the fold, every gate here was path-shaped — out-of-scope path, protected surface,
    delete-prohibition, half-promote — so a promoted template could name a `${placeholder}` the
    verb does not declare and nothing in the lane would look. `connect`'s check would not catch
    it either: it ran at scaffold time and excluded `_draft/`, the directory this lane mints
    into. The gather lead that then bound the template is refused at `validate_params` with its
    turn already spent."""
    repo = tmp_git_repo
    (repo / _CATALOG / "wazuh" / "newthing.md").write_text(
        query_template(
            "wazuh.newthing", "established",
            body="```query\nverb: search\nparams:\n  index: ${mystery}\n```",
        )
    )
    (repo / _CATALOG / "wazuh" / "_draft" / "newthing.md").unlink()
    with pytest.raises(lead_author.LeadAuthorError, match="mystery"):
        lead_author._verify_skills_state(repo, baseline_stray=[], systems=DECLARED)


def test_verify_skills_state_accepts_a_malformed_draft(tmp_git_repo: Path):
    """The decided SCOPE, pinned so a later widening is deliberate rather than incidental.

    The content gate fires at PROMOTION, not on the lane's `_draft/` writes: a draft is minted
    from a query that really ran, and refusing the batch over one would discard the signal the
    loop wanted. A draft is model-reachable through `template_search` before promotion, which is
    the cost this accepts; the corpus-wide CI sweep (`test_scaffold_rules_901.py`) is where a
    malformed draft is caught, one PR later rather than one commit earlier."""
    repo = tmp_git_repo
    (repo / _CATALOG / "wazuh" / "_draft" / "rough.md").write_text(
        query_template(
            "wazuh.rough", "draft",
            body="```query\nverb: search\nparams:\n  index: ${mystery}\n```",
        )
    )
    changed = lead_author._verify_skills_state(repo, baseline_stray=[], systems=DECLARED)
    assert "defender/skills/gather/queries/wazuh/_draft/rough.md" in changed


def test_is_catalog_template_excludes_what_is_not_a_template(tmp_git_repo: Path):
    """A template lives at `{catalog}/{system}/{name}.md`, and the catalog holds files that are
    not one. The content rule reads a file AS a template (`id:`, `verb:`, a system derived from
    its parent dir), so pointing it at one of those refuses the file for a reason that is not
    its defect — "no `id:`", or the verbs of a system called `queries`.

    A classifier test rather than a `_verify_skills_state` one: since #869 a catalog-root note
    and a `_draft` twin are refused by the MEMBERSHIP rule before any content rule reads them
    (`_membership_segment` yields `NOTES.md`, which no tree declares), so driving this through
    the gate would assert about the wrong refusal. The predicate is what #901 changed.
    """
    assert lead_author._is_catalog_template("defender/skills/gather/queries/wazuh/auth.md")
    # `README.md` is excluded by NAME, not by depth: it sits at `{system}/README.md`, exactly
    # where a template sits, so the depth test alone let the content rule refuse a system's
    # catalog notes for "no `id:`" — the very failure this predicate was split out to stop.
    assert not lead_author._is_catalog_template("defender/skills/gather/queries/wazuh/README.md")
    assert not lead_author._is_catalog_template("defender/skills/gather/queries/NOTES.md")
    assert not lead_author._is_catalog_template("defender/skills/gather/queries/SCHEMA.md")
    assert not lead_author._is_catalog_template(
        "defender/skills/gather/queries/wazuh/_draft/rough.md"
    )
    # EXTRA depth stays IN, `_draft` at extra depth included. `{system}/sub/_draft/x.md` is not
    # the documented draft shape (`_under_draft` is depth-1), so the content rule must still
    # read it and refuse it — its parent dir names no system, so the resolver raises. A
    # `"_draft" not in parts` membership test over every segment handed exactly that shape a
    # silent pass, which is the guard-dropped direction this predicate was split out to avoid.
    assert lead_author._is_catalog_template("defender/skills/gather/queries/wazuh/sub/x.md")
    assert lead_author._is_catalog_template(
        "defender/skills/gather/queries/wazuh/sub/_draft/x.md"
    )


def test_verify_skills_state_rejects_a_promotion_under_a_system_with_no_adapter(
    tmp_git_repo: Path,
):
    """"Could not check" must not read as "nothing wrong". A catalog dir for a system no adapter
    declares is the phantom-system class (#855 F-06) wearing a catalog path, and it is exactly
    the case a resolver that swallowed its own failure would wave through."""
    ghost = tmp_git_repo / _CATALOG / "ghost"
    ghost.mkdir(parents=True)
    (ghost / "x.md").write_text(query_template("ghost.x", "established"))
    # `ghost` is DECLARED here on purpose: #869's membership gate fires before the resolver,
    # so leaving it undeclared would refuse the path for the wrong reason and stop testing that
    # an unresolvable adapter is never swallowed. Declared-but-unresolvable is the real case.
    with pytest.raises(lead_author.LeadAuthorError, match="could not be resolved"):
        lead_author._verify_skills_state(
            tmp_git_repo, baseline_stray=[], systems=DECLARED | {"ghost"},
        )


def test_verify_skills_state_ignores_baseline_stray(tmp_git_repo: Path):
    """A pre-existing stray captured in baseline_stray isn't blamed on the agent."""
    (tmp_git_repo / "defender" / "other").mkdir(parents=True)
    (tmp_git_repo / "defender" / "other" / "preexisting.md").write_text("x")
    baseline = lead_author._author_shared.changes_outside(
        tmp_git_repo, lead_author.SKILLS_REL
    )
    assert "defender/other/preexisting.md" in baseline
    changed = lead_author._verify_skills_state(
        tmp_git_repo, baseline_stray=baseline, systems=DECLARED,
    )
    assert changed == []




def _bypass_tables():
    """Override the two-table read + draft synthesis so the commit/gate flow runs
    against a seeded repo: extract yields one dummy lead, synthesis is a no-op.
    Splatted into ``_deps(...)`` — the agent (faked below) is the only thing that
    touches the corpus."""
    return dict(
        extract=lambda rd: ([], [_executed_lead()]),
        synthesize=lambda executed, catalog_dir=None, catalog=None, systems=None: [],
    )


def test_run_loop_commits_agent_edits(tmp_git_repo: Path, tmp_path: Path):
    """End-to-end: the agent (faked) edits the worktree and runs no git; the loop
    verifies + commits exactly the skills delta with a generated message + writes done."""
    repo = tmp_git_repo
    run_dir = tmp_path / "lead-run"
    run_dir.mkdir()

    def fake_agent(rd, handoffs, pending, *, box=None):
        (repo / _CATALOG / "wazuh" / "newthing.md").write_text(
            query_template("wazuh.newthing", "established")
        )
        (repo / _CATALOG / "wazuh" / "_draft" / "newthing.md").unlink()
        return 0

    deps = _deps(
        repo,
        **_bypass_tables(),
        invoke_agent=fake_agent,
        build_handoff=lambda rd, ex, jl=None, **_: [{"query_id": "wazuh.newthing"}],
        discover_system_drafts=lambda: [],
        acquire_queue_lock=lambda: object(),
        release_queue_lock=lambda fh: None,
    )
    head_before = _run_git(repo, "rev-parse", "HEAD").stdout.strip()
    assert lead_author.run(run_dir, deps=deps) == 0
    head_after = _run_git(repo, "rev-parse", "HEAD").stdout.strip()
    assert head_after != head_before, "the loop should have committed"
    changed = _run_git(repo, "diff", "--name-only", "HEAD~1", "HEAD").stdout.split()
    assert changed
    assert all(p.startswith("defender/skills/") for p in changed)
    assert "defender/skills/gather/queries/wazuh/newthing.md" in changed
    msg = _run_git(repo, "log", "-1", "--format=%B").stdout
    assert "lead-author" in msg
    assert run_dir.name in msg
    assert (run_dir / "lead_author" / "done").is_file()


def test_run_raises_and_skips_commit_on_scope_violation(tmp_git_repo: Path, tmp_path: Path):
    """A stray edit makes the gate raise LeadAuthorError (the drain quarantines the
    marker); the loop commits nothing and writes no done sentinel."""
    repo = tmp_git_repo
    run_dir = tmp_path / "lead-run"
    run_dir.mkdir()

    def fake_agent(rd, handoffs, pending, *, box=None):
        (repo / "defender" / "other").mkdir(parents=True, exist_ok=True)
        (repo / "defender" / "other" / "stray.md").write_text("stray")
        return 0

    deps = _deps(
        repo,
        **_bypass_tables(),
        invoke_agent=fake_agent,
        build_handoff=lambda rd, ex, jl=None, **_: [{"query_id": "x.y"}],
        discover_system_drafts=lambda: [],
        acquire_queue_lock=lambda: object(),
        release_queue_lock=lambda fh: None,
    )
    head_before = _run_git(repo, "rev-parse", "HEAD").stdout.strip()
    with pytest.raises(lead_author.LeadAuthorError):
        lead_author.run(run_dir, deps=deps)
    assert _run_git(repo, "rev-parse", "HEAD").stdout.strip() == head_before
    assert not (run_dir / "lead_author" / "done").is_file()


def test_run_returns_rc2_on_nonzero_agent_exit(tmp_git_repo: Path, tmp_path: Path):
    """A non-zero agent exit (crash/timeout) makes ``run`` return 2 — the drain
    quarantines the marker. The loop commits nothing, writes no done sentinel, and
    (post-#426) writes no ``failure.txt`` brake (quarantine is the sole surfacing)."""
    repo = tmp_git_repo
    run_dir = tmp_path / "lead-run"
    run_dir.mkdir()
    deps = _deps(
        repo,
        **_bypass_tables(),
        invoke_agent=lambda rd, handoffs, pending, **_kw: 124,
        build_handoff=lambda rd, ex, jl=None, **_: [{"query_id": "x.y"}],
        discover_system_drafts=lambda: [],
        acquire_queue_lock=lambda: object(),
        release_queue_lock=lambda fh: None,
    )
    head_before = _run_git(repo, "rev-parse", "HEAD").stdout.strip()
    assert lead_author.run(run_dir, deps=deps) == 2
    assert _run_git(repo, "rev-parse", "HEAD").stdout.strip() == head_before
    assert not (run_dir / "lead_author" / "done").is_file()
    assert not (run_dir / "lead_author" / "failure.txt").exists()


def test_run_loop_clears_drafts_on_discard_and_promote(tmp_git_repo: Path, tmp_path: Path):
    """The fake-LLM stand-in for the live ``--lead-author-drain`` check: the agent does a
    discard (``rm`` a draft) AND a promote (write established + ``rm`` its draft) in the
    worktree; after ``run`` the loop has committed and *both* draft files are actually gone
    — neither left on disk nor tracked — with the promoted established template present and
    no established+draft duplicate. This is what the live ``rm``-under-allowlist run was to
    confirm; only the real Claude Code Bash matcher is out of frame here (the grant uses the
    documented ``:*`` form), the loop's commit/clear logic is end-to-end."""
    repo = tmp_git_repo
    (repo / _CATALOG / "wazuh" / "_draft" / "olddraft.md").write_text(
        query_template("wazuh.olddraft", "draft")
    )
    _run_git(repo, "add", "-A")
    _run_git(repo, "commit", "-q", "-m", "seed second draft")
    run_dir = tmp_path / "lead-run"
    run_dir.mkdir()

    promoted_est = repo / _CATALOG / "wazuh" / "newthing.md"
    promoted_draft = repo / _CATALOG / "wazuh" / "_draft" / "newthing.md"
    discarded_draft = repo / _CATALOG / "wazuh" / "_draft" / "olddraft.md"

    def fake_agent(rd, handoffs, pending, *, box=None):
        promoted_est.write_text(query_template("wazuh.newthing", "established"))
        promoted_draft.unlink()
        discarded_draft.unlink()
        return 0

    deps = _deps(
        repo,
        **_bypass_tables(),
        invoke_agent=fake_agent,
        build_handoff=lambda rd, ex, jl=None, **_: [{"query_id": "wazuh.newthing"}],
        discover_system_drafts=lambda: [],
        acquire_queue_lock=lambda: object(),
        release_queue_lock=lambda fh: None,
    )
    assert lead_author.run(run_dir, deps=deps) == 0
    assert not promoted_draft.exists()
    assert not discarded_draft.exists()
    assert promoted_est.is_file()
    tracked = _run_git(repo, "ls-files", "defender/skills/").stdout.split()
    assert "defender/skills/gather/queries/wazuh/newthing.md" in tracked
    assert "defender/skills/gather/queries/wazuh/_draft/newthing.md" not in tracked
    assert "defender/skills/gather/queries/wazuh/_draft/olddraft.md" not in tracked
    assert (run_dir / "lead_author" / "done").is_file()


def test_run_quarantines_half_promote(tmp_git_repo: Path, tmp_path: Path):
    """End-to-end: the agent writes a promote's established template but forgets the draft
    ``rm`` (the silent-loss case A1's matcher fix can't prevent if the model omits it). The
    loop's half-promote gate raises through ``run`` → no commit, no ``done`` → the drain
    quarantines the marker instead of committing established + draft together."""
    repo = tmp_git_repo
    run_dir = tmp_path / "lead-run"
    run_dir.mkdir()

    def fake_agent(rd, handoffs, pending, *, box=None):
        (repo / _CATALOG / "wazuh" / "newthing.md").write_text(
            query_template("wazuh.newthing", "established")
        )
        return 0

    deps = _deps(
        repo,
        **_bypass_tables(),
        invoke_agent=fake_agent,
        build_handoff=lambda rd, ex, jl=None, **_: [{"query_id": "wazuh.newthing"}],
        discover_system_drafts=lambda: [],
        acquire_queue_lock=lambda: object(),
        release_queue_lock=lambda fh: None,
    )
    head_before = _run_git(repo, "rev-parse", "HEAD").stdout.strip()
    with pytest.raises(lead_author.LeadAuthorError, match="half-promote"):
        lead_author.run(run_dir, deps=deps)
    assert _run_git(repo, "rev-parse", "HEAD").stdout.strip() == head_before
    assert not (run_dir / "lead_author" / "done").is_file()




def test_run_refuses_a_bare_discard_of_a_draft_it_minted_this_tick(
    tmp_git_repo: Path, tmp_path: Path
):
    """End-to-end, through `run` — the WIRING, not the rule.

    The rule's own tests hand `_verify_skills_state` a `minted` mapping they built themselves,
    so every one of them passes against a `_run_locked` that stopped threading it. That is the
    shape of the defect this test exists for: the transfer rule was unit-tested from the moment
    it was written and was still inert in production, because the drafts it was written to guard
    are minted untracked in the same tick and no test drove that path. Here the mint is the real
    one (`synthesize_drafts` off a real queries row), the discard is the agent's, and the only
    thing under test is that the two are connected."""
    repo = tmp_git_repo
    run_dir = tmp_path / "lead-run"
    (run_dir / "gather_raw").mkdir(parents=True)
    _write_lead_meta(run_dir, "l-001", "probe a brand-new measurement")
    _write_query(run_dir, "l-001", 0, "wazuh.hunt-failed-logins", verb="search",
                 payload_status="ok")

    def fake_agent(rd, handoffs, pending, *, box=None):
        # A bare discard: `rm` the minted draft, attribute it nowhere.
        minted = repo / _CATALOG / "wazuh" / "_draft" / (
            f"{lead_author._draft_basename('wazuh.hunt-failed-logins')}.md"
        )
        assert minted.is_file(), "the mint did not produce the draft this test is about"
        minted.unlink()
        return 0

    deps = replace(
        lead_author.build_lead_author_deps(LoopPaths(repo_root=repo, state_dir=tmp_path / "st")),
        acquire_queue_lock=lambda: object(),
        release_queue_lock=lambda fh: None,
        invoke_agent=fake_agent,
    )
    head_before = _run_git(repo, "rev-parse", "HEAD").stdout.strip()
    with pytest.raises(lead_author.LeadAuthorError, match="wazuh.hunt-failed-logins"):
        lead_author.run(run_dir, deps=deps)
    assert _run_git(repo, "rev-parse", "HEAD").stdout.strip() == head_before
    assert not (run_dir / "lead_author" / "done").is_file()


def test_prepare_handoffs_below_lift_threshold_returns_empty_drafts(
    run_dir: Path, monkeypatch
):
    """Pending drafts below threshold are silenced; executed handoffs unaffected.

    Stubs out the executed-flow primitives so this test exercises only the
    threshold gate, independent of which query templates exist in the catalog.
    """
    fake_executed = [_executed_lead()]
    fake_handoff = [{
        "query_id": "fake.lead", "status": "established",
        "executed_template_path": "defender/skills/gather/queries/fake/lead.md",
        "neighbors": [], "invocations": [],
    }]
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "5")
    deps = _deps(
        run_dir.parent,
        extract=lambda rd: ([], fake_executed),
        build_handoff=lambda rd, ex, jl=None, **_: fake_handoff,
        discover_system_drafts=lambda: [Path("/fake/a.md"), Path("/fake/b.md")],
    )
    handoffs, drafts, rc = lead_author._prepare_handoffs(run_dir, deps)
    assert rc is None
    assert handoffs == fake_handoff
    assert drafts == []


def test_prepare_handoffs_at_threshold_surfaces_drafts(
    run_dir: Path, monkeypatch, tmp_path
):
    """At-or-above threshold → drafts surface alongside executed handoffs."""
    fake_handoff = [{
        "query_id": "fake.lead", "status": "established",
        "executed_template_path": "defender/skills/gather/queries/fake/lead.md",
        "neighbors": [], "invocations": [],
    }]
    skills = tmp_path / "defender" / "skills"
    (skills / "elastic" / "_draft").mkdir(parents=True)
    drafts = [
        skills / "elastic" / "_draft" / "a.md",
        skills / "elastic" / "_draft" / "b.md",
    ]
    for d in drafts:
        d.write_text("---\nstatus: draft\n---\n")
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "2")
    deps = _deps(
        tmp_path,
        extract=lambda rd: ([], [_executed_lead()]),
        build_handoff=lambda rd, ex, jl=None, **_: fake_handoff,
        discover_system_drafts=lambda: drafts,
    )

    handoffs, pending, rc = lead_author._prepare_handoffs(run_dir, deps)
    assert rc is None
    assert handoffs == fake_handoff
    assert len(pending) == 2
    assert pending[0]["system"] == "elastic"
    assert pending[0]["skill_path"] == "defender/skills/elastic/SKILL.md"


def test_prepare_handoffs_drafts_only_no_executed_proceeds(
    run_dir: Path, monkeypatch, tmp_path
):
    """No executed leads + drafts at threshold → proceed with drafts only."""
    skills = tmp_path / "defender" / "skills"
    (skills / "elastic" / "_draft").mkdir(parents=True)
    drafts = [skills / "elastic" / "_draft" / f"d{i}.md" for i in range(2)]
    for d in drafts:
        d.write_text("---\nstatus: draft\n---\n")
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "1")
    deps = _deps(tmp_path, discover_system_drafts=lambda: drafts)

    handoffs, pending, rc = lead_author._prepare_handoffs(run_dir, deps)
    assert rc is None
    assert handoffs == []
    assert len(pending) == 2


def test_prepare_handoffs_both_empty_exits_zero(run_dir: Path):
    """No executed leads AND no pending drafts → early exit 0, no work."""
    deps = _deps(run_dir.parent, discover_system_drafts=lambda: [])
    handoffs, pending, rc = lead_author._prepare_handoffs(run_dir, deps)
    assert rc == 0
    assert handoffs == []
    assert pending == []


def _capture_engine(monkeypatch, *, rc: int = 0, raise_exc=None):
    """Patch the in-process engine seam the spawn spine calls. ``_spawn_author_agent`` looks up
    ``run_author_stage`` on the engine module at call time, so patching the module attr is seen. Captures the kwargs the
    spawn forwards to the engine + returns a canned rc / raises."""
    from defender.learning.leads import lead_author_engine

    cap: dict = {}

    def _fake(**kwargs):
        cap.update(kwargs)
        # #713: the spawn now forwards a StageWiring/StageContext pair. Flatten the fields
        # the cases assert on back onto `cap`, so each case still names one knob.
        if (w := kwargs.get("wiring")) is not None:
            cap.update(system_prompt_file=w.prompt_path, model=w.model,
                       effort=w.effort, trace_name=w.trace_name, label=w.label)
        if (c := kwargs.get("ctx")) is not None:
            cap.update(user_prompt=c.user, learning_run_dir=c.learning_run_dir,
                       repo_root=c.repo_root, request_limit=c.request_limit,
                       timeout=c.wall_clock_timeout, box=c.box, salt=c.salt)
        if raise_exc is not None:
            raise raise_exc
        return rc

    monkeypatch.setattr(  # lint-monkeypatch: ok — the spawn spine has no DI seam; capture engine kwargs
        lead_author_engine, "run_author_stage", _fake
    )
    return cap


def test_invoke_agent_pending_drafts_reach_engine_user_prompt(run_dir: Path, monkeypatch):
    """(GLM-port rewrite) invoke_agent no longer spawns ``claude -p`` — it routes to the in-process
    engine. Assert the handoff envelope reaches the engine as the ``user_prompt`` PAYLOAD (not
    merely that a rc came back): the whole prompt survives the transport swap."""
    cap = _capture_engine(monkeypatch)
    handoffs = [{"query_id": "wazuh.auth-events", "status": "established",
                 "executed_template_path": "defender/skills/gather/queries/wazuh/auth-events.md",
                 "neighbors": [], "invocations": []}]
    pending = [{"draft_path": "defender/skills/elastic/_draft/falco-na.md",
                "system": "elastic",
                "skill_path": "defender/skills/elastic/SKILL.md"}]
    rc = lead_author.invoke_agent(run_dir, handoffs, pending)
    assert rc == 0
    prompt = cap["user_prompt"]
    assert re.search(r"<run-[0-9a-f]+-handoffs>", prompt)
    assert re.search(r"<run-[0-9a-f]+-pending_system_drafts>", prompt)
    assert "elastic/_draft/falco-na.md" in prompt
    assert "skills_dir: defender/skills/" in prompt




def test_extract_carries_error_class(run_dir: Path):
    """An errored query's row back-fills error_class from exit_code, and extract
    threads it onto the ExecutedLead."""
    _write_lead_meta(run_dir, "l-001", "probe")
    _write_query(run_dir, "l-001", 0, "elastic.esql", payload_status="error")
    _, leads = lead_author.extract(run_dir)
    assert leads[0].error_class == "agent-fixable"


def test_collect_general_failures_residue_only(tmp_path: Path, catalog: Path):
    """Only agent-fixable errors that resolve to no template AND are not draft
    candidates are collected — the residue build_handoff would silently drop."""
    run_dir = tmp_path / "run-abc"
    leads = [
        _executed_lead(lead_id="l-001", query_index=0, query_id="elastic.esql",
                       error_class="agent-fixable", payload_digest="exit=1; bad pipe"),
        _executed_lead(lead_id="l-002", query_id="elastic.auth-events",
                       error_class="agent-fixable"),
        _executed_lead(lead_id="l-003", query_id="elastic.new-thing",
                       error_class="agent-fixable"),
        _executed_lead(lead_id="l-004", query_id="elastic.esql", error_class="infra"),
        _executed_lead(lead_id="l-005", query_id="elastic.esql", error_class=None),
    ]
    out = lead_author.collect_general_failures(leads, run_dir, catalog_dir=catalog)
    assert [r["query_id"] for r in out] == ["elastic.esql"]
    r = out[0]
    assert r["pitfall_id"] == "run-abc:l-001:0"
    assert r["source_run"] == "run-abc"
    assert r["system"] == "elastic"
    assert r["error_class"] == "agent-fixable"
    assert r["stderr_digest"] == "exit=1; bad pipe"


def test_collect_and_synthesize_partition_disjointly(tmp_path: Path, catalog: Path):
    """A coined query_id is drafted XOR collected as a general failure, never both
    — the shared _draft_candidate_segments predicate keeps the paths disjoint."""
    leads = [
        _executed_lead(lead_id="l-001", query_id="elastic.new-thing", error_class="agent-fixable"),
        _executed_lead(lead_id="l-002", query_id="elastic.esql", error_class="agent-fixable"),
    ]
    by_id = {t.id for t in lead_author.lead_neighbors.load_catalog(catalog)}
    drafted = {ld.query_id for ld in leads
               if lead_author._draft_candidate_segments(
                   ld.query_id, ld.verb, by_id, row_system=ld.system) is not None}
    collected = {r["query_id"]
                 for r in lead_author.collect_general_failures(leads, tmp_path / "r", catalog_dir=catalog)}
    assert drafted == {"elastic.new-thing"}
    assert collected == {"elastic.esql"}
    assert drafted.isdisjoint(collected)


def test_run_collects_general_failure_before_early_return(tmp_git_repo: Path, tmp_path: Path):
    """The collection runs before _prepare_handoffs' done-sentinel early-return (the
    all-unresolved case is the very source of general failures), lands in the central
    queue, and the pitfalls_collected sentinel makes a re-run idempotent. repo_root is
    a real git repo (the tick runs `git status` for its stray baseline); the queue
    resolves to an out-of-repo state dir."""
    paths = LoopPaths(repo_root=tmp_git_repo, state_dir=tmp_path / "state")
    deps = replace(
        lead_author.build_lead_author_deps(paths),
        acquire_queue_lock=lambda: object(),
        release_queue_lock=lambda fh: None,
        invoke_agent=lambda *a, **k: 0,
    )
    run_dir = tmp_path / "run-xyz"
    (run_dir / "gather_raw").mkdir(parents=True)
    _write_lead_meta(run_dir, "l-001", "probe")
    _write_query(run_dir, "l-001", 0, "elastic.esql", payload_status="error")

    assert lead_author.run(run_dir, deps=deps) == 0
    queue = deps.paths.pitfalls.file
    rows = [json.loads(ln) for ln in queue.read_text().splitlines()]
    assert [r["query_id"] for r in rows] == ["elastic.esql"]
    assert rows[0]["error_class"] == "agent-fixable"
    assert (run_dir / "lead_author" / "pitfalls_collected").is_file()

    (run_dir / "lead_author" / "done").unlink()
    assert lead_author.run(run_dir, deps=deps) == 0
    rows2 = [json.loads(ln) for ln in queue.read_text().splitlines()]
    assert len(rows2) == 1


def test_run_reloads_catalog_after_mint_so_minted_draft_resolves(
    tmp_git_repo: Path, tmp_path: Path
):
    """The reload-on-mint hinge: when synthesize_drafts mints a draft for an
    uncatalogued verb this tick, `_run_locked` refreshes the once-loaded catalog so
    build_handoff (the post-synthesis consumer) sees the new `_draft/` and the
    just-minted query_id resolves into a handoff (the WARN-and-draft path) instead of
    being dropped (WARN-and-drop). Uses production synthesize + build_handoff, so it
    guards against a regression that reused the stale pre-synthesis snapshot — which
    would silently drop every just-minted draft's handoff."""
    paths = LoopPaths(repo_root=tmp_git_repo, state_dir=tmp_path / "state")
    seen: dict = {}
    deps = replace(
        lead_author.build_lead_author_deps(paths),
        acquire_queue_lock=lambda: object(),
        release_queue_lock=lambda fh: None,
        invoke_agent=lambda rd, handoffs, pending, **_kw: seen.update(handoffs=handoffs) or 0,
    )
    run_dir = tmp_path / "run-mint"
    (run_dir / "gather_raw").mkdir(parents=True)
    _write_lead_meta(run_dir, "l-001", "probe a brand-new verb")
    _write_query(run_dir, "l-001", 0, "wazuh.brandnew", verb="lookup", payload_status="ok")

    assert lead_author.run(run_dir, deps=deps) == 0
    minted = lead_author._draft_basename("wazuh.brandnew")
    assert (tmp_git_repo / _CATALOG / "wazuh" / "_draft" / f"{minted}.md").is_file()
    # The row still resolves, through `covers:` rather than through a matching `id:`. The
    # draft's name is now derived, so the coined `wazuh.brandnew` the row carries is no
    # template's id — and a `by_id` that indexed only ids would drop this row as an unresolved
    # contract violation, handing the author nothing about the draft this tick just minted.
    assert f"wazuh.{minted}" in {h["query_id"] for h in seen["handoffs"]}


def test_collect_general_failures_skips_systemless(tmp_path: Path, catalog: Path):
    """A failure with a blank system is never collected — it has no
    defender/skills/{system}/execution.md to fold into."""
    leads = [
        _executed_lead(lead_id="l-001", query_id="elastic.esql", system="",
                       error_class="agent-fixable"),
    ]
    out = lead_author.collect_general_failures(leads, tmp_path / "r", catalog_dir=catalog)
    assert out == []






def test_verify_skills_stray_wins_over_in_corpus_violation(tmp_git_repo: Path):
    """A stray edit AND an in-corpus deletion together → the stray-gate error
    ('outside') is raised, proving the preamble runs before the per-path loop (a
    loop-first order would surface 'delete-prohibition', which lacks 'outside')."""
    (tmp_git_repo / "defender" / "other").mkdir(parents=True)
    (tmp_git_repo / "defender" / "other" / "stray.md").write_text("stray")
    (tmp_git_repo / _CATALOG / "wazuh" / "auth-events.md").unlink()
    with pytest.raises(lead_author.LeadAuthorError, match="outside"):
        lead_author._verify_skills_state(tmp_git_repo, baseline_stray=[], systems=DECLARED)


def test_verify_skills_state_returns_sorted_changed(tmp_git_repo: Path):
    """Two in-scope edits whose paths interleave ACROSS git's status-class boundary →
    the returned list is sorted (path order, not git-status order). This discriminates
    `return sorted(changed)`: git lists all changed-class records before all
    untracked-class ones (each class internally sorted), so a modified catalog file
    (`.../gather/...`, sorts LATE) precedes an untracked system draft
    (`.../elastic/...`, sorts EARLY) in raw git order — only `sorted()` flips them.
    A regression to `return changed` would return git order and fail this."""
    (tmp_git_repo / _CATALOG / "wazuh" / "auth-events.md").write_text(
        query_template("wazuh.auth-events", "established") + "\n# folded\n"
    )
    (tmp_git_repo / "defender" / "skills" / "elastic" / "_draft" / "aa-new.md").write_text(
        "---\nid: elastic.aa-new\nstatus: draft\n---\n# new\n"
    )
    changed = lead_author._verify_skills_state(tmp_git_repo, baseline_stray=[], systems=DECLARED)
    assert changed == [
        "defender/skills/elastic/_draft/aa-new.md",
        "defender/skills/gather/queries/wazuh/auth-events.md",
    ]




def test_invoke_agent_wires_engine_kwargs(run_dir: Path, tmp_path: Path, monkeypatch):
    """(rewrite of the RunnerOptions options-wiring) The spawn hands the engine the lead-author
    prompt, the run-dir-named batch id, the injected repo_root (distinguishing it from the
    pitfalls spawn), and the run_dir as the learning trace anchor. The model/effort/request_limit
    default INSIDE run_author_stage from config (pinned in test_lead_author_engine), so they are
    not forwarded here — only the per-spawn wiring is.

    Since #713 the batch id is no longer its own engine kwarg: it is carried by the
    StageWiring the spawn builds, so it stays observable on the trace name and label."""
    cap = _capture_engine(monkeypatch)
    lead_author.invoke_agent(run_dir, [], repo_root=tmp_path)
    assert cap["system_prompt_file"] == lead_author.LEAD_AUTHOR_PROMPT
    assert cap["trace_name"].startswith(f"{run_dir.name}.")
    assert cap["label"].endswith(f":{run_dir.name}")
    assert cap["repo_root"] == tmp_path
    assert cap["learning_run_dir"] == run_dir


def test_invoke_agent_config_fault_propagates(run_dir: Path, tmp_path: Path, monkeypatch):
    """(replaces runner-error-maps-to-124) F1: a systemic FatalConfigError from the engine
    PROPAGATES through invoke_agent — it is NOT swallowed into an rc, so a deployment-wide
    misconfig fails loudly instead of quarantining every marker."""
    from defender.learning.core.config import FatalConfigError
    _capture_engine(monkeypatch, raise_exc=FatalConfigError("needs FIREWORKS_API_KEY"))
    with pytest.raises(FatalConfigError):
        lead_author.invoke_agent(run_dir, [], repo_root=tmp_path)


def test_invoke_agent_passes_through_engine_rc(run_dir: Path, tmp_path: Path, monkeypatch):
    """A per-run rc from the engine (124 from a RunUnprocessable inside run_author_stage) is
    returned unchanged — the caller then maps rc != 0 → 2 → drain quarantine."""
    _capture_engine(monkeypatch, rc=124)
    assert lead_author.invoke_agent(run_dir, [], repo_root=tmp_path) == 124




# `_loop_commit_message` derives the commit SCOPE from the changed paths alone. Each row is
# one path shape and the scope it must produce — and, where it matters, the scope it must NOT
# produce: a message that named both scopes for a catalog-only batch would read as a wider
# edit than the one that happened.
@pytest.mark.parametrize(("case", "changed", "present", "absent"), [
    ("catalog-only", ["defender/skills/gather/queries/wazuh/auth-events.md"],
     ["gather catalog for run-123"], ["system skills"]),

    ("skill-md-only", ["defender/skills/elastic/SKILL.md"],
     ["learning(lead-author): system skills for run-123"], ["gather catalog"]),

    # a system-skill _draft is NOT a catalog path, so it counts as system-skills scope
    ("system-draft-counts-as-skill", ["defender/skills/elastic/_draft/falco-na.md"],
     ["system skills"], ["gather catalog"]),

    ("catalog-and-skill-together",
     ["defender/skills/gather/queries/wazuh/auth-events.md",
      "defender/skills/elastic/SKILL.md"],
     ["gather catalog + system skills"], []),

    # The loop message is built UNCONDITIONALLY, even for an empty change set, so it has to
    # render (no catalog/skill ⇒ 'gather catalog') rather than crash.
    ("empty-change-set", [],
     ["gather catalog for run-123", "\n\nsource-run: run-123\n"], []),
], ids=lambda v: v if isinstance(v, str) and len(v) < 40 and "/" not in v else "")
def test_loop_commit_message_scope_follows_the_changed_paths(case, changed, present, absent):
    """The subject line names the scope the batch actually touched — catalog, system skills,
    or both — and never a scope nothing in `changed` supports."""
    msg = lead_author._loop_commit_message(Path("run-123"), changed)
    for fragment in present:
        assert fragment in msg
    for fragment in absent:
        assert fragment not in msg


def test_loop_commit_message_lists_paths_and_source_run_trailer():
    """Body lists each changed path as '- {p}' in order; trailer carries source-run."""
    changed = [
        "defender/skills/gather/queries/wazuh/a.md",
        "defender/skills/gather/queries/wazuh/b.md",
    ]
    msg = lead_author._loop_commit_message(Path("run-123"), changed)
    assert "git).\n\nPaths:\n- defender/skills/gather/queries/wazuh/a.md\n" in msg
    assert (
        "- defender/skills/gather/queries/wazuh/a.md\n"
        "- defender/skills/gather/queries/wazuh/b.md\n"
        "\nsource-run: run-123\n"
    ) in msg


