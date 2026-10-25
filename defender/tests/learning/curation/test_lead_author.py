"""Lead-author driver: lead extraction, handoff shape, lock/sentinel paths, and the post-flight skills scope gate.

#1108 P4 (O7, amendments 2-3): the lane works over a git-free draft of a P3 batch, never a product
worktree. Every gate case drives the REAL tick (`lead_author.run`) with the spawn faked as an edit
of the draft's `agent/skills/`, and reads what landed from the batch branch (`agent/...`, OD6).
ASSUMED SEAM (S-H, `_curator1134`): `lead_author.build_lead_author_deps(paths, *, state, trees,
batch)`. `paths.repo_root` is the product checkout holding the adapters only (#1172).
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from defender.learning.leads import lead_author  # type: ignore[import-not-found]
from defender.tests.support.shared.contracts._repo import query_template, seed_skills_repo
from defender.learning.core.config import LEAD_AUTHOR_DRAIN_LABEL
from defender.learning.core.state import LEAD_QUEUE_LOCK, PITFALLS, TRY_ONCE
from defender.tests.support.learning.curation import _curator1134 as C
from defender.tests.support.learning.curation._curator1134 import open_state
from defender.tests.support.learning.curation._lead_author_1134 import repo_skills, skills_view
from defender.tests.support.learning.core._state1135 import curation_run_dir, run_of
from defender.tests.support.learning.core._state1135 import state_over, set_state_dir
from defender.tests.support.shared._locations_1210 import location_path


#: The seeded catalog, agent-relative (where it sits in the draft) and repo-relative (OD6).
_CATALOG = "skills/gather/queries"
CATALOG_REL = f"agent/{_CATALOG}"


def _product(tmp_path: Path, seeded: Path) -> Path:
    """The product checkout `paths.repo_root` names: the seeded adapters only, committed (adapters
    stay in the product repo, #1172); no corpus (O1)."""
    product = tmp_path / "product"
    shutil.copytree(seeded / "defender" / "integrations", product / "defender" / "integrations")
    for args in (("init", "-q", "-b", "main"), ("config", "user.email", "t@t"),
                 ("config", "user.name", "t"), ("add", "-A"), ("commit", "-q", "-m", "adapters")):
        subprocess.run(["git", *args], cwd=product, check=True)
    return product


def _lane(tmp_path: Path, files: dict[str, str] | None = None) -> C.DraftLane:
    """The seeded skills tree (`seed_skills_repo`: an established and a draft `wazuh` template,
    `SCHEMA.md`, `elastic`'s SKILL.md with a pending `_draft/`) as the tenant's `agent/skills`,
    plus `files` (agent-relative) in the same export commit; then P3's `start_batch` with the
    lead lane `skills`."""
    seeded = seed_skills_repo(tmp_path / "seed")
    agent = tmp_path / "agent-src"
    shutil.copytree(seeded / "defender" / "skills", agent / "skills")
    for rel, text in (files or {}).items():
        C.put(agent / rel, text)
    return C.draft_lane(tmp_path, lanes=C.LEAD_LANES, agent=agent,
                        product=_product(tmp_path, seeded))


def _deps(lane: C.DraftLane, **overrides):
    """REAL lead-author deps over the lane's draft (ASSUMED SEAM `batch=`), leaf collaborators
    overridden by keyword — replaces monkeypatching lead_author's own functions."""
    deps = lead_author.build_lead_author_deps(
        lane.paths, state=open_state(lane.paths), trees=C.draft_trees(lane), batch=lane.batch)
    return replace(deps, **overrides) if overrides else deps


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
def run_dir() -> Path:
    # A natural run where run setup leaves one (`<data root>/<T>/runs/<id>`): the lane takes it
    # as the `Run` its open hands it (`run_of`, #1105 PR 2).
    rd = curation_run_dir("test-run-001")
    (rd / "gather_raw").mkdir()
    return rd


@pytest.fixture
def catalog(tmp_path: Path) -> Path:
    """Self-contained query catalog so build_handoff resolves ids without
    depending on the live, environment-specific on-disk catalog (v2 ships an
    elastic/host-state/cmdb catalog; main ships wazuh). Returns the catalog dir;
    tests pass it as ``build_handoff(..., repo_root=catalog.parent,
    skills=skills_view(catalog.parents[1]), where=catalog.parents[1])``
    (the read root + the relative-path anchor), so no module-global patch is needed."""
    cat = tmp_path / "skills" / "gather" / "queries"
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
        run_dir, leads, repo_root=catalog.parent, skills=skills_view(catalog.parents[1]),
        where=catalog.parents[1]
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


def test_build_handoff_drops_unresolved_query_id(run_dir: Path, catalog: Path):
    """Unresolved query_id ⇒ skip with a corpus-health warning, don't crash."""
    _write_lead_meta(run_dir, "l-001", "novel")
    _write_query(run_dir, "l-001", 0, "elastic.does-not-exist")
    _write_lead_meta(run_dir, "l-002", "real one")
    _write_query(run_dir, "l-002", 0, "elastic.auth-events")
    _, leads = lead_author.extract(run_dir)
    assert len(leads) == 2
    handoffs = lead_author.build_handoff(
        run_dir, leads, repo_root=catalog.parent, skills=skills_view(catalog.parents[1]),
        where=catalog.parents[1]
    )
    assert len(handoffs) == 1
    assert handoffs[0]["query_id"] == "elastic.auth-events"


def test_build_handoff_drops_ad_hoc_empty_query_id(run_dir: Path):
    _write_lead_meta(run_dir, "l-001", "ad-hoc")
    _write_query(run_dir, "l-001", 0, "")
    _, leads = lead_author.extract(run_dir)
    handoffs = lead_author.build_handoff(run_dir, leads, **repo_skills())
    assert handoffs == []


def test_build_handoff_one_handoff_per_template_cross_system(run_dir: Path, catalog: Path):
    """A multi-query, cross-system lead yields one handoff per executed template."""
    _write_lead_meta(run_dir, "l-001", "cross-system")
    _write_query(run_dir, "l-001", 0, "elastic.auth-events")
    _write_query(run_dir, "l-001", 1, "host-state.process-list", {"pattern": "x"})
    _, leads = lead_author.extract(run_dir)
    handoffs = lead_author.build_handoff(
        run_dir, leads, repo_root=catalog.parent, skills=skills_view(catalog.parents[1]),
        where=catalog.parents[1]
    )
    assert len(handoffs) == 2
    by_id = {h["query_id"]: h for h in handoffs}
    assert set(by_id) == {"elastic.auth-events", "host-state.process-list"}
    assert len(by_id["elastic.auth-events"]["invocations"]) == 1


def _claude_should_not_be_called(*args, **kwargs):
    raise AssertionError("claude was spawned despite gating check")


def test_run_held_queue_lock_reports_a_skip_not_a_serve(run_dir: Path, tmp_path: Path):
    deps = _deps(_lane(tmp_path), invoke_agent=_claude_should_not_be_called)
    with deps.state.lock(LEAD_QUEUE_LOCK, wait=TRY_ONCE) as held:
        assert held, "the test could not take the queue lock it means to hold"
        rc = lead_author.run(run_of(run_dir), label=LEAD_AUTHOR_DRAIN_LABEL, deps=deps)
    assert rc == lead_author.QUEUE_LOCK_SKIP_RC
    assert rc != 0


@pytest.mark.parametrize("held_root", ["tenant", "legacy"])
def test_1186_lead_author_cli_takes_the_runs_tenant_queue_lock(
    run_dir, tmp_path, monkeypatch, held_root,
):
    """O2: the CLI uses its Run's tenant for the queue lock and pitfall writes."""
    set_state_dir(monkeypatch, tmp_path / "legacy-state")
    learning = run_dir.parent.parent / "learning"
    _write_lead_meta(run_dir, "l-001", "failed query")
    _write_query(run_dir, "l-001", 0, "idp.query", payload_status="error")
    learning.mkdir(exist_ok=True)
    root = learning if held_root == "tenant" else tmp_path / "legacy-state"
    with (state_over(root) as holder, holder.lock(LEAD_QUEUE_LOCK, wait=TRY_ONCE) as held):
        assert held
        rc = lead_author.main(["--tenant", run_dir.parent.parent.name, run_dir.name])
    assert rc == (lead_author.QUEUE_LOCK_SKIP_RC if held_root == "tenant" else 0)
    if held_root == "tenant":
        assert not (run_dir / "lead_author" / "pitfalls_collected").exists()
        assert not (learning / PITFALLS.queue).exists()
        assert not (tmp_path / "legacy-state" / LEAD_QUEUE_LOCK.file).exists()
    else:
        rows = [json.loads(line) for line in (learning / PITFALLS.queue).read_text().splitlines()]
        assert [(row["source_run"], row["query_id"]) for row in rows] == [(run_dir.name, "idp.query")]
    assert not (tmp_path / "legacy-state" / PITFALLS.queue).exists()


def test_run_done_sentinel_short_circuits(run_dir: Path, tmp_path: Path):
    state = run_dir / "lead_author"
    state.mkdir()
    (state / "done").write_text("ok")
    deps = _deps(_lane(tmp_path), invoke_agent=_claude_should_not_be_called)
    assert lead_author.run(run_of(run_dir), label=LEAD_AUTHOR_DRAIN_LABEL, deps=deps) == 0


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
        skills=skills_view(skills), where=skills, systems=frozenset({"elastic", "wazuh", "cmdb"}))
    rel = [str(p.relative_to(tmp_path)) for p in found]
    assert rel == ["defender/skills/elastic/_draft/real-draft.md"]


def test_build_system_draft_handoffs_emits_triple(tmp_path):
    """The triple names the draft and its system's SKILL.md below the draft's `skills/`, never
    the product tree's spelling (#1108 P4 O-TEXT; the exact prefix is an open handoff-spelling
    gap, so only its tail and the absence of `defender/` are pinned)."""
    skills = tmp_path / "agent" / "skills"
    (skills / "elastic" / "_draft").mkdir(parents=True)
    draft = skills / "elastic" / "_draft" / "falco-na.md"
    draft.write_text("---\nstatus: draft\n---\n")
    handoffs = lead_author.build_system_draft_handoffs([draft], repo_root=tmp_path)
    assert [sorted(h) for h in handoffs] == [["draft_path", "skill_path", "system"]]
    (h,) = handoffs
    assert h["system"] == "elastic"
    assert h["draft_path"].endswith("skills/elastic/_draft/falco-na.md")
    assert h["skill_path"].endswith("skills/elastic/SKILL.md")
    assert not h["draft_path"].startswith("defender/")
    assert not h["skill_path"].startswith("defender/")


#: `tests/_repo.seed_skills_repo`'s adapter-declared systems (#869): the product checkout's
#: adapters, which `build_lead_author_deps` resolves at its own boundary.
DECLARED = frozenset({"elastic", "wazuh"})


def _tick(lane: C.DraftLane, edit, *, label: str = "lead-run", synthesize=None,
          handoff: str = "wazuh.newthing", **overrides) -> tuple[Path, int]:
    """One REAL lead-author tick over the draft: the tables bypassed (one dummy lead), the spawn
    faked as `edit(<the draft's agent/skills>)` (it runs no git), handing over `handoff`."""
    run_dir = curation_run_dir(label)

    def agent(rd, handoffs, pending, *, box=None):
        edit(lane.skills_dir)
        return 0

    deps = _deps(
        lane,
        extract=lambda rd: ([], [_executed_lead()]),
        synthesize=synthesize or (lambda executed, **_kw: []),
        invoke_agent=agent,
        build_handoff=lambda rd, ex, jl=None, **_: [{"query_id": handoff}],
        discover_system_drafts=lambda: [],
        **overrides,
    )
    return run_dir, lead_author.run(run_of(run_dir), label=LEAD_AUTHOR_DRAIN_LABEL, deps=deps)


def _landed(lane: C.DraftLane, edit, **kw) -> list[str]:
    """The gate admitted the tick: rc 0, and what the commit-maker landed on the batch branch."""
    run_dir, rc = _tick(lane, edit, **kw)
    assert rc == 0
    assert (run_dir / "lead_author" / "done").is_file()
    return lane.landed()


def _refused(lane: C.DraftLane, edit, match: str, *, errors=None, **kw) -> pytest.ExceptionInfo:
    """The gate refused the tick naming `match`: nothing landed on the batch branch, no done
    sentinel."""
    label = kw.pop("label", "lead-run")
    with pytest.raises(errors or lead_author.LeadAuthorError, match=match) as exc:
        _tick(lane, edit, label=label, **kw)
    assert lane.landed() == []
    assert not (curation_run_dir(label) / "lead_author" / "done").is_file()
    return exc


def _append(path: Path, text: str) -> None:
    path.write_text(path.read_text() + text)


def test_verify_skills_state_accepts_in_scope_edits(tmp_path: Path):
    """Fold an established template, promote a draft (write established + rm draft), and
    lift a system skill (edit SKILL.md + rm draft) — all in-scope; all of them land (#869/#1108 O7)."""
    def edit(sk: Path) -> None:
        (sk / "gather/queries/wazuh/auth-events.md").write_text(
            query_template("wazuh.auth-events", "established") + "\n# folded\n")
        (sk / "gather/queries/wazuh/newthing.md").write_text(
            query_template("wazuh.newthing", "established"))
        (sk / "gather/queries/wazuh/_draft/newthing.md").unlink()
        _append(sk / "elastic/SKILL.md", "\n## Falco quirk\nworkaround\n")
        (sk / "elastic/_draft/falco-na.md").unlink()

    landed = _landed(_lane(tmp_path), edit)
    assert f"{CATALOG_REL}/wazuh/auth-events.md" in landed
    assert f"{CATALOG_REL}/wazuh/newthing.md" in landed
    assert "agent/skills/elastic/SKILL.md" in landed


def test_verify_skills_state_rejects_stray_outside_skills(tmp_path: Path):
    """An edit outside the lane's `skills/` is refused by the batch's ChangeSet (an out-of-lane
    path, OD18: before the lane gate reads it), naming it outside: nothing lands and the draft is
    back at its base (#1175, U10). How the drain routes it is below."""
    from defender.learning.author.version_control import DeliveryRefused

    lane = _lane(tmp_path, files={"other/stray.md": "committed\n"})
    _refused(lane, lambda sk: (sk.parent / "other" / "stray.md").write_text("stray"), "outside",
             errors=DeliveryRefused)
    assert lane.drift() == []


def _queue_entry(paths, where: str, name: str) -> dict | None:
    """The lead-author queue's request `name` in `where` (`""` queued, `"failed"`,
    `"inflight"`), or `None`."""
    at = location_path(paths.state_root) / "author-queue" / where / f"{name}.json"
    return json.loads(at.read_text(encoding="utf-8")) if at.is_file() else None


@pytest.mark.parametrize("fault", ["refused-claim", "gate-rejection", "unrelated"])
def test_the_drain_routes_a_refused_claim_to_a_counted_retry_not_a_dead_letter(
        tmp_path: Path, fault: str, monkeypatch):
    """U10/OD18 (human, 2026-10-23): the lead-author claim loop serving a run whose claim the
    batch's ChangeSet refuses (a symlink the box left inside `skills/`, at a path the lane gate
    would admit as a plain file) keeps the request queued with ONE attempt — not dead-lettered,
    not in flight — nothing lands and the draft is back at its base. Controls keep the lane's
    existing rule (#952), not U10's: a lane-gate content rejection (a delete-prohibition) and an
    unrelated spawn fault are dead-lettered at once (`lead-author-error`) (#1175, P4 O7)."""
    from defender.learning.core import drains
    from defender.tests.support.learning.core._state1135 import enqueue_run, state_for_paths

    monkeypatch.setenv("LEAD_AUTHOR_MAX_RETRIES", "3")
    lane = _lane(tmp_path)
    run_dir = curation_run_dir("lead-u10")
    state = state_for_paths(lane.paths)
    enqueue_run(state, run_dir)
    outside = tmp_path / "outside" / "host.md"
    outside.parent.mkdir(parents=True, exist_ok=True)
    outside.write_text(query_template("wazuh.newthing", "established"))

    def agent(rd, handoffs, pending, *, box=None):
        if fault == "unrelated":
            raise RuntimeError("unrelated spawn fault")
        if fault == "gate-rejection":
            (lane.skills_dir / "gather/queries/wazuh/auth-events.md").unlink()
        else:
            (lane.skills_dir / "gather/queries/wazuh/newthing.md").symlink_to(outside)
        return 0

    def serve(paths, st, run, *, box=None, on_done, **_kw):
        deps = _deps(lane, extract=lambda rd: ([], [_executed_lead()]),
                     synthesize=lambda executed, **_kw: [], invoke_agent=agent,
                     build_handoff=lambda rd, ex, jl=None, **_: [{"query_id": "wazuh.newthing"}],
                     discover_system_drafts=lambda: [])
        lead_author.run(run, label=LEAD_AUTHOR_DRAIN_LABEL, deps=deps, box=box, on_done=on_done)

    drains._drain_lead_author_markers(lane.paths, state, serve,
                                      accept_tenant=drains._tenant_acceptor(None))

    name = run_dir.name
    assert lane.landed() == []
    assert _queue_entry(lane.paths, "inflight", name) is None
    assert outside.read_text() == query_template("wazuh.newthing", "established")
    if fault != "refused-claim":
        assert _queue_entry(lane.paths, "", name) is None
        failed = _queue_entry(lane.paths, "failed", name)
        assert failed is not None, "the existing rule's dead letter is missing"
        return
    assert lane.drift() == []
    assert _queue_entry(lane.paths, "failed", name) is None, "a refused claim was dead-lettered"
    queued = _queue_entry(lane.paths, "", name)
    assert queued is not None, "the refused claim's request was lost"
    assert queued.get("attempts") == 1


@pytest.mark.parametrize(("case", "mutate", "match"), [
    # a non-*.md file under skills/ is a stray — the corpus is *.md
    ("non-md-under-skills",
     lambda sk: (sk / "junk.json").write_text("{}"), "outside"),

    # deleting an ESTABLISHED template, and deleting a system's SKILL.md, are both the
    # delete-prohibition: a promote writes, it never removes what another run relies on
    ("established-template-deletion",
     lambda sk: (sk / "gather/queries/wazuh/auth-events.md").unlink(), "delete-prohibition"),
    ("skill-md-deletion",
     lambda sk: (sk / "elastic" / "SKILL.md").unlink(), "delete-prohibition"),

    # the `_draft/README.md` is scaffold the lane may not author over
    ("draft-readme-mutation",
     lambda sk: _append(sk / "elastic" / "_draft" / "README.md", "\nstomped\n"),
     "protected surface"),

    ("half-promote",
     lambda sk: (sk / "gather/queries/wazuh/newthing.md").write_text(
         query_template("wazuh.newthing", "established")), "half-promote"),

    ("skill-md-naming-another-system",
     lambda sk: (sk / "elastic" / "SKILL.md").write_text(
         "---\nname: defender-cmdb\n---\n# elastic\n"), "defender-elastic"),
], ids=lambda v: v if isinstance(v, str) and len(v) < 50 and " " not in v else "")
def test_verify_skills_state_rejects_a_tree_the_write_lane_could_produce(
    tmp_path: Path, case, mutate, match
):
    _refused(_lane(tmp_path), mutate, match)


def test_verify_skills_state_rejects_out_of_scope_skills_md(tmp_path: Path):
    _refused(_lane(tmp_path), lambda sk: (sk / "elastic" / "notes.md").write_text("x"),
             "out-of-scope")


def test_verify_skills_state_rejects_execution_md(tmp_path: Path):
    """`execution.md` is the one per-system file the lead-author lane can never get
    committed (#869 C32/F1) — under NF1 the commit gate IS the marker's integrity."""
    _refused(_lane(tmp_path), lambda sk: (sk / "elastic" / "execution.md").write_text("x"),
             "execution.md")


def _covered_draft(query_id: str) -> tuple[str, str]:
    """A `wazuh` draft that accounts for `query_id`, as the mint would write it, for the batch's
    base (agent-relative path, text). In the base, not merely written: the invariants under test
    read the draft's PRE-IMAGE from the base commit."""
    name = lead_author._draft_basename(query_id)
    return (f"{_CATALOG}/wazuh/_draft/{name}.md",
            query_template(f"wazuh.{name}", "draft", covers=[query_id]))


def test_a_discard_into_widen_that_carries_covers_is_accepted(tmp_path: Path):
    draft, text = _covered_draft("wazuh.hunt-failed-logins")

    def edit(sk: Path) -> None:
        (sk / "gather/queries/wazuh/auth-events.md").write_text(
            query_template("wazuh.auth-events", "established",
                           covers=["wazuh.hunt-failed-logins"]) + "\n# widened\n")
        (sk.parent / draft).unlink()

    assert f"{CATALOG_REL}/wazuh/auth-events.md" in _landed(_lane(tmp_path, {draft: text}), edit)


def test_a_bare_discard_of_a_covered_draft_is_refused(tmp_path: Path):
    draft, text = _covered_draft("wazuh.hunt-failed-logins")
    _refused(_lane(tmp_path, {draft: text}), lambda sk: (sk.parent / draft).unlink(),
             "wazuh.hunt-failed-logins")


def _mint(query_id: str):
    """A `synthesize` that mints a `wazuh` draft this tick into the draft's catalog — what
    `synthesize_drafts` leaves behind and hands to the author. `covers:` carries BOTH identities
    the real mint writes: the draft's own derived id and the coined `query_id`."""
    name = lead_author._draft_basename(query_id)
    draft_id = f"wazuh.{name}"

    def synthesize(executed, *, skills=None, where=None, **_kw):
        at = Path(where) / "gather" / "queries" / "wazuh" / "_draft" / f"{name}.md"
        at.write_text(query_template(draft_id, "draft", covers=[draft_id, query_id]))
        return [at]

    return synthesize, f"{_CATALOG}/wazuh/_draft/{name}.md"


def test_a_promote_of_a_draft_minted_this_tick_is_accepted(tmp_path: Path):
    """The positive control for the rule above — the identity lands, so the delete costs
    nothing and the batch commits."""
    synthesize, draft = _mint("wazuh.hunt-failed-logins")

    def edit(sk: Path) -> None:
        (sk / "gather/queries/wazuh/auth-failure-rate.md").write_text(query_template(
            "wazuh.auth-failure-rate", "established",
            covers=[Path(draft).stem.join(("wazuh.", "")), "wazuh.hunt-failed-logins"]))
        (sk.parent / draft).unlink()

    landed = _landed(_lane(tmp_path), edit, synthesize=synthesize)
    assert f"{CATALOG_REL}/wazuh/auth-failure-rate.md" in landed


def test_a_draft_minted_this_tick_and_left_alone_is_not_a_departure(tmp_path: Path):
    """SKIP is a legal disposition, and it is the one the prompt names for a draft that fits
    nowhere — the rule must fire on the `rm`, never on the file still being there."""
    synthesize, draft = _mint("wazuh.hunt-failed-logins")
    assert _landed(_lane(tmp_path), lambda sk: None, synthesize=synthesize) == [f"agent/{draft}"]


def test_a_promote_that_leaves_the_draft_behind_is_refused(tmp_path: Path):
    draft, text = _covered_draft("wazuh.hunt-failed-logins")
    # …and no `rm` of the draft.
    _refused(_lane(tmp_path, {draft: text}),
             lambda sk: (sk / "gather/queries/wazuh/auth-failure-rate.md").write_text(
                 query_template("wazuh.auth-failure-rate", "established",
                                covers=["wazuh.hunt-failed-logins"])),
             "half-promote")


def test_a_discard_is_accepted_when_an_untouched_template_already_covers_it(tmp_path: Path):
    draft, text = _covered_draft("wazuh.hunt-failed-logins")
    widened = {f"{_CATALOG}/wazuh/auth-events.md": query_template(
        "wazuh.auth-events", "established", covers=["wazuh.hunt-failed-logins"])}
    landed = _landed(_lane(tmp_path, {draft: text, **widened}),
                     lambda sk: (sk.parent / draft).unlink())
    assert landed == [f"agent/{draft}"]


def test_repairing_an_id_that_disagrees_with_its_directory_is_not_a_clobber(tmp_path: Path):
    broken = {f"{_CATALOG}/wazuh/auth-events.md":
              query_template("elastic.auth-events", "established")}
    landed = _landed(_lane(tmp_path, broken),
                     lambda sk: (sk / "gather/queries/wazuh/auth-events.md").write_text(
                         query_template("wazuh.auth-events", "established")))
    assert f"{CATALOG_REL}/wazuh/auth-events.md" in landed


def test_a_draft_folded_into_another_draft_is_attributed(tmp_path: Path):
    mint_narrow, narrow = _mint("wazuh.narrow-probe")
    mint_wide, wide = _mint("wazuh.wide-probe")

    def synthesize(executed, **kw):
        return [*mint_narrow(executed, **kw), *mint_wide(executed, **kw)]

    def edit(sk: Path) -> None:
        # The survivor absorbs the narrow one's identities; the narrow one goes.
        (sk.parent / wide).write_text(query_template(
            f"wazuh.{lead_author._draft_basename('wazuh.wide-probe')}", "draft",
            covers=[
                f"wazuh.{lead_author._draft_basename('wazuh.wide-probe')}", "wazuh.wide-probe",
                f"wazuh.{lead_author._draft_basename('wazuh.narrow-probe')}", "wazuh.narrow-probe",
            ],
        ))
        (sk.parent / narrow).unlink()

    assert f"agent/{wide}" in _landed(_lane(tmp_path), edit, synthesize=synthesize)


def test_an_established_template_may_not_lose_the_identities_it_covers(tmp_path: Path):
    covered = {f"{_CATALOG}/wazuh/auth-events.md": query_template(
        "wazuh.auth-events", "established", covers=["wazuh.old-probe"])}
    _refused(_lane(tmp_path, covered),
             lambda sk: (sk / "gather/queries/wazuh/auth-events.md").write_text(
                 query_template("wazuh.auth-events", "established")),
             "wazuh.old-probe")


def test_an_established_template_may_not_have_its_id_rewritten(tmp_path: Path):
    _refused(_lane(tmp_path),
             lambda sk: (sk / "gather/queries/wazuh/auth-events.md").write_text(
                 query_template("wazuh.something-else", "established")),
             "rewrote the identity")


def test_verify_skills_state_rejects_schema_mutation(tmp_path: Path):
    _refused(_lane(tmp_path),
             lambda sk: _append(sk / "gather/queries/SCHEMA.md", "\nstomped\n"),
             "protected surface")


def test_verify_skills_state_rejects_a_promotion_whose_placeholder_is_not_a_param(
    tmp_path: Path,
):
    def edit(sk: Path) -> None:
        (sk / "gather/queries/wazuh/newthing.md").write_text(query_template(
            "wazuh.newthing", "established",
            body="```query\nverb: search\nparams:\n  index: ${mystery}\n```"))
        (sk / "gather/queries/wazuh/_draft/newthing.md").unlink()

    _refused(_lane(tmp_path), edit, "mystery")


def test_verify_skills_state_accepts_a_malformed_draft(tmp_path: Path):
    landed = _landed(_lane(tmp_path),
                     lambda sk: (sk / "gather/queries/wazuh/_draft/rough.md").write_text(
                         query_template("wazuh.rough", "draft",
                                        body="```query\nverb: search\nparams:\n  index: ${mystery}\n```")))
    assert f"{CATALOG_REL}/wazuh/_draft/rough.md" in landed


def test_is_catalog_template_excludes_what_is_not_a_template():
    """Over the repo-relative spelling after P4 (OD6). ASSUMED: the rule keeps its path-string
    shape, its paths now `agent/...` from the ChangeSet."""
    assert lead_author._is_catalog_template(f"{CATALOG_REL}/wazuh/auth.md")
    assert not lead_author._is_catalog_template(f"{CATALOG_REL}/wazuh/README.md")
    assert not lead_author._is_catalog_template(f"{CATALOG_REL}/NOTES.md")
    assert not lead_author._is_catalog_template(f"{CATALOG_REL}/SCHEMA.md")
    assert not lead_author._is_catalog_template(f"{CATALOG_REL}/wazuh/_draft/rough.md")
    assert lead_author._is_catalog_template(f"{CATALOG_REL}/wazuh/sub/x.md")
    assert lead_author._is_catalog_template(f"{CATALOG_REL}/wazuh/sub/_draft/x.md")
    assert not lead_author._is_catalog_template("defender/skills/gather/queries/wazuh/auth.md")


def test_verify_skills_state_rejects_a_promotion_under_a_system_with_no_adapter(
    tmp_path: Path,
):
    _refused(_lane(tmp_path),
             lambda sk: C.put(sk / "gather/queries/ghost/x.md",
                              query_template("ghost.x", "established")),
             "could not be resolved", systems=DECLARED | {"ghost"})


def test_verify_skills_state_refuses_a_tree_whose_adapters_cannot_be_read(tmp_path: Path):
    lane = _lane(tmp_path)
    adapters = lane.paths.repo_root / "defender" / "integrations"
    exc = _refused(lane, lambda sk: shutil.rmtree(adapters), "could not be resolved")
    assert str(adapters) in str(exc.value), f"the refusal does not name the directory: {exc.value}"
    assert "refusing to commit" in str(exc.value)


# test_verify_skills_state_ignores_baseline_stray: deleted (#1108 P4 OD12 i). It pinned the
# worktree's pre-existing dirt (`changes_outside` over git status) not being blamed on the agent;
# a draft is built clean from the export's blobs, so there is no baseline to subtract. Covered by
# tests/tenancy/tenant_1108_delivery/test_batches.py::test_start_batch_makes_a_git_free_draft_of_the_export_commit_and_no_checkout
# and test_changes.py::test_change_set_is_the_draft_against_the_batch_base_and_commits_as_plain_files.


def test_run_loop_commits_agent_edits(tmp_path: Path):
    """End-to-end: the agent (faked) edits the draft and runs no git; the loop verifies and
    the commit-maker commits exactly the skills delta on the batch branch with a generated
    message, and writes done (#1108 P4 O7: closes F-LEAD's lead-author row)."""
    lane = _lane(tmp_path)

    def edit(sk: Path) -> None:
        (sk / "gather/queries/wazuh/newthing.md").write_text(
            query_template("wazuh.newthing", "established"))
        (sk / "gather/queries/wazuh/_draft/newthing.md").unlink()

    run_dir, rc = _tick(lane, edit)
    assert rc == 0
    assert len(lane.commits()) == 1, "the loop should have committed once on the batch branch"
    changed = lane.landed()
    assert changed
    assert all(p.startswith("agent/skills/") for p in changed)
    assert f"{CATALOG_REL}/wazuh/newthing.md" in changed
    msg = lane.message()
    assert "lead-author" in msg
    assert run_dir.name in msg
    assert (run_dir / "lead_author" / "done").is_file()


def test_run_raises_and_skips_commit_on_scope_violation(tmp_path: Path):
    """A stray edit makes the gate raise (the drain quarantines the marker); nothing lands and
    no done sentinel is written."""
    from defender.learning.author.version_control import DeliveryRefused

    lane = _lane(tmp_path, files={"other/stray.md": "committed\n"})
    _refused(lane, lambda sk: (sk.parent / "other" / "stray.md").write_text("stray"), "outside",
             errors=DeliveryRefused)
    assert lane.drift() == []


def test_run_returns_rc2_on_nonzero_agent_exit(tmp_path: Path):
    lane = _lane(tmp_path)
    run_dir = curation_run_dir("lead-run")
    deps = _deps(
        lane,
        extract=lambda rd: ([], [_executed_lead()]),
        synthesize=lambda executed, **_kw: [],
        invoke_agent=lambda rd, handoffs, pending, **_kw: 124,
        build_handoff=lambda rd, ex, jl=None, **_: [{"query_id": "x.y"}],
        discover_system_drafts=lambda: [],
    )
    assert lead_author.run(run_of(run_dir), label=LEAD_AUTHOR_DRAIN_LABEL, deps=deps) == 2
    assert lane.commits() == []
    assert not (run_dir / "lead_author" / "done").is_file()
    assert not (run_dir / "lead_author" / "failure.txt").exists()


def test_run_loop_clears_drafts_on_discard_and_promote(tmp_path: Path):
    olddraft = f"{_CATALOG}/wazuh/_draft/olddraft.md"
    lane = _lane(tmp_path, {olddraft: query_template("wazuh.olddraft", "draft")})

    def edit(sk: Path) -> None:
        (sk / "gather/queries/wazuh/newthing.md").write_text(
            query_template("wazuh.newthing", "established"))
        (sk / "gather/queries/wazuh/_draft/newthing.md").unlink()
        (sk.parent / olddraft).unlink()

    run_dir, rc = _tick(lane, edit)
    assert rc == 0
    assert lane.text_at_tip(f"{CATALOG_REL}/wazuh/newthing.md") is not None
    assert lane.text_at_tip(f"{CATALOG_REL}/wazuh/_draft/newthing.md") is None
    assert lane.text_at_tip(f"agent/{olddraft}") is None
    assert (run_dir / "lead_author" / "done").is_file()


def test_run_quarantines_half_promote(tmp_path: Path):
    _refused(_lane(tmp_path),
             lambda sk: (sk / "gather/queries/wazuh/newthing.md").write_text(
                 query_template("wazuh.newthing", "established")),
             "half-promote")


def test_run_refuses_a_bare_discard_of_a_draft_it_minted_this_tick(tmp_path: Path):
    """The REAL mint (no synthesize override): a bare `rm` of the draft it minted is refused and
    nothing lands (draft synthesis over the draft, F-LEAD)."""
    lane = _lane(tmp_path)
    run_dir = curation_run_dir("lead-run")
    (run_dir / "gather_raw").mkdir(parents=True)
    _write_lead_meta(run_dir, "l-001", "probe a brand-new measurement")
    _write_query(run_dir, "l-001", 0, "wazuh.hunt-failed-logins", verb="search",
                 payload_status="ok")
    minted = lane.skills_dir / "gather" / "queries" / "wazuh" / "_draft" / (
        f"{lead_author._draft_basename('wazuh.hunt-failed-logins')}.md")

    def fake_agent(rd, handoffs, pending, *, box=None):
        # A bare discard: `rm` the minted draft, attribute it nowhere.
        assert minted.is_file(), "the mint did not produce the draft this test is about"
        minted.unlink()
        return 0

    deps = _deps(lane, invoke_agent=fake_agent)
    with pytest.raises(lead_author.LeadAuthorError, match="wazuh.hunt-failed-logins"):
        lead_author.run(run_of(run_dir), label=LEAD_AUTHOR_DRAIN_LABEL, deps=deps)
    assert lane.landed() == []
    assert not (run_dir / "lead_author" / "done").is_file()


def test_prepare_handoffs_at_threshold_surfaces_drafts(run_dir: Path, monkeypatch, tmp_path):
    """At-or-above threshold → drafts surface alongside executed handoffs; each names its
    system's SKILL.md in the draft, not the product tree (#1108 P4)."""
    lane = _lane(tmp_path)
    fake_handoff = [{
        "query_id": "fake.lead", "status": "established",
        "executed_template_path": f"{CATALOG_REL}/fake/lead.md",
        "neighbors": [], "invocations": [],
    }]
    drafts = [lane.skills_dir / "elastic" / "_draft" / n for n in ("a.md", "b.md")]
    for d in drafts:
        d.write_text("---\nstatus: draft\n---\n")
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "2")
    deps = _deps(
        lane,
        extract=lambda rd: ([], [_executed_lead()]),
        build_handoff=lambda rd, ex, jl=None, **_: fake_handoff,
        discover_system_drafts=lambda: drafts,
    )

    handoffs, pending, rc = lead_author._prepare_handoffs(run_dir, deps)
    assert rc is None
    assert handoffs == fake_handoff
    assert len(pending) == 2
    assert pending[0]["system"] == "elastic"
    assert pending[0]["skill_path"].endswith("skills/elastic/SKILL.md")
    assert not pending[0]["skill_path"].startswith("defender/")


def test_prepare_handoffs_drafts_only_no_executed_proceeds(run_dir: Path, monkeypatch, tmp_path):
    """No executed leads + drafts at threshold → proceed with drafts only."""
    lane = _lane(tmp_path)
    drafts = [lane.skills_dir / "elastic" / "_draft" / f"d{i}.md" for i in range(2)]
    for d in drafts:
        d.write_text("---\nstatus: draft\n---\n")
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "1")
    deps = _deps(lane, discover_system_drafts=lambda: drafts)

    handoffs, pending, rc = lead_author._prepare_handoffs(run_dir, deps)
    assert rc is None
    assert handoffs == []
    assert len(pending) == 2


def test_prepare_handoffs_both_empty_exits_zero(run_dir: Path, tmp_path: Path):
    """No executed leads AND no pending drafts → early exit 0, no work."""
    deps = _deps(_lane(tmp_path), discover_system_drafts=lambda: [])
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
    """The pending drafts reach the engine's user prompt, whose `skills_dir:` line names the
    draft's skills root, not the product tree's (#1108 P4 O-TEXT; its exact spelling is the open
    handoff-spelling gap, so only the absence of `defender/` is pinned)."""
    cap = _capture_engine(monkeypatch)
    handoffs = [{"query_id": "wazuh.auth-events", "status": "established",
                 "executed_template_path": f"{CATALOG_REL}/wazuh/auth-events.md",
                 "neighbors": [], "invocations": []}]
    pending = [{"draft_path": "agent/skills/elastic/_draft/falco-na.md",
                "system": "elastic",
                "skill_path": "agent/skills/elastic/SKILL.md"}]
    rc = lead_author.invoke_agent(run_dir, handoffs, pending)
    assert rc == 0
    prompt = cap["user_prompt"]
    assert re.search(r"<run-[0-9a-f]+-handoffs>", prompt)
    assert re.search(r"<run-[0-9a-f]+-pending_system_drafts>", prompt)
    assert "elastic/_draft/falco-na.md" in prompt
    (line,) = [ln for ln in prompt.splitlines() if ln.startswith("skills_dir: ")]
    assert line.rstrip("/").endswith("skills")
    assert "defender/skills" not in line


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
    out = lead_author.collect_general_failures(leads, run_dir,
                                               skills=skills_view(catalog.parents[1]),
    where=catalog.parents[1])
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
                 for r in lead_author.collect_general_failures(
                     leads, tmp_path / "r", skills=skills_view(catalog.parents[1]),
                     where=catalog.parents[1])}
    assert drafted == {"elastic.new-thing"}
    assert collected == {"elastic.esql"}
    assert drafted.isdisjoint(collected)


def test_run_collects_general_failure_before_early_return(tmp_path: Path):
    deps = _deps(_lane(tmp_path), invoke_agent=lambda *a, **k: 0)
    run_dir = curation_run_dir("run-xyz")
    (run_dir / "gather_raw").mkdir(parents=True)
    _write_lead_meta(run_dir, "l-001", "probe")
    _write_query(run_dir, "l-001", 0, "elastic.esql", payload_status="error")

    assert lead_author.run(run_of(run_dir), label=LEAD_AUTHOR_DRAIN_LABEL, deps=deps) == 0
    queue = location_path(deps.paths.state_root) / PITFALLS.queue
    rows = [json.loads(ln) for ln in queue.read_text().splitlines()]
    assert [r["query_id"] for r in rows] == ["elastic.esql"]
    assert rows[0]["error_class"] == "agent-fixable"
    assert (run_dir / "lead_author" / "pitfalls_collected").is_file()

    (run_dir / "lead_author" / "done").unlink()
    assert lead_author.run(run_of(run_dir), label=LEAD_AUTHOR_DRAIN_LABEL, deps=deps) == 0
    rows2 = [json.loads(ln) for ln in queue.read_text().splitlines()]
    assert len(rows2) == 1


def test_run_reloads_catalog_after_mint_so_minted_draft_resolves(tmp_path: Path):
    """The REAL mint writes its draft into the batch's draft and the reloaded catalog resolves
    it for the handoff (draft synthesis over a draft, #1108 P4 F-LEAD)."""
    lane = _lane(tmp_path)
    seen: dict = {}
    deps = _deps(
        lane,
        invoke_agent=lambda rd, handoffs, pending, **_kw: seen.update(handoffs=handoffs) or 0,
    )
    run_dir = curation_run_dir("run-mint")
    (run_dir / "gather_raw").mkdir(parents=True)
    _write_lead_meta(run_dir, "l-001", "probe a brand-new verb")
    _write_query(run_dir, "l-001", 0, "wazuh.brandnew", verb="lookup", payload_status="ok")

    assert lead_author.run(run_of(run_dir), label=LEAD_AUTHOR_DRAIN_LABEL, deps=deps) == 0
    minted = lead_author._draft_basename("wazuh.brandnew")
    assert (lane.agent / _CATALOG / "wazuh" / "_draft" / f"{minted}.md").is_file()
    assert f"wazuh.{minted}" in {h["query_id"] for h in seen["handoffs"]}


@pytest.mark.parametrize(("case", "changed", "present", "absent"), [
    ("catalog-only", ["agent/skills/gather/queries/wazuh/auth-events.md"],
     ["gather catalog for run-123"], ["system skills"]),

    ("skill-md-only", ["agent/skills/elastic/SKILL.md"],
     ["learning(lead-author): system skills for run-123"], ["gather catalog"]),

    # a system-skill _draft is NOT a catalog path, so it counts as system-skills scope
    ("system-draft-counts-as-skill", ["agent/skills/elastic/_draft/falco-na.md"],
     ["system skills"], ["gather catalog"]),

    ("catalog-and-skill-together",
     ["agent/skills/gather/queries/wazuh/auth-events.md",
      "agent/skills/elastic/SKILL.md"],
     ["gather catalog + system skills"], []),

    # The loop message is built UNCONDITIONALLY, even for an empty change set, so it has to
    # render (no catalog/skill ⇒ 'gather catalog') rather than crash.
    ("empty-change-set", [],
     ["gather catalog for run-123", "\n\nsource-run: run-123\n"], []),
], ids=lambda v: v if isinstance(v, str) and len(v) < 40 and "/" not in v else "")
def test_loop_commit_message_scope_follows_the_changed_paths(case, changed, present, absent):
    """The subject line names the scope the batch actually touched — catalog, system skills,
    or both — and never a scope nothing in `changed` supports. Over the repo-relative spelling
    after P4 (OD6, `agent/...`)."""
    msg = lead_author._loop_commit_message(Path("run-123"), changed)
    for fragment in present:
        assert fragment in msg
    for fragment in absent:
        assert fragment not in msg
