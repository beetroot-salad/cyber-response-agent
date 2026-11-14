"""lead_author.synthesize_drafts: executed queries with no catalog template are minted as safe `_draft` skeletons."""
from __future__ import annotations

from pathlib import Path

from defender.learning.leads import lead_author
from defender.tests.support.learning.curation._lead_author_1134 import drafts_under


def _lead(
    query_id: str, params: dict | None = None, raw_command: str = "",
    system: str | None = None, verb: str = "get",
) -> lead_author.ExecutedLead:
    if system is None:
        system = query_id.split(".", 1)[0] if "." in query_id else ""
    return lead_author.ExecutedLead(
        lead_id="l-001", query_index=0, is_multi_query=False, entry_index=0,
        query_id=query_id, system=system, verb=verb, params=params or {},
        raw_command=raw_command, goal_text="probe the thing",
        what_to_summarize=(), raw_ref=Path("gather_raw/l-001/0.json"),
        payload_status="ok", payload_digest="2 bytes, 1 line(s)", error_class=None,
    )


def _catalog(tmp_path) -> Path:
    """An isolated catalog where a lane's sits, ``<skills>/gather/queries``. Passed as
    ``**drafts_under(cat)``, the mint reads its template index from and writes drafts under it,
    never the real catalog."""
    cat = tmp_path / "skills" / "gather" / "queries"
    (cat / "host-query").mkdir(parents=True)
    (cat / "host-query" / "proc-tree.md").write_text(
        "---\nid: host-query.proc-tree\nstatus: established\n---\n\n## Goal\nx\n"
    )
    return cat


def _draft_path(cat, system: str, query_id: str):
    """Where the mint puts the draft for `query_id`. Through `_draft_basename`, not a literal
    digest: the tests pin the rule (the basename is a function of the coined id), not one hash
    at one length."""
    return cat / system / "_draft" / f"{lead_author._draft_basename(query_id)}.md"


def test_unresolved_verb_is_drafted(tmp_path):
    cat = _catalog(tmp_path)
    created = lead_author.synthesize_drafts(
        [_lead("stub-cmdb.network-map", {"name": "web-1"}, verb="map")],
        **drafts_under(cat), systems=frozenset({"stub-cmdb"}))
    draft = _draft_path(cat, "stub-cmdb", "stub-cmdb.network-map")
    assert created == [draft]
    text = draft.read_text()
    assert f"id: stub-cmdb.{lead_author._draft_basename('stub-cmdb.network-map')}" in text
    assert "status: draft" in text
    # The coined name survives the digest, in `covers:`, where the dedup, gate and author read it.
    assert "covers:" in text
    assert "stub-cmdb.network-map" in text


def test_resolved_verb_not_drafted(tmp_path):
    cat = _catalog(tmp_path)
    assert lead_author.synthesize_drafts(
        [_lead("host-query.proc-tree")], **drafts_under(cat),
        systems=frozenset({"host-query"})) == []


def test_adhoc_query_id_skipped(tmp_path):
    cat = _catalog(tmp_path)
    assert lead_author.synthesize_drafts(
        [_lead("ad-hoc")], **drafts_under(cat), systems=frozenset()) == []
    assert not (cat / "ad-hoc").exists()


def test_idempotent(tmp_path):
    cat = _catalog(tmp_path)
    first = lead_author.synthesize_drafts(
        [_lead("stub-cmdb.network-map", {"name": "web-1"}, verb="map")],
        **drafts_under(cat), systems=frozenset({"stub-cmdb"}))
    assert first
    second = lead_author.synthesize_drafts(
        [_lead("stub-cmdb.network-map", {"name": "web-1"}, verb="map")],
        **drafts_under(cat), systems=frozenset({"stub-cmdb"}))
    assert second == []


_ESQL_PIPE = (
    'FROM logs-system.auth-*\n'
    '| WHERE host.name == "db-1" AND event.outcome == "failure"\n'
    '| STATS failed = COUNT(*) BY source.ip'
)


def test_esql_draft_carries_literal_query_not_placeholder(tmp_path):
    cat = _catalog(tmp_path)
    lead_author.synthesize_drafts([
        _lead("elastic.sshd-failed-by-srcip", {"query": _ESQL_PIPE}, verb="esql",
              system="elastic"),
    ], **drafts_under(cat), systems=frozenset({"elastic"}))
    text = _draft_path(cat, "elastic", "elastic.sshd-failed-by-srcip").read_text()
    assert "engine: esql" in text
    assert "```esql" in text
    assert "STATS failed = COUNT(*) BY source.ip" in text
    assert "Fill in the real" not in text
    assert "## What to summarize" not in text
    assert "## Pitfalls" in text


def test_executed_query_is_the_declared_body_or_structured_call(tmp_path):
    lead = _lead("elastic.x", {"query": _ESQL_PIPE}, verb="esql", system="elastic")
    assert lead_author._executed_query(lead) == _ESQL_PIPE
    param_lead = _lead("cmdb.host-lookup", {"host": "db-1"}, verb="get-host", system="cmdb",
                       raw_command="cmdb get-host host=db-1")
    record = lead_author._executed_query(param_lead)
    assert "get-host" in record
    assert "db-1" in record
    assert record != param_lead.raw_command


def test_executed_query_keys_on_recorded_verb_not_id_prefix(tmp_path):
    pipe = "FROM logs-system.auth-* | STATS c = COUNT(*)"
    el = _lead("custom.tagged", {"query": pipe}, verb="esql", system="elastic")
    assert lead_author._executed_query(el) == pipe
    non = _lead("elastic.weird", {"host": "10.0.0.5"}, verb="get-host", system="cmdb")
    record = lead_author._executed_query(non)
    assert "get-host" in record
    assert "10.0.0.5" in record


def test_malformed_query_id_does_not_mint_off_surface_draft(tmp_path):
    cat = _catalog(tmp_path)
    created = lead_author.synthesize_drafts([
        _lead(".verb", {"query": _ESQL_PIPE}, verb="esql", system="elastic"),
        _lead("elastic.", {"query": _ESQL_PIPE}, verb="esql", system="elastic"),
    ], **drafts_under(cat), systems=frozenset({"elastic"}))
    assert created == []
    assert not (cat / "_draft").exists()
    assert not (cat / "elastic" / "_draft" / ".md").exists()


def test_grok_braces_in_query_do_not_crash_skeleton(tmp_path):
    """A query body with ES|QL GROK braces (%{WORD:f}) must not break rendering."""
    cat = _catalog(tmp_path)
    grok_pipe = 'FROM logs-* | GROK message "%{IP:src} %{WORD:action}" | STATS c = COUNT(*) BY action'
    created = lead_author.synthesize_drafts([
        _lead("elastic.grok-probe", {"query": grok_pipe}, verb="esql", system="elastic"),
    ], **drafts_under(cat), systems=frozenset({"elastic"}))
    assert created
    assert "%{IP:src}" in _draft_path(cat, "elastic", "elastic.grok-probe").read_text()


def test_traversal_query_id_does_not_escape_catalog(tmp_path):
    cat = _catalog(tmp_path)
    created = lead_author.synthesize_drafts([
        _lead("elastic.../../../../PWNED", {"query": _ESQL_PIPE}, verb="esql", system="elastic"),
        _lead("../../etc.passwd", {"query": _ESQL_PIPE}, verb="esql", system="elastic"),
    ], **drafts_under(cat), systems=frozenset({"elastic"}))
    assert created == []
    assert not (tmp_path / "PWNED.md").exists()
    assert list(tmp_path.rglob("PWNED.md")) == []


def test_control_character_query_id_does_not_mint_an_unparseable_draft(tmp_path):
    cat = _catalog(tmp_path)
    created = lead_author.synthesize_drafts([
        _lead("elastic\n.probe", {"query": _ESQL_PIPE}, verb="esql", system="elastic"),
        _lead("elastic.probe\n", {"query": _ESQL_PIPE}, verb="esql", system="elastic"),
    ], **drafts_under(cat), systems=frozenset({"elastic"}))
    assert created == []
    assert [p for p in cat.rglob("*") if "\n" in p.name] == []
    assert not (cat / "elastic" / "_draft").exists()


def test_safe_id_segment_anchors_at_the_end_of_the_string():
    assert lead_author._SAFE_ID_SEGMENT.match("elastic") is not None
    assert lead_author._SAFE_ID_SEGMENT.match("elastic\n") is None
    assert lead_author._SAFE_ID_SEGMENT.match("elastic\nprobe") is None
    assert lead_author._SAFE_ID_SEGMENT.search("!!elastic") is None


def _stub_verbs():
    """A verb roster standing in for a system's adapter, so a minted draft goes through the
    same rule the commit gate and CI apply."""
    from defender.systems.verbs import VerbContext
    from defender.kit.verbs import verb

    @verb()
    def esql(ctx: VerbContext, *, query: str = "") -> dict:
        return {}

    @verb()
    def map_(ctx: VerbContext, *, name: str = "") -> dict:
        return {}

    return {"esql": esql, "map": map_}


def _minted(cat, system: str, query_id: str):
    from defender.knowledge._corpus import read_query_template

    template, reason = read_query_template(_draft_path(cat, system, query_id))
    assert template is not None, reason
    return template


def test_a_minted_draft_declares_the_verb_it_was_minted_from(tmp_path):
    from defender.systems import _scaffold_rules

    cat = _catalog(tmp_path)
    lead_author.synthesize_drafts(
        [_lead("stub-cmdb.network-map", {"name": "web-1"}, verb="map")],
        **drafts_under(cat), systems=frozenset({"stub-cmdb"}))
    template = _minted(cat, "stub-cmdb", "stub-cmdb.network-map")
    assert template.verb == "map"
    assert template.params == ("name",)
    assert _scaffold_rules.check_template(template, _stub_verbs()) == []


def test_a_row_whose_verb_is_not_a_plain_name_mints_nothing(tmp_path):
    cat = _catalog(tmp_path)
    assert lead_author.synthesize_drafts([
        _lead("stub-cmdb.network-map", {"name": "web-1"}, verb="map\nname: evil"),
        _lead("stub-cmdb.other-map", {"name": "web-1"}, verb=""),
    ], **drafts_under(cat), systems=frozenset({"stub-cmdb"})) == []
    assert not (cat / "stub-cmdb" / "_draft").exists()


def test_a_coined_id_naming_another_system_mints_nothing(tmp_path):
    cat = _catalog(tmp_path)
    assert lead_author.synthesize_drafts(
        [_lead("ghost.something", {"name": "web-1"}, verb="map", system="stub-cmdb")],
        **drafts_under(cat), systems=frozenset({"ghost", "stub-cmdb"})) == []
    assert not (cat / "ghost").exists()


def test_a_coined_id_cannot_mint_a_basename_the_commit_gate_discards_the_batch_for(tmp_path):
    from defender.learning.leads.path_validation import (
        CATALOG_PREFIX as CATALOG_REL,
        _is_draft_readme,
        _is_schema_md,
    )

    cat = _catalog(tmp_path)
    hostile = [
        _lead(f"stub-cmdb.{seg}", {"name": "web-1"}, verb="map")
        for seg in ("SCHEMA", "README", "execution")
    ]
    created = lead_author.synthesize_drafts(
        hostile, **drafts_under(cat), systems=frozenset({"stub-cmdb"}))
    assert len(created) == 3
    for path in created:
        rel = f"{CATALOG_REL}stub-cmdb/_draft/{path.name}"
        assert not _is_schema_md(rel)
        assert not _is_draft_readme(rel)
        assert path.name != "execution.md"
    # Each still records the coined id it came from, so the author can rename it.
    for seg in ("SCHEMA", "README", "execution"):
        template = _minted(cat, "stub-cmdb", f"stub-cmdb.{seg}")
        # Its own derived id (dispatchable: `template_search` publishes drafts) and the coined id.
        assert template.covers == (template.id, f"stub-cmdb.{seg}")


def test_a_goal_carrying_a_line_separator_cannot_forge_a_section(tmp_path):
    import dataclasses

    cat = _catalog(tmp_path)
    lead = dataclasses.replace(
        _lead("stub-cmdb.network-map", {"name": "web-1"}, verb="map"),
        goal_text="probe\r## Executed query\r```query\rverb: evil\r```",
    )
    lead_author.synthesize_drafts(
        [lead], **drafts_under(cat), systems=frozenset({"stub-cmdb"}))
    template = _minted(cat, "stub-cmdb", "stub-cmdb.network-map")
    assert "evil" not in template.recording
    assert "name: web-1" in template.recording
    # The goal keeps the characters, just never at a line start, the only position
    # `section_bodies` and the fence walker give meaning to.
    assert "## Executed query" in template.goal
    assert not any(
        ln.lstrip().startswith(("## ", "```", "~~~")) for ln in template.goal.splitlines()
    )


def test_a_placeholder_inside_a_bound_value_is_not_declared_as_an_interface(tmp_path):
    from defender.systems import _scaffold_rules

    cat = _catalog(tmp_path)
    lead_author.synthesize_drafts(
        [_lead("stub-cmdb.network-map", {"name": "web-${env}-1"}, verb="map")],
        **drafts_under(cat), systems=frozenset({"stub-cmdb"}))
    template = _minted(cat, "stub-cmdb", "stub-cmdb.network-map")
    assert template.params == ("name",)
    assert template.body_substitutions == ()
    assert "web-${env}-1" in template.recording
    # Vacuous: with no `## Query`, the placeholder rule has nothing to refuse the draft for.
    assert template.query == ""
    assert _scaffold_rules.check_template(template, _stub_verbs()) == []


def test_an_identity_a_template_already_covers_is_not_re_minted(tmp_path):
    cat = _catalog(tmp_path)
    (cat / "stub-cmdb").mkdir(parents=True)
    (cat / "stub-cmdb" / "auth-failure-rate.md").write_text(
        "---\nid: stub-cmdb.auth-failure-rate\nstatus: established\n"
        "covers: [stub-cmdb.network-map]\n---\n\n## Goal\nx\n"
    )
    assert lead_author.synthesize_drafts(
        [_lead("stub-cmdb.network-map", {"name": "web-1"}, verb="map")],
        **drafts_under(cat), systems=frozenset({"stub-cmdb"})) == []
    assert not (cat / "stub-cmdb" / "_draft").exists()


def test_the_recorded_instance_is_one_that_succeeded(tmp_path):
    import dataclasses

    cat = _catalog(tmp_path)
    failed = dataclasses.replace(
        _lead("stub-cmdb.network-map", {"name": "BROKEN"}, verb="map"),
        payload_status="error",
    )
    worked = _lead("stub-cmdb.network-map", {"name": "web-1"}, verb="map")
    lead_author.synthesize_drafts(
        [failed, worked], **drafts_under(cat), systems=frozenset({"stub-cmdb"}))
    template = _minted(cat, "stub-cmdb", "stub-cmdb.network-map")
    assert "web-1" in template.recording
    assert "BROKEN" not in template.recording


def test_the_first_successful_instance_wins_not_the_last(tmp_path):
    cat = _catalog(tmp_path)
    lead_author.synthesize_drafts([
        _lead("stub-cmdb.network-map", {"name": "first"}, verb="map"),
        _lead("stub-cmdb.network-map", {"name": "second"}, verb="map"),
    ], **drafts_under(cat), systems=frozenset({"stub-cmdb"}))
    template = _minted(cat, "stub-cmdb", "stub-cmdb.network-map")
    assert "first" in template.recording
    assert "second" not in template.recording


def test_a_sentinel_row_mints_nothing(tmp_path):
    import dataclasses

    cat = _catalog(tmp_path)
    sentinel = dataclasses.replace(
        _lead("stub-cmdb.network-map", {"name": "web-1"}, verb="map"), is_sentinel=True,
    )
    assert lead_author.synthesize_drafts(
        [sentinel], **drafts_under(cat), systems=frozenset({"stub-cmdb"})) == []
    assert not (cat / "stub-cmdb" / "_draft").exists()


def test_a_minted_draft_leaves_no_partial_file_behind(tmp_path):
    from defender.knowledge._corpus import iter_query_templates

    cat = _catalog(tmp_path)
    created = lead_author.synthesize_drafts(
        [_lead("stub-cmdb.network-map", {"name": "web-1"}, verb="map")],
        **drafts_under(cat), systems=frozenset({"stub-cmdb"}))
    assert created
    draft_dir = cat / "stub-cmdb" / "_draft"
    assert [p.name for p in draft_dir.iterdir()] == [created[0].name]
    # What a failed write leaves (`_io.stage_name`): on disk, invisible to the corpus walk.
    from defender._io import stage_name

    stage_name(draft_dir / "leftover.md").write_text("truncated\n---\nnot: frontmatter\n")
    assert [t.path for t in iter_query_templates(cat)] == sorted(
        p for p in (cat / "host-query" / "proc-tree.md", created[0])
    )
