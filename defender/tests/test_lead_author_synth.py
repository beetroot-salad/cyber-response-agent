"""Tests for lead_author.synthesize_drafts — the WARN-and-draft fix.

An executed query whose coined `{system}.{suffix}` id matches no catalog template must
be minted as a `{system}/_draft/{suffix}.md` skeleton (so the lead-author curates it)
rather than dropped. Ad-hoc leads (id with no `{system}.` prefix) and untagged calls
(id suffix == the row's recorded verb) are not catalog candidates and are skipped.

#620: re-pinned off the dead `params['arg0']` positional (the query tool never writes it)
onto the named-params row shape — the canonical record is the verb's declared body param
verbatim (an engine verb) or a structured `{verb, params}` call (a param-only verb), and
candidacy keys on the row's own recorded `verb`, not a hardcoded reserved-verb set.
"""
from __future__ import annotations

from pathlib import Path

from defender.learning.leads import lead_author


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
    """Build an isolated tmp catalog and return its dir.

    Pass the returned dir as ``synthesize_drafts(..., catalog_dir=cat)``: that
    threads the read root through to ``load_catalog`` (it both reads the template
    index from and writes drafts under the same dir), so no module-global patch is
    needed to keep the call off the real on-disk catalog."""
    cat = tmp_path / "queries"
    (cat / "host-query").mkdir(parents=True)
    (cat / "host-query" / "proc-tree.md").write_text(
        "---\nid: host-query.proc-tree\nstatus: established\n---\n\n## Goal\nx\n"
    )
    return cat


def test_unresolved_verb_is_drafted(tmp_path):
    cat = _catalog(tmp_path)
    created = lead_author.synthesize_drafts(
        [_lead("stub-cmdb.network-map", {"name": "web-1"}, verb="map")], catalog_dir=cat,
        systems=frozenset({"stub-cmdb"}))
    draft = cat / "stub-cmdb" / "_draft" / "network-map.md"
    assert created == [draft]
    text = draft.read_text()
    assert "id: stub-cmdb.network-map" in text
    assert "status: draft" in text


def test_resolved_verb_not_drafted(tmp_path):
    cat = _catalog(tmp_path)
    assert lead_author.synthesize_drafts(
        [_lead("host-query.proc-tree")], catalog_dir=cat,
        systems=frozenset({"host-query"})) == []


def test_adhoc_query_id_skipped(tmp_path):
    cat = _catalog(tmp_path)
    assert lead_author.synthesize_drafts(
        [_lead("ad-hoc")], catalog_dir=cat, systems=frozenset()) == []
    assert not (cat / "ad-hoc").exists()


def test_idempotent(tmp_path):
    cat = _catalog(tmp_path)
    first = lead_author.synthesize_drafts(
        [_lead("stub-cmdb.network-map", {"name": "web-1"}, verb="map")], catalog_dir=cat,
        systems=frozenset({"stub-cmdb"}))
    assert first
    second = lead_author.synthesize_drafts(
        [_lead("stub-cmdb.network-map", {"name": "web-1"}, verb="map")], catalog_dir=cat,
        systems=frozenset({"stub-cmdb"}))
    assert second == []



_ESQL_PIPE = (
    'FROM logs-system.auth-*\n'
    '| WHERE host.name == "db-1" AND event.outcome == "failure"\n'
    '| STATS failed = COUNT(*) BY source.ip'
)


def test_esql_draft_carries_literal_query_not_placeholder(tmp_path):
    """An elastic esql draft's ## Query is the exact pipe that ran (the verbatim `query` body
    param), engine-tagged — no KQL 'fill in the invocation' placeholder, no ## What to
    summarize."""
    cat = _catalog(tmp_path)
    lead_author.synthesize_drafts([
        _lead("elastic.sshd-failed-by-srcip", {"query": _ESQL_PIPE}, verb="esql",
              system="elastic"),
    ], catalog_dir=cat, systems=frozenset({"elastic"}))
    text = (cat / "elastic" / "_draft" / "sshd-failed-by-srcip.md").read_text()
    assert "engine: esql" in text
    assert "```esql" in text
    assert "STATS failed = COUNT(*) BY source.ip" in text
    assert "Fill in the real" not in text
    assert "## What to summarize" not in text
    assert "## Pitfalls" in text


def test_executed_query_is_the_declared_body_or_structured_call(tmp_path):
    """_executed_query returns the verbatim declared body param for an engine verb (esql →
    `query`) and a structured `{verb, params}` call for a param-only verb — never raw_command,
    never a dead `params['arg0']` read."""
    lead = _lead("elastic.x", {"query": _ESQL_PIPE}, verb="esql", system="elastic")
    assert lead_author._executed_query(lead) == _ESQL_PIPE
    param_lead = _lead("cmdb.host-lookup", {"host": "db-1"}, verb="get-host", system="cmdb",
                       raw_command="cmdb get-host host=db-1")
    record = lead_author._executed_query(param_lead)
    assert "get-host" in record
    assert "db-1" in record
    assert record != param_lead.raw_command


def test_executed_query_keys_on_recorded_verb_not_id_prefix(tmp_path):
    """The engine decision reads the queries-table `(system, verb)`, not the query_id prefix — a
    tagged query whose id namespace differs from the verb that actually ran is still classified
    by the real per-verb engine."""
    pipe = "FROM logs-system.auth-* | STATS c = COUNT(*)"
    el = _lead("custom.tagged", {"query": pipe}, verb="esql", system="elastic")
    assert lead_author._executed_query(el) == pipe
    non = _lead("elastic.weird", {"host": "10.0.0.5"}, verb="get-host", system="cmdb")
    record = lead_author._executed_query(non)
    assert "get-host" in record
    assert "10.0.0.5" in record


def test_malformed_query_id_does_not_mint_off_surface_draft(tmp_path):
    """A query_id with an empty system (`.verb`) or empty verb (`system.`) must
    not mint a draft off the `{system}/_draft/{kebab}` surface (the empty-system
    case would land at the catalog root `_draft/` and brick the post-flight)."""
    cat = _catalog(tmp_path)
    created = lead_author.synthesize_drafts([
        _lead(".verb", {"query": _ESQL_PIPE}, verb="esql", system="elastic"),
        _lead("elastic.", {"query": _ESQL_PIPE}, verb="esql", system="elastic"),
    ], catalog_dir=cat, systems=frozenset({"elastic"}))
    assert created == []
    assert not (cat / "_draft").exists()
    assert not (cat / "elastic" / "_draft" / ".md").exists()


def test_grok_braces_in_query_do_not_crash_skeleton(tmp_path):
    """A query body with ES|QL GROK braces (%{WORD:f}) must not break rendering."""
    cat = _catalog(tmp_path)
    grok_pipe = 'FROM logs-* | GROK message "%{IP:src} %{WORD:action}" | STATS c = COUNT(*) BY action'
    created = lead_author.synthesize_drafts([
        _lead("elastic.grok-probe", {"query": grok_pipe}, verb="esql", system="elastic"),
    ], catalog_dir=cat, systems=frozenset({"elastic"}))
    assert created
    assert "%{IP:src}" in (cat / "elastic" / "_draft" / "grok-probe.md").read_text()


def test_traversal_query_id_does_not_escape_catalog(tmp_path):
    """A query_id whose segments contain `/`, `..`, or a backslash must not write
    a draft outside the `{system}/_draft/` surface. Defense-in-depth at the sink:
    record_query rejects these at the boundary, but synthesize_drafts holds the
    line on its own for any already-persisted/foreign row."""
    cat = _catalog(tmp_path)
    created = lead_author.synthesize_drafts([
        _lead("elastic.../../../../PWNED", {"query": _ESQL_PIPE}, verb="esql", system="elastic"),
        _lead("../../etc.passwd", {"query": _ESQL_PIPE}, verb="esql", system="elastic"),
    ], catalog_dir=cat, systems=frozenset({"elastic"}))
    assert created == []
    assert not (tmp_path / "PWNED.md").exists()
    assert list(tmp_path.rglob("PWNED.md")) == []


def test_control_character_query_id_does_not_mint_an_unparseable_draft(tmp_path):
    """#852 F-21. A coined `query_id` segment ending in a NEWLINE must not pass the
    hostile-id guard, in either segment.

    `_SAFE_ID_SEGMENT` anchored with `$`, which also matches immediately before a trailing
    newline — so `"elastic\\n.probe"` passed, and `synthesize_drafts` minted (and the
    lead-author loop then committed) a catalog path holding a control character. That draft's
    own frontmatter no longer parses, so the id is permanently uncataloguable: `iter_query_
    templates` warn-skips the file and the pitfall it stands for is silently absent from the
    queue. The model chooses `query_id` freely — the `query` tool declares it as a bare
    `str | None`, and the boundary screens only `/ \\ .. NUL` and the `∅.` prefix — so the
    sink is where this has to hold."""
    cat = _catalog(tmp_path)
    created = lead_author.synthesize_drafts([
        _lead("elastic\n.probe", {"query": _ESQL_PIPE}, verb="esql", system="elastic"),
        _lead("elastic.probe\n", {"query": _ESQL_PIPE}, verb="esql", system="elastic"),
    ], catalog_dir=cat, systems=frozenset({"elastic"}))
    assert created == []
    assert [p for p in cat.rglob("*") if "\n" in p.name] == []
    assert not (cat / "elastic" / "_draft").exists()


def test_safe_id_segment_anchors_at_the_end_of_the_string():
    """The anchor itself, pinned: `\\Z` and not `$`, at both ends.

    Bound directly because the call sites read the guard through `match`, which hides a weak
    tail anchor — every id this rejects, it rejects for the same reason, and the next reader
    of this pattern should not have to rediscover which of the two anchors it is."""
    assert lead_author._SAFE_ID_SEGMENT.match("elastic") is not None
    assert lead_author._SAFE_ID_SEGMENT.match("elastic\n") is None
    assert lead_author._SAFE_ID_SEGMENT.match("elastic\nprobe") is None
    assert lead_author._SAFE_ID_SEGMENT.search("!!elastic") is None


def _stub_verbs():
    """A verb roster standing in for a system's adapter, so a minted draft can be run through
    the SAME rule the loop's commit gate and CI run it through."""
    from defender.runtime.verbs import VerbContext, verb

    @verb()
    def esql(ctx: VerbContext, *, query: str = "") -> dict:
        return {}

    @verb()
    def map_(ctx: VerbContext, *, name: str = "") -> dict:
        return {}

    return {"esql": esql, "map": map_}


def _minted(cat, system: str, name: str):
    from defender._corpus import read_query_template

    template, reason = read_query_template(cat / system / "_draft" / f"{name}.md")
    assert template is not None, reason
    return template


def test_a_minted_draft_declares_the_verb_it_was_minted_from(tmp_path):
    """#901's positive control for the minter.

    The skeleton emitted `id`, `status` and (for an engine verb) `engine` — no `verb:`, no
    `params:` — while `SCHEMA.md` makes both part of the format and says outright they exist so
    the scaffold check can read them. Nothing noticed because no check ever ran on `_draft/`:
    point one at the directory and every synthesized draft fails it on rule one. The verb is in
    hand at the mint (`lead.verb`), so this is a declaration the loop was throwing away."""
    from defender import _scaffold_rules

    cat = _catalog(tmp_path)
    lead_author.synthesize_drafts(
        [_lead("stub-cmdb.network-map", {"name": "web-1"}, verb="map")],
        catalog_dir=cat, systems=frozenset({"stub-cmdb"}))
    template = _minted(cat, "stub-cmdb", "network-map")
    assert template.verb == "map"
    assert template.params == ("name",)
    assert _scaffold_rules.check_template(template, _stub_verbs()) == []


def test_a_minted_engine_draft_does_not_declare_the_body_param_it_spent(tmp_path):
    """An engine verb's body param is not bound by a `${placeholder}` in the minted file — its
    VALUE became the fenced `## Query` body. Declaring it would describe a file that does not
    exist, and would be the one `params:` entry no reader could reconcile against the text."""
    from defender import _scaffold_rules

    cat = _catalog(tmp_path)
    lead_author.synthesize_drafts([
        _lead("elastic.sshd-failed-by-srcip", {"query": _ESQL_PIPE}, verb="esql",
              system="elastic"),
    ], catalog_dir=cat, systems=frozenset({"elastic"}))
    template = _minted(cat, "elastic", "sshd-failed-by-srcip")
    assert template.verb == "esql"
    assert template.params == ()
    assert _scaffold_rules.check_template(template, _stub_verbs()) == []


def test_a_row_whose_verb_is_not_a_plain_name_mints_nothing(tmp_path):
    """The verb is spent as a frontmatter DECLARATION now, so it is held to the alphabet the id
    segments already were (#852 F-21). A draft whose `verb:` resolves to nothing would fail the
    corpus-wide check and take the lane's next commit down with it — and the row is not lost,
    the shared candidacy predicate routes it to the pitfalls residue instead."""
    cat = _catalog(tmp_path)
    assert lead_author.synthesize_drafts([
        _lead("stub-cmdb.network-map", {"name": "web-1"}, verb="map\nname: evil"),
        _lead("stub-cmdb.other-map", {"name": "web-1"}, verb=""),
    ], catalog_dir=cat, systems=frozenset({"stub-cmdb"})) == []
    assert not (cat / "stub-cmdb" / "_draft").exists()


def test_a_coined_id_naming_another_system_mints_nothing(tmp_path):
    """`resolve_query_id` returns a model-coined `query_id` VERBATIM once it clears the
    reserved/traversal screen, so nothing upstream ties its routing prefix to the system the
    call actually reached. Unpinned, a `cmdb` call coined `ghost.something` mints
    `queries/ghost/_draft/something.md`: a catalog directory for a system no adapter declares
    (#855 F-06), carrying a `verb:`/`engine:` resolved against `cmdb`, which the corpus-wide
    scaffold sweep cannot even evaluate — it raises rather than reporting a finding, so one
    such draft is a CI break rather than a refusal. The row is not lost: the predicate is
    shared with `collect_general_failures`, so it lands in the pitfalls residue instead."""
    cat = _catalog(tmp_path)
    # `ghost` is DECLARED here, deliberately: #869's `system not in systems` filter would
    # reject an undeclared prefix on its own, so a test that left it undeclared would pass
    # without this check existing. Declaring it leaves the id/row DISAGREEMENT as the only
    # thing that can refuse the mint.
    assert lead_author.synthesize_drafts(
        [_lead("ghost.something", {"name": "web-1"}, verb="map", system="stub-cmdb")],
        catalog_dir=cat, systems=frozenset({"ghost", "stub-cmdb"})) == []
    assert not (cat / "ghost").exists()


def test_a_placeholder_inside_a_bound_value_is_declared_body_text(tmp_path):
    """A param-only verb's minted `## Query` holds literal VALUES, so any `${…}` reaching the
    file came out of the DATA (`host: web-${env}-1`) — and the placeholder rule reads the
    rendered body, not the intent. Undeclared, that one value mints a draft the corpus-wide
    sweep refuses; and the lane's commit gate deliberately does not check `_draft/`, so the
    refusal lands in CI on everyone rather than on the batch that wrote it."""
    from defender import _scaffold_rules

    cat = _catalog(tmp_path)
    lead_author.synthesize_drafts(
        [_lead("stub-cmdb.network-map", {"name": "web-${env}-1"}, verb="map")],
        catalog_dir=cat, systems=frozenset({"stub-cmdb"}))
    template = _minted(cat, "stub-cmdb", "network-map")
    assert template.params == ("name",)
    assert template.body_substitutions == ("env",)
    assert _scaffold_rules.check_template(template, _stub_verbs()) == []


def test_untagged_verb_not_drafted(tmp_path):
    """A bare `{system}.{verb}` id whose suffix IS the recorded verb (no coined --query-id) is a
    non-candidate — an untagged call must not mint a junk catch-all draft."""
    cat = _catalog(tmp_path)
    assert lead_author.synthesize_drafts([
        _lead("elastic.esql", {"query": _ESQL_PIPE}, verb="esql", system="elastic"),
    ], catalog_dir=cat, systems=frozenset({"elastic"})) == []
    assert not (cat / "elastic" / "_draft" / "esql.md").exists()
