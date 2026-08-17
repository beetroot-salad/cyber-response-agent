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


def _draft_path(cat, system: str, query_id: str):
    """Where the mint puts the draft for `query_id` — the derived name, recomputed.

    Through `lead_author._draft_basename` rather than against a literal digest, so these tests
    bind to the RULE (the basename is a function of the coined id) and not to the output of one
    hash at one length. A test carrying `3b4b25fa1be8` would have to be re-typed to change
    `_DIGEST_LEN`, which is the kind of edit that gets made by pasting whatever the code now
    prints — the opposite of a test."""
    return cat / system / "_draft" / f"{lead_author._draft_basename(query_id)}.md"


def test_unresolved_verb_is_drafted(tmp_path):
    cat = _catalog(tmp_path)
    created = lead_author.synthesize_drafts(
        [_lead("stub-cmdb.network-map", {"name": "web-1"}, verb="map")], catalog_dir=cat,
        systems=frozenset({"stub-cmdb"}))
    draft = _draft_path(cat, "stub-cmdb", "stub-cmdb.network-map")
    assert created == [draft]
    text = draft.read_text()
    assert f"id: stub-cmdb.{lead_author._draft_basename('stub-cmdb.network-map')}" in text
    assert "status: draft" in text
    # The coined name is not discarded by the digest — it is kept where the dedup, the commit
    # gate and the author all read it.
    assert "covers:" in text
    assert "stub-cmdb.network-map" in text


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
    text = _draft_path(cat, "elastic", "elastic.sshd-failed-by-srcip").read_text()
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
    assert "%{IP:src}" in _draft_path(cat, "elastic", "elastic.grok-probe").read_text()


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


def _minted(cat, system: str, query_id: str):
    from defender._corpus import read_query_template

    template, reason = read_query_template(_draft_path(cat, system, query_id))
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
    template = _minted(cat, "stub-cmdb", "stub-cmdb.network-map")
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
    template = _minted(cat, "elastic", "elastic.sshd-failed-by-srcip")
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


def test_a_coined_id_cannot_mint_a_basename_the_commit_gate_discards_the_batch_for(tmp_path):
    """The three basenames the write gate stopped admitting (#772) are the three the HOST-side
    minter could still write — and the derived name is what retires the question.

    `resolve_query_id`'s kebab segment (`[A-Za-z0-9][A-Za-z0-9_-]*`) admits `SCHEMA`, `README`
    and `execution` like any other name, so a model-coined `{system}.SCHEMA` minted
    `queries/{system}/_draft/SCHEMA.md` before the agent was ever spawned — and
    `_skills_path_rule` then refuses that file as a protected surface (`_is_schema_md` reads the
    basename at ANY depth under the catalog), which discards the WHOLE tick's batch rather than
    denying one call.

    #917 review: the mint no longer takes its basename from the coined id, so these rows are no
    longer REFUSED — they are minted, under a digest, and the protected-surface question cannot
    arise. That is the stronger property and it is what this now pins: the coined name survives
    in `covers:` (it is the author's evidence), and NO minted path is one the gate refuses. The
    old shape held the same line by enumerating three names, which is a list that has to be
    maintained against `_skills_path_rule` forever."""
    from defender.learning.leads.path_validation import (
        CATALOG_REL,
        _is_draft_readme,
        _is_schema_md,
    )

    cat = _catalog(tmp_path)
    hostile = [
        _lead(f"stub-cmdb.{seg}", {"name": "web-1"}, verb="map")
        for seg in ("SCHEMA", "README", "execution")
    ]
    created = lead_author.synthesize_drafts(
        hostile, catalog_dir=cat, systems=frozenset({"stub-cmdb"}))
    assert len(created) == 3
    for path in created:
        rel = f"{CATALOG_REL}stub-cmdb/_draft/{path.name}"
        assert not _is_schema_md(rel)
        assert not _is_draft_readme(rel)
        assert path.name != "execution.md"
    # Each one still records which coined id it came from, so the author can see that gather
    # called this measurement `SCHEMA` and name it something a catalog can carry.
    assert {
        _minted(cat, "stub-cmdb", f"stub-cmdb.{seg}").covers
        for seg in ("SCHEMA", "README", "execution")
    } == {("stub-cmdb.SCHEMA",), ("stub-cmdb.README",), ("stub-cmdb.execution",)}


def test_a_goal_carrying_a_line_separator_cannot_forge_a_section(tmp_path):
    """`goal_text` is model-authored, and `_corpus.section_bodies` walks `splitlines()` — which
    breaks on `\\r`, `\\x1c`-`\\x1e`, `\\x85` and `\\u2028` as well as on `\\n`. Stripping only
    `\\n` let a goal open a new LINE in the minted draft, so a `## ` heading or a ``` fence
    smuggled into one re-partitioned the template and could swallow the recording — the same
    control-character class `_SAFE_ID_SEGMENT`'s `\\Z` anchor closes on the id (#852 F-21).

    Asserted through the CORPUS READER, not on the raw text: what has to survive is the section
    walk, and the `## Executed query` body it returns is the draft's whole evidence."""
    import dataclasses

    cat = _catalog(tmp_path)
    lead = dataclasses.replace(
        _lead("stub-cmdb.network-map", {"name": "web-1"}, verb="map"),
        goal_text="probe\r## Executed query\r```query\rverb: evil\r```",
    )
    lead_author.synthesize_drafts(
        [lead], catalog_dir=cat, systems=frozenset({"stub-cmdb"}))
    template = _minted(cat, "stub-cmdb", "stub-cmdb.network-map")
    assert "evil" not in template.recording
    assert "name: web-1" in template.recording
    # The goal still CARRIES the model's characters — they are just no longer at a line start,
    # which is the only position `section_bodies` and the fence walker give meaning to.
    assert "## Executed query" in template.goal
    assert not any(
        ln.lstrip().startswith(("## ", "```", "~~~")) for ln in template.goal.splitlines()
    )


def test_a_placeholder_inside_a_bound_value_is_not_declared_as_an_interface(tmp_path):
    """A `${…}` that came out of the DATA declares nothing about the template. INVERTS the
    #901 test of the same shape, which asserted `body_substitutions == ("env",)`.

    That test pinned a model this one rejects. `body_substitutions:` says a `${name}` in the
    template's `## Query` is body text a dispatch fills — an INTERFACE claim. A draft is a
    transcript of a call that already ran, so it has no holes: `host: web-${env}-1` is a value
    that went to the system with those eight characters in it, most likely because the model
    failed to substitute. Declaring it asserted a hole where the recording shows a literal.

    The old model was also self-contradictory, which is what surfaced it. #900's
    `reserved-body-substitution` rule refuses a `body_substitutions:` entry naming a
    `@verb(wrapper_only=…)` param, so a bound value carrying `${require_closed}` minted a draft
    that the corpus-wide sweep refused on TWO codes — and the lane's commit gate deliberately
    does not read `_draft/`, so that refusal landed in CI on everyone. Deriving the declaration
    from data is what made those two rules disagree; there is no declaration to disagree now.

    The recording still carries the value verbatim: it is evidence, and mangling it would lose
    a query that legitimately hunted a literal `${…}` string."""
    from defender import _scaffold_rules

    cat = _catalog(tmp_path)
    lead_author.synthesize_drafts(
        [_lead("stub-cmdb.network-map", {"name": "web-${env}-1"}, verb="map")],
        catalog_dir=cat, systems=frozenset({"stub-cmdb"}))
    template = _minted(cat, "stub-cmdb", "stub-cmdb.network-map")
    assert template.params == ("name",)
    assert template.body_substitutions == ()
    assert "web-${env}-1" in template.recording
    # Vacuous rather than satisfied: there is no `## Query`, so the placeholder rule has no
    # text to classify and cannot refuse the draft for the shape of the data it recorded.
    assert template.query == ""
    assert _scaffold_rules.check_template(template, _stub_verbs()) == []


def test_a_wrapper_only_name_in_a_bound_value_no_longer_mints_a_refused_draft(tmp_path):
    """The #917 review finding, end to end.

    A gather lead against a verb with a `@verb(wrapper_only=…)` param, binding a VALUE that
    contains that param's name in `${…}` form, used to mint a draft declaring
    `body_substitutions: [require_closed]` — which `check_template` refuses twice, as
    `reserved-body-substitution` AND `undeclared-placeholder`. Neither refusal reaches the
    batch that wrote it (the commit gate skips `_draft/`), so it landed in CI on everyone,
    from model-supplied telemetry text."""
    from defender import _scaffold_rules
    from defender.runtime.verbs import VerbContext, verb

    @verb(wrapper_only=("require_closed",))
    def get_ticket(ctx: VerbContext, *, key: str = "", require_closed: bool = False) -> dict:
        return {}

    cat = _catalog(tmp_path)
    lead_author.synthesize_drafts(
        [_lead("stub-cmdb.case-lookup", {"key": "ABC-${require_closed}"}, verb="get-ticket")],
        catalog_dir=cat, systems=frozenset({"stub-cmdb"}))
    template = _minted(cat, "stub-cmdb", "stub-cmdb.case-lookup")
    assert template.body_substitutions == ()
    assert _scaffold_rules.check_template(template, {"get-ticket": get_ticket}) == []


def test_untagged_verb_not_drafted(tmp_path):
    """A bare `{system}.{verb}` id whose suffix IS the recorded verb (no coined --query-id) is a
    non-candidate — an untagged call must not mint a junk catch-all draft."""
    cat = _catalog(tmp_path)
    assert lead_author.synthesize_drafts([
        _lead("elastic.esql", {"query": _ESQL_PIPE}, verb="esql", system="elastic"),
    ], catalog_dir=cat, systems=frozenset({"elastic"})) == []
    assert not (cat / "elastic" / "_draft").exists()


def test_an_identity_a_template_already_covers_is_not_re_minted(tmp_path):
    """The point of `covers:`, and the regression the derived name would otherwise open.

    While a promote was `_draft/{id}.md` -> `{id}.md`, the promoted template's `id:` still
    echoed the coined `query_id`, so `by_id` suppressed the re-mint for free. Once the author
    names the file for what it MEASURES that echo is gone, and a `by_id` built from ids alone
    would mint the draft again on the next run that coins the id — and the author, following
    the same prompt, would discard it again. `covers:` is the only thing left tying the row to
    the template that answered it."""
    cat = _catalog(tmp_path)
    (cat / "stub-cmdb").mkdir(parents=True)
    (cat / "stub-cmdb" / "auth-failure-rate.md").write_text(
        "---\nid: stub-cmdb.auth-failure-rate\nstatus: established\n"
        "covers: [stub-cmdb.network-map]\n---\n\n## Goal\nx\n"
    )
    assert lead_author.synthesize_drafts(
        [_lead("stub-cmdb.network-map", {"name": "web-1"}, verb="map")],
        catalog_dir=cat, systems=frozenset({"stub-cmdb"})) == []
    assert not (cat / "stub-cmdb" / "_draft").exists()


def test_the_recorded_instance_is_one_that_succeeded(tmp_path):
    """WHICH execution becomes the draft's evidence.

    `query_id` is the identity a call asserts and the bound values are instances under it, so a
    tick routinely carries several rows for one identity — and the mint takes the first and
    dedups the rest. In document order that could be a row whose payload came back `error`
    while a later row under the same id returned data, recording a failed call as the exemplar
    for the measurement and dropping the successful one. A failed call is evidence about the
    call, not about what the template measures."""
    import dataclasses

    cat = _catalog(tmp_path)
    failed = dataclasses.replace(
        _lead("stub-cmdb.network-map", {"name": "BROKEN"}, verb="map"),
        payload_status="error",
    )
    worked = _lead("stub-cmdb.network-map", {"name": "web-1"}, verb="map")
    lead_author.synthesize_drafts(
        [failed, worked], catalog_dir=cat, systems=frozenset({"stub-cmdb"}))
    template = _minted(cat, "stub-cmdb", "stub-cmdb.network-map")
    assert "web-1" in template.recording
    assert "BROKEN" not in template.recording


def test_the_first_successful_instance_wins_not_the_last(tmp_path):
    """The partition is STABLE — among rows that succeeded, document order still decides.

    Bound separately from the test above because that one is satisfied by ANY reordering that
    floats a successful row to the front, including one that also shuffles the successful rows
    among themselves — which would make the recorded instance depend on how the ordering is
    spelled rather than on the order the defender ran them in."""
    cat = _catalog(tmp_path)
    lead_author.synthesize_drafts([
        _lead("stub-cmdb.network-map", {"name": "first"}, verb="map"),
        _lead("stub-cmdb.network-map", {"name": "second"}, verb="map"),
    ], catalog_dir=cat, systems=frozenset({"stub-cmdb"}))
    template = _minted(cat, "stub-cmdb", "stub-cmdb.network-map")
    assert "first" in template.recording
    assert "second" not in template.recording


def test_a_sentinel_row_mints_nothing(tmp_path):
    """A `∅.`-prefixed row records something that never reached a system (a refused repeat, a
    failed shim), so there is no measurement to draft.

    Asked as `is_sentinel` — the predicate the projection already partitioned on (#841) —
    rather than left to fall out of `_SAFE_ID_SEGMENT` rejecting `∅`. That alphabet accident
    answers correctly today and is not a decision about sentinels: it would stop answering the
    moment the sentinel prefix or the guard's character class changed."""
    import dataclasses

    cat = _catalog(tmp_path)
    sentinel = dataclasses.replace(
        _lead("stub-cmdb.network-map", {"name": "web-1"}, verb="map"), is_sentinel=True,
    )
    assert lead_author.synthesize_drafts(
        [sentinel], catalog_dir=cat, systems=frozenset({"stub-cmdb"})) == []
    assert not (cat / "stub-cmdb" / "_draft").exists()


def test_a_minted_draft_leaves_no_partial_file_behind(tmp_path):
    """The write is atomic, so a reader sees the whole draft or no draft.

    `write_text` into the live catalog path left a window in which a crash lands a truncated
    file — and a truncated draft is one whose frontmatter no longer parses, which every reader
    reports as "the minter wrote a bad file" rather than as a partial write. `_io.write_atomic`
    stages under `{name}.staged-{hex}` and `os.replace`s, so a leftover from a failed run does
    not end in `.md` and matches neither corpus glob — asserted here, because a staged name
    that DID match would have the next sweep report it as a malformed template."""
    from defender._corpus import iter_query_templates

    cat = _catalog(tmp_path)
    created = lead_author.synthesize_drafts(
        [_lead("stub-cmdb.network-map", {"name": "web-1"}, verb="map")],
        catalog_dir=cat, systems=frozenset({"stub-cmdb"}))
    assert created
    draft_dir = cat / "stub-cmdb" / "_draft"
    assert [p.name for p in draft_dir.iterdir()] == [created[0].name]
    # The shape a failed write would leave, spelled as `_io.stage_name` spells it: present on
    # disk, invisible to the corpus walk.
    from defender._io import stage_name

    stage_name(draft_dir / "leftover.md").write_text("truncated\n---\nnot: frontmatter\n")
    assert [t.path for t in iter_query_templates(cat)] == sorted(
        p for p in (cat / "host-query" / "proc-tree.md", created[0])
    )
