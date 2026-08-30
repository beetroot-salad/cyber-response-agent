"""#947 — Elasticsearch corpus staging, its guard, its record, and its removal (M3, M9, O5).

Staging is the FIRST code in `defender/` that writes to the cluster: at b8a63e66 the
`elastic_corpus` root has no writer at all (C9/G10, re-verified). Everything here is therefore
new surface, and its three negative universals are the whole security case:

* no staging call targets a name a configured corpus pattern reaches;
* no staging call targets a name outside `is_world_view` for its OWN token;
* nothing staging creates is unrecorded at the moment it is created.

The write door is host-side and separate: it reaches `transport.docker_exec_curl` with PUT and
DELETE (X9's executed signature), never `_http_json`, whose door is read-confined to four
endpoints (C14/C27). Because that door bypasses `guard_outbound` — which is ALSO the capture
recorder (G15/F9) — `staged.yaml` is the SOLE record of a cluster write, which is why the
append must be durable BEFORE the create is issued and not merely ordered before it.

RED against b8a63e66: `learning/branch/staging.py` does not exist (X16). The confinement
primitives it builds on DO, so every naming assertion below drives the real
`world_view` / `is_world_view` / `_reach_ok` rather than a fixture's idea of them.
"""
from __future__ import annotations

import json

import pytest

from defender.tests import _triplet_947 as T

TOKEN = T.world_token("b")
VIEW = f"wv-{TOKEN}-logs-"
INJECT = f"{VIEW}.inject"


def _staging():
    return T.mod("learning.branch.staging")


def _refused():
    return _staging().StagingRefused


def _world(**kw):
    ov = kw.pop("ov", T.overlay(elastic=T.elastic_overlay(inject=[{"_id": "i1"}])))
    return T.mod("runtime.branch._family").parse_world(T.world_doc("b", ov=ov, **kw))


def _stage(episode_dir, *, door, world=None, patterns=T.CONFIGURED):
    return _staging().stage_world(
        world if world is not None else _world(), episode_dir=episode_dir,
        episode_token=T.EPISODE_TOKEN, configured_patterns=patterns, door=door)


# ---------------------------------------------------------------------------------------
# the namespace guard, and its positive control
# ---------------------------------------------------------------------------------------


def test_947_staging_refuses_a_target_outside_is_world_view_for_its_token(tmp_path):
    """A staging target that is not a world view of THIS world's own token is refused: a
    sibling's alias, and a view of a corpus this run never configured, are both out of bounds
    even though each is a well-formed name in the namespace."""
    door = T.FakeDoor()
    for foreign in (f"wv-{T.world_token('c')}-logs-", f"wv-{TOKEN}-other"):
        with pytest.raises(_refused()) as bad:
            _staging().stage_name(foreign, episode_token=T.EPISODE_TOKEN, world_id="b",
                                  configured_patterns=T.CONFIGURED, door=door)
        assert foreign in str(bad.value)
    assert door.calls == []


def test_947_staging_refuses_a_target_a_configured_pattern_reaches(tmp_path):
    """A staging target any configured corpus pattern still REACHES is refused: a view the base
    pattern matches is one the base run and every non-staging sibling would read this world's
    documents through, which is the contamination the namespace exists to prevent."""
    door = T.FakeDoor()
    with pytest.raises(_refused()) as bad:
        _staging().stage_name("logs-wv-b", episode_token=T.EPISODE_TOKEN, world_id="b",
                              configured_patterns=T.CONFIGURED, door=door)
    assert "logs-wv-b" in str(bad.value)
    assert door.calls == []


def test_947_a_well_formed_world_view_target_is_accepted(tmp_path):
    """The positive control for the namespace guard: a view derived from a configured pattern
    for this world's own token is accepted and staged — including the alerts pattern, whose
    dotted, hyphenated spelling is the one most likely to trip a naming rule."""
    confinement = T.mod("scripts.adapters.confinement")
    door = T.FakeDoor()
    for pattern in T.CONFIGURED:
        name = confinement.world_view(pattern, TOKEN)
        assert _staging().stage_name(name, episode_token=T.EPISODE_TOKEN, world_id="b",
                                     configured_patterns=T.CONFIGURED, door=door) == name
        assert confinement.is_world_view(name, T.CONFIGURED, TOKEN)


def test_947_a_refused_staging_target_opens_no_connection(tmp_path):
    """A refused staging target opens no connection: the guard is a pre-flight check on the
    NAME, so a refusal costs the cluster nothing and leaves nothing half-created."""
    door = T.FakeDoor()
    ep = T.episode(tmp_path)
    bad_world = _world(ov=T.overlay(elastic={"logs-wv-b": {"inject": [{"_id": "i"}],
                                                            "exclude": None}}))
    with pytest.raises(_refused()):
        _stage(ep, door=door, world=bad_world)
    assert door.connections == 0
    assert door.created() == []


# ---------------------------------------------------------------------------------------
# the write-ahead record
# ---------------------------------------------------------------------------------------


def test_947_every_staged_name_is_recorded_before_it_is_created(tmp_path):
    """Every name staging creates is appended to the staging record BEFORE the create is
    issued: a door that fails on its first create still leaves that name recorded, because the
    record is what teardown and the next launcher's sweep reconcile against."""
    ep = T.episode(tmp_path)
    door = T.FakeDoor(fault=T.Fault(fail_on=(INJECT,)))
    with pytest.raises(T.refusals()):
        _stage(ep, door=door)
    assert [r["name"] for r in T.staged_rows(ep)] == [INJECT]


def test_947_the_staging_append_is_durable_before_the_create_is_issued(tmp_path):
    """The staging append reaches DURABLE storage before the create is issued, not merely a
    buffer: a door that reads the record from disk at the moment it is called finds the name
    already there, which is the only reading under which a killed launcher can be reconciled."""
    ep = T.episode(tmp_path)
    seen: list[list[str]] = []

    class Watching(T.FakeDoor):
        def create_index(self, name, *, docs):
            seen.append([r["name"] for r in T.staged_rows(ep)])
            super().create_index(name, docs=docs)

    _stage(ep, door=Watching())
    assert seen, "the create never ran"
    assert INJECT in seen[0], "the create ran before the record was on disk"


def test_947_staging_record_carries_world_name_kind_derived_from_and_time(tmp_path):
    """Each staging row carries the world it belongs to, the name created, whether that name is
    an alias or an index, the base pattern it was derived from, and when — every slot the
    record's own type declares."""
    ep = T.episode(tmp_path)
    _stage(ep, door=T.FakeDoor())
    rows = T.staged_rows(ep)
    assert rows, "staging wrote no record"
    for row in rows:
        assert set(row) >= {"world", "name", "kind", "derived_from", "created_at"}
        assert row["world"] == TOKEN
        assert row["kind"] in {"alias", "index"}
        assert row["derived_from"] == T.EVENTS_PATTERN


def test_947_staging_record_is_append_only_across_worlds(tmp_path):
    """The staging record is append-only across worlds: staging a second world adds its rows
    after the first world's, and no earlier row is rewritten or dropped."""
    ep = T.episode(tmp_path)
    door = T.FakeDoor()
    _stage(ep, door=door)
    first = T.staged_rows(ep)
    other = T.mod("runtime.branch._family").parse_world(
        T.world_doc("c", ov=T.overlay(elastic=T.elastic_overlay(inject=[{"_id": "i2"}]))))
    _staging().stage_world(other, episode_dir=ep, episode_token=T.EPISODE_TOKEN,
                           configured_patterns=T.CONFIGURED, door=door)
    after = T.staged_rows(ep)
    assert after[:len(first)] == first
    assert len(after) > len(first)
    assert {r["world"] for r in after} == {TOKEN, T.world_token("c")}


def test_947_an_unparseable_staging_record_refuses(tmp_path):
    """A staging record that does not parse REFUSES rather than being guessed at: acting on a
    record this code cannot read means deleting a name it did not write, or leaving one it
    did."""
    ep = T.episode(tmp_path)
    (ep / "staged.yaml").write_text("- {world: b, name: [unclosed\n", encoding="utf-8")
    with pytest.raises(T.refusals()) as bad:
        _staging().teardown(ep, door=T.FakeDoor())
    assert "staged.yaml" in str(bad.value)


# ---------------------------------------------------------------------------------------
# the door itself
# ---------------------------------------------------------------------------------------


def test_947_the_write_door_is_host_side_and_only_staging_calls_it(tmp_path):
    """The cluster's write door is a host-side function in the staging module, and staging,
    teardown and the sweep are the only callers: no adapter verb and no registry path reaches
    it, so a model-dispatched call has no route to a cluster write."""
    door_fn = _staging().write_door
    assert door_fn.__module__ == "defender.learning.branch.staging"
    adapters = (T.DEFENDER / "scripts" / "adapters").rglob("*.py")
    for path in adapters:
        assert "write_door" not in path.read_text(encoding="utf-8"), path
    runtime = (T.DEFENDER / "runtime").rglob("*.py")
    for path in runtime:
        assert "branch.staging" not in path.read_text(encoding="utf-8"), path


def test_947_no_verb_can_reach_the_cluster_write_door(tmp_path):
    """The read path gains no write: the adapter's endpoint allowlist admits no write method and
    no staging endpoint, and the write door is unreachable from the registry every verb resolves
    through."""
    confinement = T.mod("scripts.adapters.confinement")
    allow = confinement.READ_ENDPOINT_ALLOWLIST["elastic"]
    assert {method for _path, method in allow} == {"POST", "GET"}
    for path, _method in allow:
        assert "_aliases" not in path
        assert "_count" not in path
    registry = T.mod("learning.branch.estate.registry")
    assert not hasattr(registry.WorldRegistry, "write_door")


def test_947_staging_writes_through_docker_exec_curl_not_http_json(tmp_path):
    """Staging writes through the container-exec curl transport with PUT and DELETE, never
    through the read-confined HTTP helper: the transport records the write methods, and the
    read helper is never called."""
    transport = T.FakeTransport()
    door = _staging().write_door(ctx=None, container="es", transport=transport)
    door.create_index(INJECT, docs=[{"_id": "i1"}])
    door.delete(INJECT)
    assert set(transport.methods) >= {"PUT", "DELETE"}
    assert all(INJECT in url for url in transport.urls)


def test_947_a_derived_staging_name_reaches_the_transport_as_a_discrete_argument(tmp_path):
    """A derived staging name reaches the transport as a discrete argument and never as text
    concatenated into a shell string: a name carrying shell metacharacters arrives whole, in the
    URL slot, and no second command or argument appears anywhere in the recorded call."""
    transport = T.FakeTransport()
    door = _staging().write_door(ctx=None, container="es", transport=transport)
    hostile = f"wv-{T.EPISODE_TOKEN}.b-logs-;id"
    with pytest.raises(T.refusals()):
        door.create_index(hostile, docs=[])
    for call in transport.calls:
        assert ";" not in call["container"]
        assert call["url"].count(";") <= 1
        assert "$(" not in call["url"]
        assert "&&" not in call["url"]


def test_947_an_unparseable_staging_status_is_a_failure_never_a_success(tmp_path):
    """The staging door reads an unparseable response status as a FAILURE, never as a success:
    a body with no trailing status line is the shape the one shipped write door misreads as
    `200`, and against a write-ahead-recorded name that is the one direction the record does not
    tolerate. The name stays recorded for teardown either way."""
    ep = T.episode(tmp_path)
    transport = T.FakeTransport(fault=T.Fault(malformed="no-status-line"))
    door = _staging().write_door(ctx=None, container="es", transport=transport)
    with pytest.raises(T.refusals()):
        _stage(ep, door=door)
    assert [r["name"] for r in T.staged_rows(ep)][:1] == [INJECT]


# ---------------------------------------------------------------------------------------
# what a world stages: the injection, the alias, the exclusion
# ---------------------------------------------------------------------------------------


def test_947_an_injected_document_is_written_only_into_a_wv_injection_index(tmp_path):
    """A model-authored injected document is written into the world's own `.inject` index and
    nowhere else: no base index, no sibling's index, and no name outside the namespace receives
    a document."""
    ep = T.episode(tmp_path)
    door = T.FakeDoor()
    _stage(ep, door=door)
    writes = [c for c in door.calls if c.op == "create_index"]
    assert [c.name for c in writes] == [INJECT]
    assert writes[0].payload["docs"] == [{"_id": "i1"}]
    assert all(c.name.startswith("wv-") for c in door.calls if c.op in
               {"create_index", "create_alias"})


def test_947_base_index_document_count_is_unchanged_across_staging(tmp_path):
    """Staging leaves every base index untouched: the concrete indices behind a configured
    pattern hold the same document count after staging as before, and no write names one."""
    ep = T.episode(tmp_path)
    door = T.FakeDoor(counts={"logs-000001": 42}, resolves={T.EVENTS_PATTERN: ("logs-000001",)})
    before = door.count("logs-000001")
    _stage(ep, door=door)
    assert door.count("logs-000001") == before == 42
    assert not any(c.name == "logs-000001" for c in door.calls
                   if c.op in {"create_index", "create_alias", "delete"})


def test_947_a_plain_exclusion_predicate_is_accepted_and_staged(tmp_path):
    """The positive control for the predicate gate: an ordinary document-matching exclusion is
    accepted and reaches the alias as its filter, so the gate's refusals are proof of a working
    mechanism rather than of a channel that returns nothing."""
    ep = T.episode(tmp_path)
    door = T.FakeDoor()
    _stage(ep, door=door, world=_world(ov=T.overlay(elastic=T.elastic_overlay(
        inject=[{"_id": "i1"}], exclude={"term": {"process.name": "nc"}}))))
    alias = door.only("create_alias")
    assert alias.name == VIEW
    assert alias.payload["filter"] == {"term": {"process.name": "nc"}}
    assert INJECT in alias.payload["over"]


def test_947_exclusion_predicate_carrying_a_script_clause_is_refused(tmp_path):
    """An exclusion predicate carrying an executable clause is refused before anything is
    staged — each of the three named clause types, and each of them nested where a top-level key
    census does not walk."""
    ep = T.episode(tmp_path)
    for clause in ("script", "script_score", "runtime_mappings"):
        for predicate in ({clause: {"source": "1"}},
                          {"bool": {"must": [{clause: {"source": "1"}}]}}):
            door = T.FakeDoor()
            with pytest.raises(_refused()) as bad:
                _stage(ep, door=door, world=_world(ov=T.overlay(elastic=T.elastic_overlay(
                    inject=[], exclude=predicate))))
            assert clause in str(bad.value)
            assert door.connections == 0


def test_947_only_an_allow_listed_predicate_clause_type_is_admitted(tmp_path):
    """The predicate gate is an ALLOW-list over the grammar, not a census of three forbidden
    names: only clause types that express document matching are admitted — term, terms, range,
    match, boolean combinations and `match_all`, the sixth the §7 round-2 seam added so that a
    full-match exclusion has an admissible spelling at all — and any other clause type is refused
    whether or not it is executable, because the predicate selects documents for removal at
    staging and is never a search interface."""
    ep = T.episode(tmp_path)
    for admitted in ({"term": {"a": "b"}}, {"terms": {"a": ["b"]}},
                     {"range": {"@timestamp": {"lt": "2026-01-01"}}},
                     {"match": {"a": "b"}},
                     {"bool": {"must_not": [{"term": {"a": "b"}}]}},
                     # F6-MATCH-ALL: without this line the gate may admit exactly five clause
                     # types and a full-match exclusion never reaches the step-4 review that
                     # `d_full_match_exclusion_recorded_not_rejected` requires to RECORD it.
                     {"match_all": {}}):
        door = T.FakeDoor()
        _stage(ep, door=door, world=_world(ov=T.overlay(elastic=T.elastic_overlay(
            inject=[], exclude=admitted))))
        assert door.only("create_alias").payload["filter"] == admitted
    for refused in ({"more_like_this": {"like": "x"}}, {"pinned": {"ids": ["1"]}},
                    {"wrapper": {"query": "e30="}}):
        door = T.FakeDoor()
        with pytest.raises(_refused()) as bad:
            _stage(ep, door=door, world=_world(ov=T.overlay(elastic=T.elastic_overlay(
                inject=[], exclude=refused))))
        assert next(iter(refused)) in str(bad.value)
        assert door.connections == 0


def test_947_an_unparseable_exclusion_predicate_is_refused(tmp_path):
    """A predicate that is not a parseable query document at all — a bare string, a list, a
    mapping with no clause — is refused by name rather than passed to the cluster to interpret."""
    ep = T.episode(tmp_path)
    for junk in ("process.name:nc", ["term"], {}, {"term": "not-a-mapping"}):
        door = T.FakeDoor()
        with pytest.raises(_refused()):
            _stage(ep, door=door, world=_world(ov=T.overlay(elastic=T.elastic_overlay(
                inject=[], exclude=junk))))
        assert door.connections == 0


def test_947_a_world_with_a_null_exclusion_stages_injection_only(tmp_path):
    """A world whose exclusion is the null sentinel stages its injection only: the injection
    index is created and the alias carries no filter, rather than an empty filter that would
    remove nothing while reading as one."""
    ep = T.episode(tmp_path)
    door = T.FakeDoor()
    _stage(ep, door=door, world=_world(ov=T.overlay(elastic=T.elastic_overlay(
        inject=[{"_id": "i1"}], exclude=None))))
    assert door.only("create_alias").payload["filter"] is None
    assert door.only("create_index").name == INJECT


# ---------------------------------------------------------------------------------------
# §7 FORK-3 (auto) — the name algebra the config can break
# ---------------------------------------------------------------------------------------


def test_947_a_configured_pattern_without_a_trailing_wildcard_refuses_the_launcher(tmp_path):
    """A configured corpus pattern with no trailing wildcard refuses the launcher at startup:
    the namespace guard would accept the alias name derived from it and REFUSE the injection
    index name, so staging's own guard would refuse the index staging must create."""
    confinement = T.mod("scripts.adapters.confinement")
    view = confinement.world_view("logs-2026", TOKEN)
    assert confinement.is_world_view(view, ("logs-2026",), TOKEN)
    assert not confinement.is_world_view(f"{view}.inject", ("logs-2026",), TOKEN)
    with pytest.raises(_refused()) as bad:
        _staging().check_configured_patterns(("logs-2026", T.ALERTS_PATTERN))
    assert "logs-2026" in str(bad.value)


def test_947_a_bare_wildcard_configured_pattern_refuses_the_launcher(tmp_path):
    """A configured corpus pattern of a bare wildcard refuses the launcher at startup: it
    reduces to nothing an alias can be named by, so no Elastic world could ever be staged for
    this episode and the refusal belongs before the questioner is paid for."""
    confinement = T.mod("scripts.adapters.confinement")
    with pytest.raises(confinement.ViewNameError):
        confinement.world_view("*", TOKEN)
    with pytest.raises(_refused()) as bad:
        _staging().check_configured_patterns(("*", T.ALERTS_PATTERN))
    assert "*" in str(bad.value)


def test_947_two_overlay_keys_trimming_to_one_view_stem_refuse_the_episode(tmp_path):
    """Two overlay keys whose view stems collide refuse the episode: one alias cannot serve two
    declared corpora, and staging both would silently give a query for the narrow corpus the
    wide one's documents."""
    confinement = T.mod("scripts.adapters.confinement")
    assert confinement.world_view("logs-*", TOKEN) == confinement.world_view("logs-", TOKEN)
    ep = T.episode(tmp_path)
    door = T.FakeDoor()
    colliding = _world(ov=T.overlay(elastic={
        "logs-*": {"inject": [{"_id": "i1"}], "exclude": None},
        "logs-": {"inject": [{"_id": "i2"}], "exclude": None}}))
    with pytest.raises(_refused()) as bad:
        _stage(ep, door=door, world=colliding, patterns=("logs-*", "logs-"))
    assert "stem" in str(bad.value)
    assert door.connections == 0


def test_947_the_overlay_key_gate_and_the_staging_guard_call_one_predicate(tmp_path):
    """The overlay-key gate and the staging guard are ONE CALL, not two spellings that happen to
    agree: the gate's own source reaches `confinement._reach_ok`, and over a family of keys
    generated mechanically around every configured pattern the two answers are equal at every
    point. Six hand-picked values cannot tell one call from two that agree on six values, which
    is the whole reason the resolution asked for the call and not for the agreement."""
    import inspect

    confinement = T.mod("scripts.adapters.confinement")
    staging = _staging()
    assert "_reach_ok" in inspect.getsource(staging), (
        "the overlay-key gate spells its own reach check, so the twin gates can still diverge")
    candidates = ["*", "", "   ", "logs", "logs-", "logs-*extra", "logs-nope-*"]
    for pattern in T.CONFIGURED:
        head = pattern.rstrip("*")
        candidates += [pattern, pattern.upper(), pattern.rstrip("*"), f"  {pattern}  ",
                       head + "*", head + "x", head + "x-*", head + ".sub-*",
                       head[:-1] + "*", "wv-" + pattern, pattern + "*", pattern.rstrip("-*")]
    for pattern in candidates:
        admitted = staging.overlay_key_admitted(pattern, T.CONFIGURED)
        reached = any(confinement._reach_ok(pattern, p) or pattern == p for p in T.CONFIGURED)
        assert admitted == reached, f"{pattern!r}: gate {admitted}, guard {reached}"


# ---------------------------------------------------------------------------------------
# teardown and sweep (M9)
# ---------------------------------------------------------------------------------------


def test_947_teardown_deletes_exactly_the_recorded_names_newest_first(tmp_path):
    """Teardown deletes exactly the names the staging record holds, newest first, and nothing
    else on the cluster — including a duplicate row, which is visited twice and verified twice."""
    ep = T.episode(tmp_path)
    door = T.FakeDoor(existing=(VIEW, INJECT, "logs-000001", f"wv-{T.world_token('c')}-logs-"))
    _stage(ep, door=door)
    recorded = [r["name"] for r in T.staged_rows(ep)]
    _staging().teardown(ep, door=door)
    assert door.deleted() == list(reversed(recorded))
    assert "logs-000001" in door.names
    assert f"wv-{T.world_token('c')}-logs-" in door.names


def test_947_teardown_verifies_each_name_is_gone(tmp_path):
    """Teardown verifies each name is gone after deleting it, and a name that is still present
    is reported rather than assumed removed."""
    ep = T.episode(tmp_path)
    door = T.FakeDoor(existing=(VIEW, INJECT))
    _stage(ep, door=door)

    class Sticky(T.FakeDoor):
        def delete(self, name):
            self._gate("delete", name, {})

    sticky = Sticky(existing=(VIEW, INJECT))
    with pytest.raises(T.refusals()) as bad:
        _staging().teardown(ep, door=sticky)
    assert VIEW in str(bad.value) or INJECT in str(bad.value)
    assert [c.op for c in sticky.calls].count("exists") >= 1


def test_947_a_teardown_failure_is_recorded_in_the_review_and_not_swallowed(tmp_path):
    """A teardown failure is recorded in the review record, naming the names that were not
    verified gone, and is never swallowed into a clean exit."""
    ep = T.episode(tmp_path)
    door = T.FakeDoor(existing=(VIEW, INJECT))
    _stage(ep, door=door)
    failing = T.FakeDoor(existing=(VIEW, INJECT), fault=T.Fault(fail_on=(INJECT,)))
    with pytest.raises(T.refusals()):
        _staging().teardown(ep, door=failing, review_path=ep / "review.yaml")
    assert INJECT in json.dumps(T.review_doc(ep))


def test_947_next_launcher_start_sweeps_leftover_world_view_names(tmp_path):
    """The next launcher start sweeps every leftover name in this episode's own token namespace
    — the ones a killed launcher never tore down — and the cluster no longer holds them."""
    ep = T.episode(tmp_path)
    door = T.FakeDoor(existing=(VIEW, INJECT))
    _stage(ep, door=door)
    _staging().sweep(ep, episode_token=T.EPISODE_TOKEN, door=door)
    assert VIEW not in door.names
    assert INJECT not in door.names


def test_947_the_sweep_leaves_another_episodes_live_names_alone(tmp_path):
    """The sweep touches only names inside its own episode's token: another episode's live
    staged names are outside the glob and survive untouched."""
    ep = T.episode(tmp_path)
    other = "wv-20260101t000000z.other.case.n1.b-logs-"
    door = T.FakeDoor(existing=(VIEW, INJECT, other))
    _stage(ep, door=door)
    _staging().sweep(ep, episode_token=T.EPISODE_TOKEN, door=door)
    assert other in door.names
    assert other not in door.deleted()


def test_947_sweep_refuses_a_world_view_name_no_staging_record_names(tmp_path):
    """The sweep refuses when it finds a name inside its own token that the staging record does
    not name: that is a name this code did not write, and removing it would be guessing."""
    ep = T.episode(tmp_path)
    door = T.FakeDoor()
    _stage(ep, door=door)
    door.names.add(f"wv-{TOKEN}-unrecorded")
    with pytest.raises(T.refusals()) as bad:
        _staging().sweep(ep, episode_token=T.EPISODE_TOKEN, door=door)
    assert "unrecorded" in str(bad.value)
    assert f"wv-{TOKEN}-unrecorded" in door.names


def test_947_a_sweep_that_cannot_reach_the_cluster_refuses(tmp_path):
    """A sweep that cannot reach the cluster REFUSES rather than skipping: a silently skipped
    sweep leaves an earlier death's names live under a namespace this episode is about to
    reuse, which is the whole of the crash-recovery story."""
    ep = T.episode(tmp_path)
    sweep = _staging().sweep
    door = T.FakeDoor(fault=T.Fault(raise_after=0))
    with pytest.raises(T.refusals()):
        sweep(ep, episode_token=T.EPISODE_TOKEN, door=door)
    assert door.calls, "the sweep never reached for the cluster at all"


# ---------------------------------------------------------------------------------------
# the stager's reading half, and the production read path beside it
# ---------------------------------------------------------------------------------------


def test_947_redirect_retargets_only_a_declared_base_pattern(tmp_path):
    """The stager retargets only a pattern the world's overlay declares: a declared pattern is
    rewritten to that world's view, and the rewrite names the view derived from the declared
    key."""
    elastic = T.mod("learning.branch.estate.stagers.elastic")
    declared = T.mod("runtime.branch._family").parse_overlay(
        T.overlay(elastic=T.elastic_overlay(T.EVENTS_PATTERN, inject=[{"_id": "i"}])))
    out = elastic.redirect("query", {"index": T.EVENTS_PATTERN}, TOKEN, overlay=declared)
    assert out["index"] == VIEW


def test_947_an_undeclared_pattern_passes_through_and_is_recorded_passthrough(tmp_path):
    """A query naming a pattern the world's overlay did not declare reads the base unchanged and
    is recorded as a passthrough — including the per-call index override the shipped corpus
    uses, which names a narrower source than the configured one."""
    elastic = T.mod("learning.branch.estate.stagers.elastic")
    ledger = T.mod("learning.branch.ledger")
    declared = T.mod("runtime.branch._family").parse_overlay(
        T.overlay(elastic=T.elastic_overlay(T.EVENTS_PATTERN, inject=[{"_id": "i"}])))
    asked = {"index": "logs-zeek.connection-*"}
    out = elastic.redirect("query", dict(asked), TOKEN, overlay=declared)
    assert out["index"] == "logs-zeek.connection-*"

    # AND THE ROW SAYS SO. Asked of the applier, which is the frame that names the decision the
    # ledger writes — the earlier spelling asked a stager helper with no production caller, so
    # the recorded half of this test's own sentence was never exercised: every one of these
    # calls was in fact recorded `staged`, because the applier asked whether the VERB stages
    # rather than whether THIS CALL was moved.
    applier = T.mod("learning.branch.estate.applier").WorldApplier()
    world = T.mod("runtime.branch._family").World(
        world_id=TOKEN, role="B", story="s", axis="a",
        disposition_declared="malicious", label_basis="policy-rule", overlay=declared)
    payload = {"hits": []}
    assert applier.apply("elastic", "query", out, payload, world, None) == (
        ledger.PASSTHROUGH, payload)


def test_947_an_index_less_call_still_refuses_on_a_staged_world(tmp_path):
    """A `query`/`alerts` call that leaves `index` unset still REFUSES on a staged world, and the
    undeclared-pattern passthrough rule does not soften it: such a call addresses the run's own
    configured default, a frame with no context cannot resolve that default, and a view built on
    a guess would stage the world into an index nobody reads — a whole evidence class silently
    becoming unrewritten base reads with nothing reporting it. Fail-closed, as everywhere else in
    this design. The BASE world, which stages nothing, still passes the same call through."""
    elastic = T.mod("learning.branch.estate.stagers.elastic")
    declared = T.mod("runtime.branch._family").parse_overlay(
        T.overlay(elastic=T.elastic_overlay(T.EVENTS_PATTERN, inject=[{"_id": "i"}])))
    for verb in elastic.PARAM_INDEXED:
        with pytest.raises(T.refusals()) as bad:
            elastic.redirect(verb, {"size": 5}, TOKEN, overlay=declared)
        assert "index" in str(bad.value)
        assert elastic.redirect(verb, {"size": 5}, None, overlay=declared) == {"size": 5}


def test_947_an_ordinary_query_resolves_the_base_pattern_while_an_episode_is_staged(tmp_path):
    """An ordinary, unbranched query resolves the configured base pattern exactly as before
    while an episode's names are live on the cluster — on BOTH surfaces the adapter reaches the
    cluster through, the param-indexed one and the query-language one."""
    elastic_stager = T.mod("learning.branch.estate.stagers.elastic")
    assert elastic_stager.redirect("query", {"index": T.EVENTS_PATTERN}, None) == \
        {"index": T.EVENTS_PATTERN}
    body = {"query": f"FROM {T.EVENTS_PATTERN} | LIMIT 1"}
    assert elastic_stager.redirect("esql", dict(body), None) == body
