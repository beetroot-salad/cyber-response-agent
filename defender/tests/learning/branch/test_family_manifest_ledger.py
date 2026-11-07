"""#947: the family manifest is the contract.

#947: the ledger's two family tiers, and the file each of them lives in.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from defender.tests.support.shared._locations_1210 import location_path
from defender.records._episode_handle import Episode
from defender.tests.support.learning.branch import _triplet_947 as T
from defender._io import append_jsonl, read_jsonl_rows
from defender.records._episode_paths import BASE_FILENAME, SERVED_DIRNAME
from defender.learning.branch.ledger import (
    BASE,
    CAPTURED,
    PASSTHROUGH,
    STAGED,
    Ledger,
    LedgerError,
    ServedCall,
    payload_text,
)


def _family():
    return T.mod("records._family")


def _load(doc):
    return _family().parse_family(doc)


def _refusal():
    return _family().FamilyError


def _no_preflight(*_args, **_kw) -> int:
    """A neutralised role preflight taking whatever arguments the launcher passes."""
    return 0


# the document's shape


def test_947_world_a_is_the_control_with_no_facts_and_null_axis():
    fam = _load(T.family_doc(worlds=[T.base_world(), T.world_doc("b")]))
    a = fam.worlds[0]
    assert a.role == "A"
    assert a.axis is None
    assert a.facts == ()


# what the loader refuses — the strict reading


def test_947_questioner_output_is_validated_into_family_before_any_reader():
    """The questioner's raw output is parsed into `Family` before any other step reads it: a
    document whose worlds are not a list never reaches pre-flight or a sibling."""
    with pytest.raises(_refusal()):
        _load(T.family_doc(worlds={"a": {}}))


def test_947_family_validation_refusal_names_the_offending_field():
    """A validation refusal names the field it refused, not merely that the document is bad."""
    with pytest.raises(_refusal()) as bad:
        _load(T.family_doc(worlds=[T.base_world(),
                                   T.world_doc("b", label_basis="vibes")]))
    assert "label_basis" in str(bad.value)


def test_947_a_manifest_declaring_no_worlds_is_refused():
    """A manifest whose world list is empty is refused: the questioner's flow produces the base
    plus two by construction, and the family would have nothing to run."""
    with pytest.raises(_refusal()) as bad:
        _load(T.family_doc(worlds=[]))
    assert "worlds" in str(bad.value)


def test_947_the_null_replicate_arm_loads_and_is_not_run_by_default():
    """A world whose role is the null replicate arm loads, and the launcher's default selection
    does not start it — admitted by the data model, not run unless asked."""
    fam = _load(T.family_doc(worlds=[T.base_world(), T.world_doc("b"),
                                     T.world_doc("n", role=None)]))
    roles = [w.role for w in fam.worlds]
    assert None in roles
    assert [w.label for w in _family().runnable_worlds(fam)] == ["a", "b"]


def test_947_a_naive_or_non_utc_as_of_is_refused_as_a_fault():
    """A naive or non-UTC T0 is refused where the registry reads it, as a manifest fault."""
    fam = _family()
    for bad_moment in ("2026-07-28T16:18:45", "2026-07-28T16:18:45+02:00"):
        with pytest.raises(_refusal()) as bad:
            fam.parse_family(T.family_doc(as_of=bad_moment))
        assert "as_of" in str(bad.value)


def test_947_a_model_authored_free_text_field_stays_one_scalar(tmp_path):
    import yaml

    payload = "a story\nepisode_id: hijacked\n- not a list item\n"
    # `write_family` takes the `Episode`; it does not make the dir.
    with Episode.create(tmp_path / T.EPISODE_ID) as episode:
        manifest = _family().write_family(episode, T.family_doc(base_story=payload))
    reread = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    assert reread["base_story"] == payload
    assert reread["episode_id"] == T.EPISODE_ID


# the strict loader


def test_947_the_family_loader_refuses_an_unknown_top_level_field():
    """An unknown top-level field is refused rather than ignored: a manifest a human edited
    after review must not load as if the edit were part of the contract."""
    with pytest.raises(_refusal()) as bad:
        _load(T.family_doc(extra_instruction="run everything twice"))
    assert "extra_instruction" in str(bad.value)


def test_947_the_family_loader_enforces_world_cardinality_and_one_base():
    """The loader enforces the family's cardinality and that exactly one world is the base: a
    triplet with two base worlds, or with no base at all, is refused by name."""
    for worlds in ([T.base_world(), T.world_doc("b", role="A")],
                   [T.world_doc("b"), T.world_doc("c")]):
        with pytest.raises(_refusal()) as bad:
            _load(T.family_doc(worlds=worlds))
        assert "role" in str(bad.value) or "base" in str(bad.value)


def test_947_an_empty_string_axis_on_a_non_base_world_is_refused():
    with pytest.raises(_refusal()) as bad:
        _load(T.family_doc(worlds=[T.base_world(), T.world_doc("b", axis="")]))
    assert "axis" in str(bad.value)


def test_947_disposition_declared_is_gated_by_the_same_enum_the_report_is():
    """A world's declared disposition is gated by the shipped disposition vocabulary, the same
    membership gate the report is held to — not by a second, looser list."""
    vocab = T.mod("_vocab")
    with pytest.raises(_refusal()) as bad:
        _load(T.family_doc(worlds=[T.base_world(),
                                   T.world_doc("b", disposition_declared="probably-bad")]))
    assert "disposition_declared" in str(bad.value)
    ok = _load(T.family_doc(worlds=[T.base_world(), T.world_doc(
        "b", disposition_declared=sorted(vocab.DISPOSITION_ENUM)[0])]))
    assert ok.worlds[1].disposition_declared in vocab.DISPOSITION_ENUM


# one identity gate, before anything is launched


def test_947_one_identity_gate_refuses_every_bad_world_identity_before_launch(tmp_path,
                                                                               monkeypatch):
    """ONE identity gate runs over the whole manifest BEFORE anything is launched"""
    fam = _family()
    bad_families = (
        ([T.base_world(), T.world_doc("B")], "b"),
        ([T.base_world(), T.world_doc("base")], "base"),
        ([T.base_world(), T.world_doc("b-1")], "b-1"),
        # TWO WORLDS, ONE LABEL: the selector would be ambiguous. Refused both directly
        # and through the launcher before either world can start.
        ([T.base_world(), T.world_doc("b"), T.world_doc("b")], "label"),
    )
    # TWO WORLDS, ONE ROLE, distinct labels: the direct leg's role half. Driven through the
    # launcher the seats assign `B` and `C` before the gate sees them, so it has no launcher leg.
    role_collision = ([T.base_world(), T.world_doc("b"), T.world_doc("c")], "role")
    for worlds, needle in (*bad_families, role_collision):
        with pytest.raises(_refusal()) as bad:
            fam.check_identities(fam.parse_family(T.family_doc(worlds=worlds)))
        assert needle in str(bad.value)

    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    base, src = location_path(T.runs_base)(tmp_path, published=True)  # a branch launch pins a published tenant's commit
    for worlds, _needle in bad_families:
        spawn = T.FakeSpawn()
        questioner = T.FakeAgent(T.declaration(T.family_doc(worlds=worlds)), *[T.declaration(w) for w in worlds[1:]])
        with pytest.raises(T.refusals()) as refused:
            T.mod("cli.learning.branch").main(
                ["--tenant", src.parent.parent.name, src.name, str(T.BRANCH_MESSAGE_ID)],
                spawn=spawn, preflight=_no_preflight,
                questioner=questioner, live_tree=T.source_capture(),
                directory=T.launcher_directory(src.parent.parent.name))
        assert questioner.calls > 0, "the launch was refused before the identity gate ran"
        assert "family could not be used" in str(refused.value), (
            f"refused by something other than the identity gate: {refused.value}")
        assert spawn.launches == [], "a sibling started before the identity gate ran"


def test_947_a_source_run_id_that_cannot_render_is_refused_by_the_gate_that_runs_first():
    """`refuse_bad_episode_id` refuses an id that cannot render to a nameable episode token and
    admits the fixture's own."""
    fam = _family()
    untokenable = ("FRESH CASE/2026-n59", "_lead-n5", ".hidden-n5", "-n5")
    for episode_id in untokenable:
        with pytest.raises(_refusal()):
            fam.refuse_bad_episode_id(episode_id)
    fam.refuse_bad_episode_id(T.EPISODE_ID)
    assert fam.parse_family(T.family_doc()).episode_id == T.EPISODE_ID


# a fact's entity is bounded data, never document structure


def _entity_family(entity: str) -> dict:
    return T.family_doc(worlds=[T.base_world(), T.world_doc(
        "b", facts=[T.fact("f1", "the entity's owner changed", (entity,))])])


def test_947_a_fact_entity_outside_its_declared_domain_is_refused():
    """A fact's entity has a bounded, validated domain"""
    fam = _family()
    bound = fam.ENTITY_MAX_LEN
    for bad_entity in ("web-1\n  owner: root", "", "x" * (bound + 1)):
        with pytest.raises(_refusal()) as bad:
            fam.parse_family(_entity_family(bad_entity))
        assert "entities" in str(bad.value)
    for data in ("../../etc", "a: b", "x" * bound):
        assert fam.parse_family(_entity_family(data)).worlds[1].facts[0].entities == (data,)


def test_947_write_family_renders_a_fact_entity_as_one_scalar(tmp_path):
    import yaml

    fam = _family()
    for entity in ("host.with.dots-01", "a: b", "- web-2"):
        with Episode.create(tmp_path / str(len(entity)) / T.EPISODE_ID) as episode:
            manifest = fam.write_family(episode, _entity_family(entity))
        world = yaml.safe_load(manifest.read_text(encoding="utf-8"))["worlds"][1]
        assert world["facts"] == [{"fact_id": "f1", "statement": "the entity's owner changed",
                                   "entities": [entity]}]


@pytest.mark.parametrize("length", [220, 1000])
def test_world_labels_do_not_bound_artifact_paths(tmp_path, length):
    from defender.records._episode_paths import LAYOUT
    from uuid import UUID

    label = "w" * length
    authored = T.declaration(T.family_doc(worlds=[T.base_world(), T.world_doc(label)]))
    published, family = _family().accept_family(authored)
    wid = family.world(label).world_id
    assert str(UUID(wid)) == wid
    assert UUID(wid).version == 4
    assert "world_id" not in authored["worlds"][1], "acceptance mutated the declaration"
    with Episode.create(tmp_path / T.EPISODE_ID) as episode:
        _family().write_family(episode, published)
        episode.served_world(wid).append("{}\n")
        episode.world_record(wid).create("world: accepted\n")
        episode.world(wid).dir.ensure()
        episode.world(wid).draw(0).write("bucket: caught\n")
        paths = [LAYOUT.world(wid).dir / "report.md", LAYOUT.oracle_dir(wid) / "facts.jsonl"]
        for relative in paths:
            path = tmp_path / T.EPISODE_ID / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("artifact\n", encoding="utf-8")
        reloaded = _family().load_family(episode.view(), expected_episode_id=T.EPISODE_ID)
        assert reloaded.world(label).world_id == wid
        assert _family().label_for_world_id(published, wid) == label
        assert _family().world_id_for(published, label) == wid
        before = (tmp_path / T.EPISODE_ID / "family.yaml").read_bytes()
        replacement, reminted = _family().accept_family(authored)
        assert {world.world_id for world in family.worlds}.isdisjoint(
            world.world_id for world in reminted.worlds)
        with pytest.raises(FileExistsError):
            _family().write_family(episode, replacement)
        assert (tmp_path / T.EPISODE_ID / "family.yaml").read_bytes() == before
    written = list((tmp_path / T.EPISODE_ID).rglob("*"))
    assert len([path for path in written if path.is_file()]) == 6
    assert all(len(path.name) < 100 for path in written)
    assert not any(label in str(path) for path in written)


@pytest.mark.parametrize("fault", ["missing", "invalid", "duplicate", "episode_binding"])
def test_world_identity_faults_are_refused_before_publication(tmp_path, fault):
    doc = T.family_doc()
    if fault == "missing":
        del doc["worlds"][1]["world_id"]
    elif fault == "invalid":
        doc["worlds"][1]["world_id"] = "b"
    elif fault == "duplicate":
        doc["worlds"][1]["world_id"] = doc["worlds"][0]["world_id"]
    elif fault == "episode_binding":
        doc["episode_id"] = T.SOURCE_RUN_ID
    with Episode.create(tmp_path / T.EPISODE_ID) as episode:
        before = list((tmp_path / T.EPISODE_ID).iterdir())
        with pytest.raises(_refusal()):
            _family().write_family(episode, doc)
        assert list((tmp_path / T.EPISODE_ID).iterdir()) == before


def test_questioner_cannot_supply_host_world_identities():
    doc = T.family_doc()
    with pytest.raises(_refusal(), match="host-assigned"):
        _family().accept_family(doc)
    assert [world["world_id"] for world in doc["worlds"]] == [
        T.fixture_world_id(label) for label in T.WORLDS]


def test_world_uuid_lookups_preserve_the_manifest_label_binding():
    doc = T.family_doc()
    family = _load(doc)
    for world in family.worlds:
        assert _family().world_id_for(doc, world.label) == world.world_id
        assert _family().label_for_world_id(doc, world.world_id) == world.label
    for identity in ("b", T.fixture_world_id("foreign")):
        with pytest.raises(_refusal()):
            _family().label_for_world_id(doc, identity)
    with pytest.raises(_refusal()):
        family.world(family.world("b").world_id)


def captured(system: str, verb: str, params: dict, payload: dict) -> dict:
    """One primed row, built through the ledger's OWN row writer and canonicaliser."""
    return ServedCall(
        system=system, verb=verb, params=params, payload_text=payload_text(payload),
        source=CAPTURED, world_id=None,
    ).row()


def episode(tmp_path: Path, *, rows: list[dict] | None = None) -> Path:
    """An episode directory whose capture has been primed. Returns the episode root."""
    root = tmp_path / "episode"
    (root / SERVED_DIRNAME).mkdir(parents=True, exist_ok=True)
    base = base_file(root)
    base.touch()
    if rows:
        append_jsonl(base, rows)
    return root


def base_file(root: Path) -> Path:
    """The episode's primed capture, spelled through the ledger's own constants."""
    return root / SERVED_DIRNAME / BASE_FILENAME


# 1. the vocabulary


@pytest.mark.parametrize("world_id", [None, T.fixture_world_id('w1')])
def test_the_ledger_refuses_a_captured_row_at_its_own_door(tmp_path, world_id):
    """`record` refuses `captured` outright, whichever tier the row claims."""
    root = episode(tmp_path)
    with Episode.open(root) as ep:
        ledger = Ledger.for_world(ep, T.fixture_world_id('w1'))

        with pytest.raises(LedgerError, match=CAPTURED):
            ledger.record(ServedCall(
                system="cmdb", verb="get-host", params={"host": "canary-1"},
                payload_text='{"owner": "estate"}', source=CAPTURED, world_id=world_id))

        assert read_jsonl_rows(root / SERVED_DIRNAME / f"{T.fixture_world_id('w1')}.jsonl") == []


# 2. the primed base is a precondition, not a parameter

def test_a_ledger_without_a_primed_base_does_not_construct(tmp_path):
    """`base_path` is REQUIRED"""
    root = episode(tmp_path)

    with pytest.raises(ValidationError, match="base_path"):
        Ledger(root / SERVED_DIRNAME / f"{T.fixture_world_id('w1')}.jsonl")


@pytest.mark.parametrize("shape", ["absent", "directory"])
def test_a_base_path_that_is_not_a_file_is_refused_at_construction(tmp_path, shape):
    """`for_world` over an episode never primed (no `served/base.jsonl`), or with a directory in
    its place, is a `LedgerError`."""
    root = tmp_path / "episode"
    (root / SERVED_DIRNAME).mkdir(parents=True)
    base = base_file(root)
    if shape == "directory":
        base.mkdir()

    with Episode.open(root) as ep, pytest.raises(LedgerError):
        Ledger.for_world(ep, T.fixture_world_id('w1'))


def test_the_primed_capture_is_never_written_to(tmp_path):
    """A world's rows go to the world's own file"""
    root = episode(tmp_path, rows=[captured("cmdb", "get-host", {"host": "canary-1"},
                                            {"owner": "estate"})])
    before = base_file(root).read_bytes()
    with Episode.open(root) as ep:
        ledger = Ledger.for_world(ep, T.fixture_world_id('w1'))

        ledger.record(ServedCall(
            system="cmdb", verb="list-hosts", params={}, payload_text='{"hosts": []}',
            source=BASE, world_id=None))
        ledger.record(ServedCall(
            system="cmdb", verb="list-hosts", params={}, payload_text='{"hosts": []}',
            source=PASSTHROUGH, world_id=T.fixture_world_id('w1')))

        assert base_file(root).read_bytes() == before, "the run appended to the primed capture"
        assert len(read_jsonl_rows(ledger.path)) == 2


# 3. what `base_payload` reads

def test_a_primed_key_is_answered_without_the_world_ever_asking(tmp_path):
    """A key the capture holds resolves out of `base.jsonl` — the world's own file is empty."""
    root = episode(tmp_path, rows=[captured("cmdb", "get-host", {"host": "canary-1"},
                                            {"owner": "estate"})])
    with Episode.open(root) as ep:
        ledger = Ledger.for_world(ep, T.fixture_world_id('w1'))

        hit = ledger.base_payload("cmdb", "get-host", {"host": "canary-1"})

        assert hit is not None, "the primed capture answered nothing for a key it holds"
        assert json.loads(hit) == {"owner": "estate"}
        assert read_jsonl_rows(ledger.path) == [], (
            "the world recorded a row for a key it never had to ask — a replay is not a serve")


def test_a_key_spelled_in_another_order_is_the_same_primed_key(tmp_path):
    """The capture is keyed through `request_key`, so param order does not split one memo in two."""
    root = episode(tmp_path, rows=[captured("elastic", "query",
                                            {"native_query": "x", "limit": 5}, {"hits": []})])
    with Episode.open(root) as ep:
        ledger = Ledger.for_world(ep, T.fixture_world_id('w1'))

        assert ledger.base_payload("elastic", "query", {"limit": 5, "native_query": "x"}) is not None


def test_one_siblings_live_read_is_not_served_to_another(tmp_path):
    """A live read recorded as `base` answers its own world on the next ask; World B does not read
    World A's own rows — only the shared capture crosses between them."""
    root = episode(tmp_path)
    with Episode.open(root) as ep:
        a = Ledger.for_world(ep, T.fixture_world_id('a'))
        b = Ledger.for_world(ep, T.fixture_world_id('b'))

        a.record(ServedCall(
            system="cmdb", verb="get-host", params={"host": "new-9"},
            payload_text='{"owner": "read-by-a"}', source=BASE, world_id=None))

        assert a.base_payload("cmdb", "get-host", {"host": "new-9"}) == '{"owner": "read-by-a"}'
        assert b.base_payload("cmdb", "get-host", {"host": "new-9"}) is None, (
            "world b was served world a's own live read as though it were the family's capture")


def test_the_capture_outranks_a_live_row_for_the_same_key(tmp_path):
    """A key held by BOTH the capture and the world's own file resolves to the CAPTURE."""
    root = episode(tmp_path, rows=[captured("cmdb", "get-host", {"host": "canary-1"},
                                            {"owner": "captured"})])
    with Episode.open(root) as ep:
        ledger = Ledger.for_world(ep, T.fixture_world_id('w1'))
        append_jsonl(ledger.path, [ServedCall(
            system="cmdb", verb="get-host", params={"host": "canary-1"},
            payload_text='{"owner": "live"}', source=BASE, world_id=None).row()])

        reopened = Ledger.for_world(ep, T.fixture_world_id('w1'))

        assert json.loads(reopened.base_payload("cmdb", "get-host", {"host": "canary-1"})) == {
            "owner": "captured"}


def test_a_failed_write_leaves_no_memo_behind_it(tmp_path):
    """A `record` whose append FAILS must not leave the payload live in memory."""
    root = episode(tmp_path)
    with Episode.open(root) as ep:
        ledger = Ledger.for_world(ep, T.fixture_world_id('w1'))
        ledger.path.mkdir(parents=True)

        with pytest.raises(OSError, match="non-plain"):
            ledger.record(ServedCall(
                system="cmdb", verb="get-host", params={"host": "canary-1"},
                payload_text='{"owner": "never landed"}', source=BASE, world_id=None))

        assert ledger.base_payload("cmdb", "get-host", {"host": "canary-1"}) is None, (
            "the payload is memoized with no ledger row behind it")


def test_two_staged_calls_for_one_question_pair_on_the_asked_form(tmp_path):
    """`correlation_key` is computed from `asked_params`, so two worlds' staged rows PAIR."""
    asked = {"query": "FROM logs-system.auth-*"}
    rows = [
        ServedCall(system="elastic", verb="esql", params={"query": f"FROM wv-{w}-logs-system.auth-"},
                   payload_text="{}", source=STAGED, world_id=w, asked_params=asked)
        for w in (T.fixture_world_id('a'), T.fixture_world_id('b'))
    ]

    assert rows[0].correlation_key == rows[1].correlation_key, (
        "two worlds asked one question and their rows do not pair — ΔO over this system is "
        "empty rather than measured")
    assert rows[0].key != rows[1].key, (
        "the memo keys collapsed too, so each world would replay the other's staged corpus")


def test_a_torn_base_row_is_not_served_as_an_answer(tmp_path):
    """A base row whose `payload_text` is present, non-empty and NOT JSON is skipped."""
    root = episode(tmp_path, rows=[{
        "system": "cmdb", "verb": "get-host", "params": {"host": "canary-1"},
        "payload_text": '{"owner": "est', "source": CAPTURED, "world_id": None,
    }])
    with Episode.open(root) as ep:
        ledger = Ledger.for_world(ep, T.fixture_world_id('w1'))

        assert ledger.base_payload("cmdb", "get-host", {"host": "canary-1"}) is None


def test_a_world_owned_row_never_answers_for_the_family_even_when_it_is_first(tmp_path):
    """A world's OWN row is not the family's answer, whatever order the file happens to hold."""
    root = episode(tmp_path)
    path = root / SERVED_DIRNAME / f"{T.fixture_world_id('w1')}.jsonl"
    call = dict(system="cmdb", verb="get-host", params={"host": "canary-1"})
    append_jsonl(path, [
        ServedCall(payload_text='{"owner": "world a made this"}', source="patched",
                   world_id=T.fixture_world_id('w1'), **call).row(),
        ServedCall(payload_text='{"owner": "estate"}', source=BASE, world_id=None, **call).row(),
    ])

    with Episode.open(root) as ep:
        ledger = Ledger.for_world(ep, T.fixture_world_id('w1'))

        assert json.loads(ledger.base_payload("cmdb", "get-host", {"host": "canary-1"})) == {
            "owner": "estate"}


def test_a_duplicate_inside_one_file_resolves_to_the_first_row(tmp_path):
    """Two rows for one key resolve to the FIRST, in memory and on a rebuild alike."""
    root = episode(tmp_path)
    with Episode.open(root) as ep:
        ledger = Ledger.for_world(ep, T.fixture_world_id('w1'))
        call = dict(system="cmdb", verb="get-host", params={"host": "canary-1"},
                    source=BASE, world_id=None)

        ledger.record(ServedCall(payload_text='{"owner": "first"}', **call))
        ledger.record(ServedCall(payload_text='{"owner": "second"}', **call))

        assert ledger.base_payload("cmdb", "get-host", {"host": "canary-1"}) \
            == Ledger.for_world(ep, T.fixture_world_id('w1')).base_payload(
                "cmdb", "get-host", {"host": "canary-1"}) \
            == '{"owner": "first"}'


# 4. `for_world`: one file per world, under the episode's own capture

def test_for_world_opens_this_worlds_file_beside_the_shared_capture(tmp_path):
    """`for_world` is the naming rule"""
    root = episode(tmp_path, rows=[captured("cmdb", "get-host", {"host": "canary-1"},
                                            {"owner": "estate"})])

    with Episode.open(root) as ep:
        ledger = Ledger.for_world(ep, T.fixture_world_id('w1'))

        assert ledger.path == root / SERVED_DIRNAME / f"{T.fixture_world_id('w1')}.jsonl"
        assert ledger.base_payload("cmdb", "get-host", {"host": "canary-1"}) is not None
        ledger.record(ServedCall(
            system="cmdb", verb="get-host", params={"host": "canary-1"},
            payload_text='{"owner": "estate"}', source=PASSTHROUGH, world_id=T.fixture_world_id('w1')))
        assert [r["world_id"] for r in read_jsonl_rows(root / SERVED_DIRNAME / f"{T.fixture_world_id('w1')}.jsonl")] == [T.fixture_world_id('w1')]


@pytest.mark.parametrize("world_id", ["", ".", "..", "a/b", "../base", "sub/w1", "w1/"])
def test_for_world_refuses_a_world_id_that_is_not_a_filename(tmp_path, world_id):
    """A world id that is not a single filename component is refused, not sanitized."""
    root = episode(tmp_path)

    with Episode.open(root) as ep, pytest.raises(LedgerError):
        Ledger.for_world(ep, world_id)
