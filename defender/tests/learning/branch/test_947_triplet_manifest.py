"""#947 — the family manifest is the contract (M2, O1)."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import pytest

from defender.records._episode_handle import Episode
from defender.tests.support.learning.branch import _triplet_947 as T


def _family():
    return T.mod("records._family")


def _load(doc):
    return _family().parse_family(doc)


def _refusal():
    return _family().FamilyError


def _no_preflight(*_args, **_kw) -> int:
    """`T.no_preflight`'s neutralised role preflight, taking the `branching=` keyword #1224's
    launcher passes."""
    return 0


# the document's shape


def test_947_world_a_is_the_control_with_no_facts_and_null_axis():
    fam = _load(T.family_doc(worlds=[T.base_world(), T.world_doc("b")]))
    a = fam.worlds[0]
    assert a.role == "A"
    assert a.axis is None
    assert a.facts == ()


# what the loader refuses — the strict reading (§7 FORK-5)


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
    # `write_family` takes the `Episode` and no longer makes the dir (#1133 rev 2).
    with Episode.create(tmp_path / T.EPISODE_ID) as episode:
        manifest = _family().write_family(episode, T.family_doc(base_story=payload))
    reread = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    assert reread["base_story"] == payload
    assert reread["episode_id"] == T.EPISODE_ID


# §7 FORK-5 (auto) — the strict loader, the manifest digest, the sentinel reading


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


# §7 FORK-4 (auto) — one identity gate, before anything is launched


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
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    base, src = location_path(T.runs_base)(tmp_path, published=True)  # #1108 P4: a branch launch needs a published tenant (flow 7 pins its commit)
    for i, (worlds, _needle) in enumerate(bad_families):
        # One episodes root per arm: four launches sharing one would have the later three meet a
        # directory an earlier abort left behind rather than the identity gate.
        monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / f"episodes-root-{i}"))
        spawn = T.FakeSpawn()
        questioner = T.FakeAgent(T.declaration(T.family_doc(worlds=worlds)), *[T.declaration(w) for w in worlds[1:]])
        with pytest.raises(T.refusals()) as refused:
            T.mod("cli.learning.branch").main(
                ["--tenant", src.parent.parent.name, src.name, str(T.BRANCH_MESSAGE_ID),
                 *T.retired_continuation_argv()],
                spawn=spawn, preflight=_no_preflight,
                questioner=questioner, live_tree=T.source_capture())
        assert questioner.calls > 0, "the launch was refused before the identity gate ran"
        assert "family could not be used" in str(refused.value), (
            f"refused by something other than the identity gate: {refused.value}")
        assert spawn.launches == [], "a sibling started before the identity gate ran"


def test_947_a_source_run_id_that_cannot_render_is_refused_by_the_gate_that_runs_first():
    """A source run whose id cannot render to a nameable episode token is refused, and refused EARLIER — by the id gate `episode_dir_for` runs before any..."""
    fam = _family()
    untokenable = ("FRESH CASE/2026-n59", "_lead-n5", ".hidden-n5", "-n5")
    for episode_id in untokenable:
        with pytest.raises(_refusal()):
            fam.refuse_bad_episode_id(episode_id)
    fam.refuse_bad_episode_id(T.EPISODE_ID)
    assert fam.parse_family(T.family_doc()).episode_id == T.EPISODE_ID


# §7 NEW-1 (gate finding) — a fact's entity is bounded data, never document structure


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
