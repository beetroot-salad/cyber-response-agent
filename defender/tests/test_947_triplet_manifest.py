"""#947 — the family manifest is the contract (M2, O1).

`runtime/branch/_family.py` owns the schema and its loader because the RUNTIME reads it:
`run.py --resume` derives the episode dir, the source run and the world from this one document
and nothing else. Learning writes through the same loader, so the questioner's output is
validated into `Family` before any other step reads it, and a refusal names the offending field.

The whole module is RED against b8a63e66 by design: `runtime/branch/_family.py` does not exist
(X16). Each test imports it through `_triplet_947.mod`, so a missing target is one failure per
demand rather than one collection error swallowing the file.
"""
from __future__ import annotations

import pytest

from defender.tests import _triplet_947 as T


def _family():
    return T.mod("runtime.branch._family")


def _load(doc):
    return _family().parse_family(doc)


def _refusal():
    return _family().FamilyError


# ---------------------------------------------------------------------------------------
# the document's shape
# ---------------------------------------------------------------------------------------


def test_947_family_schema_and_loader_live_in_runtime_branch():
    """The `Family` schema and its loader are importable from `runtime/branch/_family.py`,
    not from `learning/`, so the resumed run reads the manifest without importing learning."""
    fam = _family()
    assert fam.__name__ == "defender.runtime.branch._family"
    for name in ("Family", "World", "Overlay", "parse_family", "load_family", "FamilyError"):
        assert hasattr(fam, name), f"_family.py declares no {name}"


def test_947_family_manifest_carries_every_declared_field(tmp_path):
    """A loaded family carries the launcher's derived half, the operator's instrument field
    and the questioner's authored half as one document: episode id, source run dir and id,
    branch message id, fences, T0, the continuation prompt, the base story, the discriminator
    and the worlds — every field the data model declares, none omitted."""
    fam = _load(T.family_doc())
    for slot in ("episode_id", "source_run_dir", "source_run_id", "branch_message_id",
                 "fences_at", "as_of", "continuation_prompt", "base_story", "discriminator",
                 "worlds"):
        assert getattr(fam, slot) is not None, f"the manifest lost {slot}"
    assert fam.episode_id == T.EPISODE_ID
    assert len(fam.worlds) == 3


def test_947_world_entry_carries_every_declared_field():
    """Each world entry carries its short label, its role, its story, its axis, the declared
    disposition, the label basis and its overlay — the seven fields the data model names."""
    fam = _load(T.family_doc())
    w = {x.world_id: x for x in fam.worlds}["b"]
    for slot in ("world_id", "role", "story", "axis", "disposition_declared",
                 "label_basis", "overlay"):
        assert hasattr(w, slot), f"a World entry declares no {slot}"
    assert w.world_id == "b"
    assert w.label_basis == "policy-rule"


def test_947_overlay_patches_and_elastic_keyed_as_declared():
    """The overlay's patch half is keyed system then entity then field, and its elastic half is
    keyed by the base pattern it stages, each entry carrying an injection list and an exclusion
    predicate."""
    doc = T.overlay(patches={"identity": {"web-1": {"owner": "platform"}}},
                    elastic=T.elastic_overlay(inject=[{"_id": "i1"}], exclude={"term": {"p": "nc"}}))
    ov = _family().parse_overlay(doc)
    assert ov.patches["identity"]["web-1"]["owner"] == "platform"
    entry = ov.elastic[T.EVENTS_PATTERN]
    assert entry.inject == [{"_id": "i1"}]
    assert entry.exclude == {"term": {"p": "nc"}}


def test_947_loader_normalises_empty_overlay_to_absent():
    """An empty overlay mapping, and an overlay whose halves are present but empty, both load
    as absent rather than as an authored difference — the falsy member is world A itself."""
    fam = _family()
    for raw in ({}, {"patches": {}, "elastic": {}}, {"patches": {}, "elastic": {"logs-*": {}}}):
        ov = fam.parse_overlay(raw)
        assert not ov.patches, f"{raw!r} did not normalise its patch half to absent"
        assert not ov.elastic, f"{raw!r} did not normalise its elastic half to absent"
        assert fam.touches_of(ov) == ()


def test_947_world_a_is_the_base_with_empty_overlay_and_null_axis():
    """World A is the base: its role is A, its overlay is empty and its axis is the null
    sentinel, and the loader admits that combination as a first-class world rather than
    refusing it as an unauthored one."""
    fam = _load(T.family_doc(worlds=[T.base_world(), T.world_doc("b")]))
    a = fam.worlds[0]
    assert a.role == "A"
    assert a.axis is None
    assert not a.overlay.patches
    assert not a.overlay.elastic


def test_947_touches_is_derived_from_overlay_never_stored():
    """The systems a world touches are computed from its overlay's keys on every read — the
    patch systems plus `elastic` when the elastic half is non-empty — and no stored field
    carries them."""
    fam = _family()
    ov = fam.parse_overlay(T.overlay(patches={"identity": {"web-1": {"owner": "p"}}},
                                     elastic=T.elastic_overlay(inject=[{"_id": "i"}])))
    assert set(fam.touches_of(ov)) == {"identity", "elastic"}
    world = _load(T.family_doc(worlds=[T.base_world(), T.world_doc("b", ov=T.overlay(
        patches={"cmdb": {"db-1": {"tier": "gold"}}}))])).worlds[1]
    assert set(fam.touches_of(world.overlay)) == {"cmdb"}
    assert not hasattr(world, "touches") or "touches" not in getattr(world, "__dataclass_fields__", {})


def test_947_validate_world_touches_takes_the_derived_set():
    """`World.touches` retires as an authored field: the estate's own validator takes the set
    derived from the overlay, and the workflow that used to declare systems on the command line
    still completes through the derived set instead."""
    registry = T.mod("learning.branch.estate.registry")
    driver = T.mod("runtime.driver")
    fam = _family()
    ov = fam.parse_overlay(T.overlay(patches={"identity": {"web-1": {"owner": "p"}}}))
    derived = fam.touches_of(ov)
    assert registry.validate_world_touches(derived, driver.GATHER_DEF.verb_grant) == derived
    with pytest.raises(registry.EstateError) as bad:
        registry.validate_world_touches(("nosuchsystem",), driver.GATHER_DEF.verb_grant)
    assert "nosuchsystem" in str(bad.value)


# ---------------------------------------------------------------------------------------
# what the loader refuses — the strict reading (§7 FORK-5)
# ---------------------------------------------------------------------------------------


def test_947_questioner_output_is_validated_into_family_before_any_reader():
    """The questioner's raw output is parsed into `Family` before any other step reads it: a
    document whose worlds are not a list never reaches staging, review or a sibling."""
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
    plus two by construction, and step 5 would have nothing to start."""
    with pytest.raises(_refusal()) as bad:
        _load(T.family_doc(worlds=[]))
    assert "worlds" in str(bad.value)


def test_947_a_patch_naming_a_system_outside_the_six_is_refused_by_field():
    """A patch keyed on a system outside the six state systems is refused at validation, the
    refusal naming the offending patches key."""
    with pytest.raises(_refusal()) as bad:
        _load(T.family_doc(worlds=[T.base_world(), T.world_doc(
            "b", ov=T.overlay(patches={"payroll": {"web-1": {"owner": "p"}}}))]))
    assert "payroll" in str(bad.value)


def test_947_overlay_names_only_configured_or_captured_patterns():
    """An overlay's elastic half may key only a configured corpus pattern or a pattern the
    capture's own FROM sources name; an invented pattern is refused, and the per-call index
    override the capture carries is admitted."""
    fam = _family()
    ok = fam.parse_family(T.family_doc(worlds=[T.base_world(), T.world_doc(
        "b", ov=T.overlay(elastic=T.elastic_overlay("logs-zeek.connection-*",
                                                    inject=[{"_id": "i"}])))]),
        captured_patterns=("logs-zeek.connection-*",))
    assert "logs-zeek.connection-*" in ok.worlds[1].overlay.elastic
    with pytest.raises(_refusal()) as bad:
        fam.parse_family(T.family_doc(worlds=[T.base_world(), T.world_doc(
            "b", ov=T.overlay(elastic=T.elastic_overlay("invented-*", inject=[{"_id": "i"}])))]),
            captured_patterns=("logs-zeek.connection-*",))
    assert "invented-*" in str(bad.value)


def test_947_the_null_replicate_arm_loads_and_is_not_run_by_default():
    """A world whose role is the null replicate arm loads, and the launcher's default selection
    does not start it — admitted by the data model, not run unless asked."""
    fam = _load(T.family_doc(worlds=[T.base_world(), T.world_doc("b"),
                                     T.world_doc("n", role=None)]))
    roles = [w.role for w in fam.worlds]
    assert None in roles
    assert [w.world_id for w in _family().runnable_worlds(fam)] == ["a", "b"]


def test_947_label_basis_defaults_to_policy_rule():
    """A world entry that omits its label basis loads as the policy-rule basis; the judgment
    basis is admitted only when the manifest says so."""
    fam = _family()
    doc = T.world_doc("b")
    doc.pop("label_basis")
    loaded = fam.parse_family(T.family_doc(worlds=[T.base_world(), doc]))
    assert loaded.worlds[1].label_basis == "policy-rule"
    judged = fam.parse_family(T.family_doc(
        worlds=[T.base_world(), T.world_doc("b", label_basis="judgment")]))
    assert judged.worlds[1].label_basis == "judgment"


def test_947_a_naive_or_non_utc_as_of_is_refused_as_a_fault():
    """A naive or non-UTC T0 is refused where the registry reads it, and the refusal is filed as
    a fault rather than as a corpus contradiction or an unreachable difference."""
    fam = _family()
    for bad_moment in ("2026-07-28T16:18:45", "2026-07-28T16:18:45+02:00"):
        with pytest.raises(_refusal()) as bad:
            fam.parse_family(T.family_doc(as_of=bad_moment))
        assert "as_of" in str(bad.value)
        assert not fam.is_contradiction(bad.value)


def test_947_a_model_authored_free_text_field_stays_one_scalar(tmp_path):
    """A model-authored free-text field carrying document-structural syntax is written back as a
    single opaque scalar: re-reading the manifest yields the same string and no sibling key the
    text tried to introduce."""
    import yaml

    payload = "a story\nepisode_id: hijacked\n- not a list item\n"
    ep = tmp_path / "ep"
    manifest = _family().write_family(ep, T.family_doc(base_story=payload))
    reread = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    assert reread["base_story"] == payload
    assert reread["episode_id"] == T.EPISODE_ID


# ---------------------------------------------------------------------------------------
# §7 FORK-5 (auto) — the strict loader, the manifest digest, the sentinel reading
# ---------------------------------------------------------------------------------------


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
    """An empty-string axis on a non-base world is refused by name: the house sentinel for
    `axis` is the null value, so an empty string is a real value and a world declaring one
    declares a difference it cannot name."""
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


def test_947_the_manifest_digest_is_recorded_in_the_review_and_rechecked_on_resume(tmp_path):
    """The manifest's digest is recorded in the review record and re-checked when a sibling
    resumes from it: a manifest edited between review and run refuses rather than running the
    edited document."""
    fam = _family()
    ep = T.episode(tmp_path)
    doc = T.family_doc()
    manifest = fam.write_family(ep, doc)
    recorded = fam.manifest_digest(manifest)
    fam.write_family(ep, T.family_doc(base_story="edited after review"))
    with pytest.raises(_refusal()) as bad:
        fam.check_manifest_digest(manifest, recorded)
    assert "digest" in str(bad.value)


# ---------------------------------------------------------------------------------------
# §7 FORK-4 (auto) — one identity gate, before anything is staged
# ---------------------------------------------------------------------------------------


def test_947_one_identity_gate_refuses_every_bad_world_identity_before_staging(tmp_path,
                                                                                monkeypatch):
    """ONE identity gate runs over the whole manifest BEFORE anything is staged: each label must
    be nameable, the labels must be distinct case-folded, none may be the reserved base ledger
    name, the roles must be distinct, and each composed world token must round-trip — and driven
    through the launcher, a family failing any of them leaves the cluster with no created name
    at all, which is the ordering the fork's answer turns on."""
    fam = _family()
    bad_families = (
        ([T.base_world(), T.world_doc("B")], "b"),
        ([T.base_world(), T.world_doc("base")], "base"),
        ([T.base_world(), T.world_doc("b-1")], "b-1"),
        # TWO WORLDS, ONE LABEL. As a document that is a role collision — both declare `B` —
        # which is what the direct leg reads. Driven through the launcher it is a LABEL
        # collision instead, because the seats assign `B` and `C` before the gate sees them, and
        # two worlds sharing one label share a run dir, a ledger file and a staged corpus. One
        # fixture, both halves of the identity gate, and neither half collapses into the
        # family the questioner authors from a clean plan.
        ([T.base_world(), T.world_doc("b"), T.world_doc("b")], "role"),
    )
    for worlds, needle in bad_families:
        with pytest.raises(_refusal()) as bad:
            fam.check_identities(fam.parse_family(T.family_doc(worlds=worlds)))
        assert needle in str(bad.value)

    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    base, src = T.runs_base(tmp_path)
    for i, (worlds, _needle) in enumerate(bad_families):
        # One episodes root per arm: four launches sharing one would have the later three meet a
        # directory an earlier abort left behind rather than the identity gate.
        monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / f"episodes-root-{i}"))
        door = T.FakeDoor()
        with pytest.raises(T.refusals()):
            T.mod("learning.branch.cli").main(
                [str(src), str(T.BRANCH_MESSAGE_ID), "--continuation-prompt", "go"],
                spawn=T.FakeSpawn(), door=door, adapters=T.FakeAdapters(),
                invoke=T.FakeAgent(*["same"] * 24),
                questioner=T.FakeAgent(T.family_doc(worlds=worlds), *worlds[1:]))
        assert door.created() == [], "a name was staged before the identity gate ran"


def test_947_a_source_run_id_that_cannot_render_is_given_an_escape():
    """A source run whose id cannot render to a nameable episode token is not permanently
    unbranchable: the launcher's escape names an operator-supplied token, and the same source
    then branches through it."""
    fam = _family()
    unrenderable = "FRESH CASE/2026"
    with pytest.raises(_refusal()):
        fam.episode_token_for(f"{unrenderable}-n59")
    assert fam.episode_token_for(f"{unrenderable}-n59", override="fresh.case.2026.n59") == \
        "fresh.case.2026.n59"


# ---------------------------------------------------------------------------------------
# §7 NEW-1 (gate finding) — `entity` is a rendered KEY, not a free-text value
# ---------------------------------------------------------------------------------------


def test_947_an_overlay_entity_outside_its_declared_domain_is_refused():
    """The patch table's entity key has a bounded, validated domain the way its system key does:
    an entity carrying document-structural or path syntax is refused by name rather than
    admitted as free text."""
    fam = _family()
    for bad_entity in ("web-1\n  owner: root", "../../etc", "a: b"):
        with pytest.raises(_refusal()) as bad:
            fam.parse_family(T.family_doc(worlds=[T.base_world(), T.world_doc(
                "b", ov=T.overlay(patches={"identity": {bad_entity: {"owner": "p"}}}))]))
        assert "entity" in str(bad.value)


def test_947_the_patch_table_renderer_escapes_an_invented_entity_as_a_key(tmp_path):
    """An invented but admissible entity is rendered as a KEY that reads back as exactly one
    key holding exactly the authored fields — the rendered document gains no sibling key the
    entity's own text introduced."""
    import yaml

    fam = _family()
    entity = "host.with.dots-01"
    ep = tmp_path / "ep"
    manifest = fam.write_family(ep, T.family_doc(worlds=[T.base_world(), T.world_doc(
        "b", ov=T.overlay(patches={"identity": {entity: {"owner": "platform"}}}))]))
    table = yaml.safe_load(manifest.read_text(encoding="utf-8"))["worlds"][1]["overlay"]["patches"]
    assert list(table["identity"]) == [entity]
    assert table["identity"][entity] == {"owner": "platform"}
