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

from defender._episode_handle import Episode
from defender.tests import _triplet_947 as T


def _family():
    return T.mod("runtime.branch._family")


def _load(doc):
    return _family().parse_family(doc)


def _refusal():
    return _family().FamilyError


def _no_preflight(*_args, **_kw) -> int:
    """`T.no_preflight`'s neutralised role preflight, taking the `branching=` keyword #1224's
    launcher passes."""
    return 0


# ---------------------------------------------------------------------------------------
# the document's shape
# ---------------------------------------------------------------------------------------


def test_947_family_schema_and_loader_live_in_runtime_branch():
    """The `Family` schema and its loader are importable from `runtime/branch/_family.py`,
    not from `learning/`, so the resumed run reads the manifest without importing learning."""
    fam = _family()
    assert fam.__name__ == "defender.runtime.branch._family"
    for name in ("Family", "World", "Fact", "parse_family", "load_family", "FamilyError"):
        assert hasattr(fam, name), f"_family.py declares no {name}"


def test_947_family_manifest_carries_every_declared_field(tmp_path):
    """A loaded family carries the launcher's derived half, the operator's instrument field
    and the questioner's authored half as one document: episode id, source run dir and id,
    branch message id, fences, T0, the continuation prompt, the served systems, the base story,
    the discriminator and the worlds — every field the data model declares, none omitted."""
    fam = _load(T.family_doc())
    for slot in ("episode_id", "source_run_dir", "source_run_id", "branch_message_id",
                 "fences_at", "as_of", "continuation_prompt", "served_systems", "base_story",
                 "discriminator", "worlds"):
        assert getattr(fam, slot) is not None, f"the manifest lost {slot}"
    assert fam.episode_id == T.EPISODE_ID
    assert len(fam.worlds) == 3


def test_947_world_entry_carries_every_declared_field():
    """Each world entry carries its short label, its role, its story, its axis, the declared
    disposition, the label basis and its facts — the seven fields the data model names."""
    fam = _load(T.family_doc())
    w = {x.world_id: x for x in fam.worlds}["b"]
    for slot in ("world_id", "role", "story", "axis", "disposition_declared",
                 "label_basis", "facts"):
        assert hasattr(w, slot), f"a World entry declares no {slot}"
    assert w.world_id == "b"
    assert w.label_basis == "policy-rule"
    assert [(f.fact_id, f.statement, f.entities) for f in w.facts] == [
        ("f1", "a second login to web-1 came from 10.0.0.9", ("web-1", "10.0.0.9"))]


def test_947_world_a_is_the_control_with_no_facts_and_null_axis():
    """World A is the control: its role is A, its facts are the explicit empty list and its
    axis is the null sentinel, and the loader admits that combination as a first-class world
    rather than refusing it as an unauthored one."""
    fam = _load(T.family_doc(worlds=[T.base_world(), T.world_doc("b")]))
    a = fam.worlds[0]
    assert a.role == "A"
    assert a.axis is None
    assert a.facts == ()


# ---------------------------------------------------------------------------------------
# what the loader refuses — the strict reading (§7 FORK-5)
# ---------------------------------------------------------------------------------------


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
    # `write_family` takes the `Episode` and no longer makes the dir (#1133 rev 2).
    with Episode.create(tmp_path / "ep") as episode:
        manifest = _family().write_family(episode, T.family_doc(base_story=payload))
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


def test_947_a_manifest_edited_after_its_digest_was_taken_is_refused(tmp_path):
    """A digest taken of the manifest is re-checkable against it: a manifest edited after the
    digest was taken refuses rather than passing as the document that was digested."""
    fam = _family()
    doc = T.family_doc()
    with Episode.open(T.episode(tmp_path)) as episode:
        fam.write_family(episode, doc)
        recorded = fam.manifest_digest(episode.view())
        fam.write_family(episode, T.family_doc(base_story="edited after the digest"))
        with pytest.raises(_refusal()) as bad:
            fam.check_manifest_digest(episode.view(), recorded)
    assert "digest" in str(bad.value)


# ---------------------------------------------------------------------------------------
# §7 FORK-4 (auto) — one identity gate, before anything is launched
# ---------------------------------------------------------------------------------------


def test_947_one_identity_gate_refuses_every_bad_world_identity_before_launch(tmp_path,
                                                                               monkeypatch):
    """ONE identity gate runs over the whole manifest BEFORE anything is launched: each label
    must be nameable, the labels must be distinct case-folded, none may be the reserved base
    ledger name, the roles must be distinct, and each composed world token must round-trip — and
    driven through the launcher, a family failing any of them is refused at the question-writer's
    step, with no sibling started, which is the ordering the fork's answer turns on."""
    fam = _family()
    bad_families = (
        ([T.base_world(), T.world_doc("B")], "b"),
        ([T.base_world(), T.world_doc("base")], "base"),
        ([T.base_world(), T.world_doc("b-1")], "b-1"),
        # TWO WORLDS, ONE LABEL: they would share a run dir, a ledger file and an oracle-side
        # store. Refused as a label collision both read directly and driven through the launcher.
        ([T.base_world(), T.world_doc("b"), T.world_doc("b")], "one label"),
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
    base, src = T.runs_base(tmp_path)
    for i, (worlds, _needle) in enumerate(bad_families):
        # One episodes root per arm: four launches sharing one would have the later three meet a
        # directory an earlier abort left behind rather than the identity gate.
        monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / f"episodes-root-{i}"))
        spawn = T.FakeSpawn()
        questioner = T.FakeAgent(T.family_doc(worlds=worlds), *worlds[1:])
        # The live-tree seam is injected to match the fixture source (#976 M2): without it the
        # anchor preflight refuses on the suite's own HEAD before the questioner is asked, and
        # the assertions below are satisfied by the wrong refusal.
        with pytest.raises(T.refusals()) as refused:
            T.mod("learning.branch.cli").main(
                [str(src), str(T.BRANCH_MESSAGE_ID), "--continuation-prompt", "go"],
                spawn=spawn, preflight=_no_preflight,
                questioner=questioner, live_tree=T.source_capture())
        assert questioner.calls > 0, "the launch was refused before the identity gate ran"
        assert "family could not be used" in str(refused.value), (
            f"refused by something other than the identity gate: {refused.value}")
        assert spawn.launches == [], "a sibling started before the identity gate ran"


def test_947_a_source_run_id_that_cannot_render_is_refused_by_the_gate_that_runs_first():
    """A source run whose id cannot render to a nameable episode token is refused, and refused
    EARLIER — by the id gate `episode_dir_for` runs before any token is derived — so the escape
    this test used to pin has no input left to serve.

    EDITED BY #1007 (F-R5), on a recorded human decision, and this is the one place a removed
    flag's own test changes hands. It used to assert that `--episode-token` made an unrenderable
    source branchable again. That escape is removed: it replaced the derived token outright, so
    two episode ids could share one namespace and one episode could stage under a namespace no
    reader re-derives, and `staging.sweep` — the only recovery for a killed attempt's live
    cluster aliases — was defeated by hand in both directions.

    THE WORKFLOW SURVIVES THROUGH ITS SUBSTITUTE, which is what this test now pins: every id
    that `episode_token_for` cannot render is ALREADY refused by `refuse_bad_episode_id`, which
    `episode_dir_for` calls first, so an operator meets one legible refusal before anything is
    spent rather than a source run that is permanently unbranchable. The pairing is re-probed
    against the real predicates on every run rather than recorded once. The positive control is
    a valid id, which both admit.
    """
    fam = _family()
    untokenable = ("FRESH CASE/2026-n59", "_lead-n5", ".hidden-n5", "-n5")
    for episode_id in untokenable:
        with pytest.raises(_refusal()):
            fam.episode_token_for(episode_id)
        with pytest.raises(_refusal()):
            fam.refuse_bad_episode_id(episode_id)
    fam.refuse_bad_episode_id(T.EPISODE_ID)
    assert fam.episode_token_for(T.EPISODE_ID) == T.EPISODE_TOKEN


# ---------------------------------------------------------------------------------------
# §7 NEW-1 (gate finding) — a fact's entity is bounded data, never document structure
# ---------------------------------------------------------------------------------------


def _entity_family(entity: str) -> dict:
    return T.family_doc(worlds=[T.base_world(), T.world_doc(
        "b", facts=[T.fact("f1", "the entity's owner changed", (entity,))])])


def test_947_a_fact_entity_outside_its_declared_domain_is_refused():
    """A fact's entity has a bounded, validated domain: an entity carrying a control character
    (the document-structural newline included), an empty one, or one over the length bound is
    refused naming `entities` rather than admitted as free text. (#1224: an entity is any
    printable name — it is data everywhere and never a path component — so path- or
    mapping-looking text is admitted as exactly the text it is.)"""
    fam = _family()
    bound = fam.ENTITY_MAX_LEN
    for bad_entity in ("web-1\n  owner: root", "", "x" * (bound + 1)):
        with pytest.raises(_refusal()) as bad:
            fam.parse_family(_entity_family(bad_entity))
        assert "entities" in str(bad.value)
    for data in ("../../etc", "a: b", "x" * bound):
        assert fam.parse_family(_entity_family(data)).worlds[1].facts[0].entities == (data,)


def test_947_write_family_renders_a_fact_entity_as_one_scalar(tmp_path):
    """An invented but admissible entity is rendered as ONE list item that reads back as exactly
    the authored text — the rendered document gains no sibling key or item the entity's own
    text introduced."""
    import yaml

    fam = _family()
    for entity in ("host.with.dots-01", "a: b", "- web-2"):
        with Episode.create(tmp_path / f"ep-{len(entity)}") as episode:
            manifest = fam.write_family(episode, _entity_family(entity))
        world = yaml.safe_load(manifest.read_text(encoding="utf-8"))["worlds"][1]
        assert world["facts"] == [{"fact_id": "f1", "statement": "the entity's owner changed",
                                   "entities": [entity]}]
