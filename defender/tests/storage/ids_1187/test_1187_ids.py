"""Run and episode identities are canonical UUIDs with no labels or composed meaning."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

from pathlib import Path

import pytest

from defender.tests.support.learning.branch import _triplet_947 as T947
from defender.tests.storage.ids_1187 import _spec1187 as S
from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H
from defender.tests.storage.tenant_1105_run_repository import _spec1105_pr2 as P

NON_CANONICAL = [pytest.param(text, id=repr(text)) for text in S.NON_CANONICAL_IDS]
# O1 / declared change 2: a minted id is a bare random UUID.

def test_1187_o1_mint_contract():
    import uuid

    from defender.run_repository import RunId

    minted = [RunId.mint() for _ in range(1000)]
    assert all(type(run_id) is RunId for run_id in minted)
    texts = [str(run_id) for run_id in minted]
    assert len(set(texts)) == 1000, "mint repeated an earlier id"
    for run_id, text in zip(minted, texts, strict=True):
        assert S.is_canonical_uuid(text), text
        assert uuid.UUID(text).version == 4, text
        assert RunId.parse(text) == run_id


def test_1187_o1_run_setup_names_an_unpinned_run_folder_by_a_bare_uuid(tmp_path, data_root):
    from defender import run_common

    t = S.tenant(data_root)
    alert = H.alert_file(tmp_path / "in", "ssh-brute-force.json")

    first = run_common.materialize_run(alert, None, tenant=t)
    second = run_common.materialize_run(alert, None, tenant=t)

    runs = Path(location_path(t.runs))
    assert Path(first.run_dir).parent == runs
    assert Path(second.run_dir).parent == runs
    for run in (first, second):
        name = Path(run.run_dir).name
        assert S.is_canonical_uuid(name), f"the minted run folder is named {name!r}"
        assert Path(run.run_dir).is_dir()
    assert Path(first.run_dir).name != Path(second.run_dir).name
# O2 / declared change 1: only canonical lowercase UUID text is an id.

def test_1187_o2_canonical_ids_pass_the_rules():
    from defender.records._run_id import episode_id_fault, run_id_fault

    for text in (S.SAMPLE_UUID, S.new_id()):
        assert run_id_fault(text) is None
        assert episode_id_fault(text) is None


@pytest.mark.parametrize("text", NON_CANONICAL)
@pytest.mark.parametrize("boundary", ["parse", "run_fault", "episode_fault", "run_id", "episode_id"])
def test_1187_o2_noncanonical_ids_are_refused_at_every_boundary(text, boundary):
    from defender.records._run_id import episode_id_fault, run_id_fault
    from defender.run_repository import RunAddress, RunId, RunRefused

    if boundary.endswith("_fault"):
        rule = run_id_fault if boundary == "run_fault" else episode_id_fault
        why = rule(text)
        assert isinstance(why, str), (rule.__name__, text, why)
        assert why, (rule.__name__, text, why)
    elif boundary == "parse":
        assert isinstance(S.raised(RunId.parse, text), RunRefused), text
    else:
        fields = {**_address_fields(), "episode_id": None, boundary: text}
        assert S.raised(RunAddress, **fields) is not None, (boundary, text)


def test_1187_o2_episode_id_rule_asks_for_no_room_for_a_label():
    from defender.records._run_id import episode_id_fault

    why = episode_id_fault("e" * 205)
    assert isinstance(why, str)
    assert "room" not in why, f"the episode id rule still counts room for a label: {why!r}"
    assert episode_id_fault(S.SAMPLE_UUID) is None


def _address_fields() -> dict[str, object]:
    from defender.tenancy import _tenant
    from defender.run_repository import RunId

    return {"tenant_id": _tenant.TenantId(H.T_ID), "run_id": RunId.parse(S.SAMPLE_UUID)}


def test_1187_o2_run_address_admits_canonical_uuid_run_and_episode_ids():
    from defender.run_repository import RunAddress

    ep = S.new_id()
    arm = RunAddress(tenant_id=_address_fields()["tenant_id"], run_id=S.new_id(), episode_id=ep)
    assert arm.episode_id == ep
    assert S.is_canonical_uuid(str(arm.run_id))
    natural = RunAddress(**_address_fields(), episode_id=None)
    assert natural.episode_id is None
    assert str(natural.run_id) == S.SAMPLE_UUID


def test_1187_o2_run_name_fault_still_tells_a_sidecar_from_a_run():
    from defender.run_repository import run_name_fault

    run_id = S.new_id()
    assert run_name_fault(run_id) is None, "a plain canonical UUID is a run"
    for suffix in S.SIDECAR_SUFFIXES:
        why = run_name_fault(run_id + suffix)
        assert why, f"{run_id + suffix!r} was admitted as a run name"
    staged = run_name_fault(f"{run_id}.run-end.json{H.STAGED_TAIL}")
    assert staged, "a staged sidecar was admitted as a run name"


# O3 / declared change 4: the family gate no longer judges the composed `<episode>-<label>`.

#: A world label that is valid by its own rule (lower-case letters and digits, 200 bytes) but
#: would make `<36-byte uuid>-<label>` 237 bytes: over the 206-byte bound the gate used to apply
#: to the composed name. Far below NAME_MAX, so no filesystem rule is the reason it is refused.
LONG_LABEL = "w" * 200


def _family_doc_for(episode_id: str, *labels: str) -> dict:
    """The committed family document builder, rewritten to this episode id and to a control world `a` plus one world per label."""
    worlds = [T947.base_world()] + [T947.world_doc(label) for label in labels]
    return T947.family_doc(episode_id=episode_id, worlds=worlds)


@pytest.mark.parametrize("label", ["b", LONG_LABEL, "w" * 220, "w" * 1000, "a-b"],
                         ids=["short", "200-bytes", "220-bytes", "1000-bytes", "invalid"])
def test_1187_o3_labels_follow_their_own_rule(label):
    from defender.runtime.branch import _family

    doc = _family_doc_for(S.new_id(), label)
    if label == "a-b":
        err = S.raised(_family.parse_family, doc)
        assert isinstance(err, _family.FamilyError), err
        assert label in S.message(err)
    else:
        family = _family.parse_family(doc)
        _family.check_identities(family)
        assert [w.label for w in family.worlds] == ["a", label]


def _attribute(obj: object, name: str) -> tuple[str, object]:
    """`("absent", None)`, `("raised", the exception)` or `("value", the value)` of `obj.<name>` — a property may be gone, refuse, or answer."""
    try:
        return "value", getattr(obj, name)
    except AttributeError:
        return "absent", None
    except Exception as exc:  # noqa: BLE001 — a property that refuses is an answer here
        return "raised", exc


def test_1187_o1_a_resumed_world_never_composes_its_arm_id(tmp_path):
    from defender.run_repository import RunId
    from defender.runtime.branch import _family

    episode_id = S.new_id()
    family = _family.parse_family(_family_doc_for(episode_id, "b"))
    roster = {family.world(label).world_id: RunId.parse(S.new_id()) for label in ("a", "b")}
    faults = []
    for label in ("a", "b"):
        composed = f"{episode_id}-{label}"
        handed = _family.resume_world_from(family, label, tmp_path, arm_ids=roster)
        kind, value = _attribute(handed, "run_id")
        if kind == "value" and str(value) != str(roster[family.world(label).world_id]):
            faults.append(f"{label}: handed the roster, run_id is {value!r}, not "
                          f"{str(roster[family.world(label).world_id])!r}")
        bare = _family.resume_world_from(family, label, tmp_path)
        kind, value = _attribute(bare, "run_id")
        if kind == "value" and str(value) == composed:
            faults.append(f"{label}: run_id still composes {composed!r}")
    assert faults == [], "ResumeWorld.run_id reads meaning into the episode id:\n  " + (
        "\n  ".join(faults))


def test_1187_o1_the_episode_layout_spells_no_sibling_run_dir():
    from defender.episodes import _episode_paths

    for owner in (_episode_paths.EpisodeLayout, _episode_paths.LAYOUT):
        assert not hasattr(owner, "sibling_run_dir"), (
            f"{owner!r} still spells the composed sibling run dir")
# O2: `run.py --run-id` refuses an old id and accepts a UUID.

def _run_py(tenant, alert: Path, run_id: str):
    """Drive run.main while recording spending seams without invoking a model or sandbox."""
    rec = P.SiblingRecorder()
    argv = [str(alert), "--tenant", tenant.id, "--run-id", run_id, "--no-learn"]
    status, refusal, stderr = P.drive_run_py(argv, rec)
    return status, refusal, stderr, rec


def test_1187_o2_run_py_runs_a_pinned_uuid(tmp_path, data_root):
    t = S.tenant(data_root)
    alert = H.alert_file(tmp_path / "in")
    run_id = S.new_id()

    status, refusal, stderr, rec = _run_py(t, alert, run_id)

    assert refusal is None, f"--run-id {run_id} was refused: {P.refusal_text(refusal)!r} {stderr!r}"
    assert status == 0, (status, stderr)
    assert rec.order.count("lifecycle") == 1, rec.order
    assert (Path(location_path(t.runs)) / run_id).is_dir()


@pytest.mark.parametrize("text", [pytest.param(t, id=repr(t)) for t in S.NON_CANONICAL_IDS
                                  if t.strip() == t and t])
def test_1187_o2_run_py_refuses_a_pinned_id_that_is_not_a_canonical_uuid(
        text, tmp_path, data_root):
    t = S.tenant(data_root)
    alert = H.alert_file(tmp_path / "in")

    status, refusal, stderr, rec = _run_py(t, alert, text)

    assert refusal is not None, f"--run-id {text!r} ran: status {status}, order {rec.order}"
    said = P.refusal_text(refusal)
    assert "run id" in said, f"not a run-id refusal: {said!r}"
    # Pre-flight runs before run setup (it spends nothing); the lifecycle, the page and the
    # curation enqueue are what a refused id must never reach.
    assert [step for step in rec.order if step != "preflight"] == [], (
        f"the run went on past a refused id: {rec.order}")
    assert not Path(location_path(t.runs)).exists() or sorted(Path(location_path(t.runs)).iterdir()) == [], (
        f"a refused id left something in the runs folder: {sorted(Path(location_path(t.runs)).iterdir())}")
