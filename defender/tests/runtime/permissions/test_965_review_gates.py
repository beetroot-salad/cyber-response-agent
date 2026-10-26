"""The two gates and the two typed boundaries that came out of the #965 review."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from defender.records._run_id import is_case_stable_id, is_valid_run_id
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.support.shared.contracts._by_path import load_lint_gate

READ_GATE = load_lint_gate("lint_tree_read_follows_link")
FIELDS_GATE = load_lint_gate("lint_dataclass_fields")

REPO_ROOT = Path(__file__).resolve().parents[4]
LINT_DIR = REPO_ROOT / "tooling" / "lint"


def _empty_baseline(tmp_path: Path) -> Path:
    """A baseline with no entries, so a run against a fixture reports what it FOUND rather
    than what the repo has already accepted."""
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps({"entries": {}}), encoding="utf-8")
    return path


def _scope(tmp_path: Path, files: dict[str, str]) -> Path:
    scope = tmp_path / "scope"
    for rel, body in files.items():
        target = scope / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
    return scope


def _run(gate, tmp_path: Path, files: dict[str, str]) -> int:
    return gate.main(
        [], scope=_scope(tmp_path, files), baseline_path=_empty_baseline(tmp_path),
    )


# lint_tree_read_follows_link

def test_a_link_following_admit_check_in_a_tree_reader_is_refused(tmp_path: Path) -> None:
    assert _run(READ_GATE, tmp_path, {"run_common.py": (
        "from pathlib import Path\n"
        "def go(p: Path) -> bool:\n"
        "    return p.is_file()\n"
    )}) == 1


# lint_dataclass_fields

def test_the_raw_field_mapping_is_refused(tmp_path: Path) -> None:
    """It also holds ClassVar/InitVar pseudo-fields, which the generated `__init__` does not
    accept — so splatting it into `replace()` raises from a line that reads as total."""
    assert _run(FIELDS_GATE, tmp_path, {"m.py": (
        "def names(x):\n"
        "    return list(type(x).__dataclass_fields__)\n"
    )}) == 1


# the case-stable id rule

@pytest.mark.parametrize("run_id", ["base", "w1", "2026-05-25t15.30.45z-alert"])
def test_an_already_folded_id_is_case_stable(run_id: str) -> None:
    assert is_case_stable_id(run_id)


@pytest.mark.parametrize("run_id", ["Base", "W1", "wA"])
def test_an_id_carrying_upper_case_is_not(run_id: str) -> None:
    assert is_valid_run_id(run_id)
    assert not is_case_stable_id(run_id)


def test_a_world_id_carrying_upper_case_is_refused_at_the_mint() -> None:
    """At the MINT, where every id rule belongs"""
    from defender.runtime.branch import _family

    doc = {
        "label": "Alpha", "world_id": T.fixture_world_id("alpha"),
        "role": "B", "story": "s", "axis": "an axis",
        "disposition_declared": "malicious", "label_basis": "policy-rule",
        "facts": [{"fact_id": "f1", "statement": "web-1's owner is the platform team",
                   "entities": ["web-1"]}],
    }
    def family(world: dict) -> dict:
        # #1255 (D1, P4): `T.family_doc` writes the continuation prompt and the fence count only
        # while `Family` still declares them, so this stays about the identity gate on both sides.
        return T.family_doc(
            episode_id="ep1", source_run_dir="/runs/src", source_run_id="src",
            branch_message_id=1, as_of="2026-07-28T16:18:45Z",
            base_story="b", served_systems=["elastic"], discriminator={"predicate": "p"},
            worlds=[T.base_world(), world])

    with pytest.raises(_family.FamilyError) as caught:
        _family.check_identities(_family.parse_family(family(doc)))
    # #1224: the case rule is now the world-token alphabet's own (`world_label_fault`), whose
    # words name the case it admits — and `Alpha` differs from an admitted label only by case.
    assert "'Alpha' is outside the world-label alphabet (lower-case" in str(caught.value)
    # The control: the same label lower-cased passes the same gate.
    _family.check_identities(_family.parse_family(family({**doc, "label": "alpha"})))


def test_an_episode_id_carrying_upper_case_is_refused() -> None:
    """The same rule, because the two are joined into one run id and an episode id names the one directory holding the family's capture."""
    from defender.records._episode_handle import EpisodeRefused, refuse_bad_episode_id

    with pytest.raises(EpisodeRefused):
        refuse_bad_episode_id("Ep1")


# the outbound-body type

def test_the_wire_takes_only_a_body_that_went_past_the_clock() -> None:
    import inspect

    from defender.integrations import elastic_adapter as ea

    assert "body: OutboundBody | None" in inspect.getsource(ea._http_json)
    for mint in (ea._search_body, ea._esql_body):
        # The module is `from __future__ import annotations`, so signatures carry the NAME.
        assert inspect.signature(mint).return_annotation == "OutboundBody"
        first = next(iter(inspect.signature(mint).parameters))
        assert first == "ctx", f"{mint.__name__} must take the ctx that carries the clock"


def test_the_esql_mint_carries_the_bound_and_the_payload_does_not() -> None:
    """The split the verb's own comment argues for: the bound rides the wire, the record keeps
    what the model asked. Pinned together because they are one decision."""
    from defender.integrations import elastic_adapter as ea

    class _Ctx:
        as_of = None

    asked = "FROM logs-* | LIMIT 5"
    assert ea._esql_body(_Ctx(), asked).payload == {"query": asked}
    assert ea.esql_payload(asked, {"values": [], "columns": []})["query"] == asked
