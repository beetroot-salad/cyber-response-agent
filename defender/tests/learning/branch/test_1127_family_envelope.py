"""YAML aliases are refused at load anywhere in the family manifest and in model replies."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

from defender import _yaml
from defender.episodes._episode_handle import Episode
from defender.runtime.branch._family import FamilyError, load_family, parse_family, write_family
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.shared.filesystem.test_1127_params_nesting_limit import raised

_PLACEHOLDER = "__WORLD_B_FACTS__"

BOMB_TIMEOUT = 30
BOMB_LOAD_SECONDS = 2.0


def spliced(doc: dict, splices: dict[str, str]) -> str:
    """`doc` as text, each placeholder string in it replaced by YAML text. JSON is YAML flow
    style, so every field not spliced is the document's own; the splices are where the YAML
    that JSON cannot spell (anchors, aliases) goes. Placeholders are spliced in document order,
    so an anchor placed earlier than its alias stays earlier."""
    text = json.dumps(doc)
    for placeholder, yaml_text in splices.items():
        assert text.count(json.dumps(placeholder)) == 1, f"placeholder {placeholder} not placed"
        text = text.replace(json.dumps(placeholder), yaml_text)
    return text


def _world_b(doc: dict) -> dict:
    world = doc["worlds"][1]
    assert world["label"] == "b"
    return world


def family_text(facts_yaml: str) -> str:
    """The shared fixture's family document as text, world b's `facts` replaced by
    `facts_yaml` spliced in as YAML text."""
    doc = T.family_doc()
    _world_b(doc)["facts"] = _PLACEHOLDER
    return spliced(doc, {_PLACEHOLDER: facts_yaml})


def load(path: Path):
    """`load_family` over the episode whose manifest is at `path` (`<episode>/family.yaml`).
    #1187 (R5, declared change 10): the loader is told the episode's id — its folder's name —
    and refuses a manifest naming another (`expected_episode_id=`, required)."""
    with Episode.open(path.parent) as episode:
        return load_family(episode.view(), expected_episode_id=path.parent.name)


def write_manifest(tmp_path: Path, text: str) -> Path:
    """The manifest `text` as an episode's `family.yaml`, the episode folder named by the id
    the shared fixture's document carries (`T.EPISODE_ID`), so the #1187 R5 id check passes
    and only the envelope under test can refuse."""
    path = tmp_path / T.EPISODE_ID / "family.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def manifest(tmp_path: Path, facts_yaml: str) -> Path:
    """A real `family.yaml` whose world b's facts are `facts_yaml`."""
    return write_manifest(tmp_path, family_text(facts_yaml))


def _anchors_and_aliases(text: str) -> list[str]:
    """Every anchor (`&name`) and alias (`*name`) in `text`, read off the parser's events."""
    found = []
    for event in yaml.parse(text, Loader=yaml.SafeLoader):
        if isinstance(event, yaml.AliasEvent):
            found.append(f"*{event.anchor}")
        elif getattr(event, "anchor", None):
            found.append(f"&{event.anchor}")
    return found


def _has_alias(text: str) -> bool:
    return any(mark.startswith("*") for mark in _anchors_and_aliases(text))


def assert_refused_at_load(err: Exception | None, what: str) -> None:
    """C's refusal: a `FamilyError` whose cause is the loader's `YAMLError` — refused by the
    YAML loader, not later by a walk of an already-built value."""
    assert err is not None, f"{what} loaded — nothing refused it"
    assert isinstance(err, FamilyError), \
        f"{what} was refused with {type(err).__name__}, not FamilyError: {str(err)[:200]}"
    assert isinstance(err.__cause__, yaml.YAMLError), (
        f"{what} was refused, but not by the YAML loader (cause: "
        f"{type(err.__cause__).__name__}): {str(err)[:200]}")


def test_a_manifest_too_deep_for_the_yaml_parser_is_still_a_family_error(tmp_path):
    """Whatever loader `_read_document` uses, text nested past what the YAML parser's own
    recursion can compose is a `FamilyError`, never a `RecursionError` out of `load_family`."""
    path = manifest(tmp_path, "[" * 3000 + '"x"' + "]" * 3000)

    err = raised(lambda: load(path))

    assert isinstance(err, FamilyError), \
        f"refused with {type(err).__name__}, not FamilyError: {str(err)[:200]}"


# ── C: the loader refuses aliases ──────────────────────────────────────────────────────────


_ALIASED = {
    "reused-mapping": "a: &h {host: x, tags: [p, q]}\nb: *h\n",
    "reused-scalar": "hosts: [&h web-1, *h]\n",
    "cyclic": "p: &a {k: [*a]}\n",
    "merge-key": "base: &b {x: 1}\nderived:\n  <<: *b\n  y: 2\n",
}

#: Every reader of a YAML document the tree has: the load, the node tree, and the typed and
#: spelled reading. None of them may hand out a shared or cyclic value.
_READERS: dict[str, Callable[[str], Any]] = {
    "safe_load": _yaml.safe_load,
    "compose": _yaml.compose,
    "typed-and-spelled": _yaml.safe_load_typed_and_spelled,
}


@pytest.mark.parametrize("reader", list(_READERS))
@pytest.mark.parametrize("text", list(_ALIASED.values()), ids=list(_ALIASED))
def test_every_yaml_reader_refuses_any_alias_as_a_yaml_error(text, reader):
    assert _has_alias(text), "the fixture carries no alias"
    assert yaml.safe_load(text) is not None

    err = raised(lambda: _READERS[reader](text))

    assert isinstance(err, _yaml.AliasRefused), \
        f"{reader} did not refuse an aliased document: {type(err).__name__} {err}"


def test_the_yaml_writer_writes_a_shared_value_in_full_and_refuses_a_cycle():
    shared = {"host": "web-1", "tags": ["p", "q"]}
    doc = {"a": shared, "b": shared, "c": [shared]}
    assert _has_alias(yaml.safe_dump(doc)), "the fixture shares no object, so this tests nothing"

    text = _yaml.safe_dump(doc, sort_keys=False)

    assert _anchors_and_aliases(text) == []
    assert _yaml.safe_load(text) == doc
    cyclic: list[Any] = []
    cyclic.append(cyclic)
    assert isinstance(raised(lambda: _yaml.safe_dump(cyclic)), _yaml.AliasRefused)


def _bomb_members(levels: int = 9, fan_out: int = 10) -> str:
    """Mapping members that are a few hundred bytes of text and `fan_out ** levels` leaves once
    expanded: each anchor is a list of `fan_out` aliases of the one before. Depth is only
    `levels + 1`, far under the limit — only the alias count makes it expensive."""
    parts = ['"l0": &l0 [' + ", ".join(['"x"'] * fan_out) + "]"]
    for i in range(1, levels):
        parts.append(f'"l{i}": &l{i} [' + ", ".join([f"*l{i - 1}"] * fan_out) + "]")
    return ", ".join(parts)


def _bomb_in_a_fact() -> tuple[str, str]:
    """The bomb inside world b's fact, beside the fields a fact declares."""
    bomb = ('[{"fact_id": "f1", "statement": "s", "entities": ["web-1"], '
            + _bomb_members() + "}]")
    return family_text(bomb), bomb


def _bomb_in_the_discriminator() -> tuple[str, str]:
    """The bomb in the discriminator mapping, beside its predicate: a second place in the
    document, so the refusal is the loader's everywhere and not one field's check."""
    doc = T.family_doc()
    doc["discriminator"] = "__DISCRIMINATOR__"
    bomb = '{"predicate": "p", ' + _bomb_members() + "}"
    return spliced(doc, {"__DISCRIMINATOR__": bomb}), bomb


_BOMBS = {"world-fact": _bomb_in_a_fact, "discriminator": _bomb_in_the_discriminator}


def _expanded_leaves(value: Any, memo: dict[int, int] | None = None) -> int:
    """How many leaves a walk of `value` visits — counted through the shared references
    without expanding them."""
    memo = {} if memo is None else memo
    if not isinstance(value, (dict, list)):
        return 1
    if id(value) not in memo:
        children = value.values() if isinstance(value, dict) else value
        memo[id(value)] = sum(_expanded_leaves(c, memo) for c in children)
    return memo[id(value)]


_LOAD_IN_A_CHILD = """
import json, sys, time
from pathlib import Path

import yaml

from defender.episodes._episode_handle import Episode
from defender.runtime.branch._family import FamilyError, load_family

start = time.monotonic()
try:
    with Episode.open(Path(sys.argv[1]).parent) as episode:
        load_family(episode.view(), expected_episode_id=Path(sys.argv[1]).parent.name)
    outcome, yaml_cause = "loaded", False
except FamilyError as e:
    outcome, yaml_cause = "FamilyError", isinstance(e.__cause__, yaml.YAMLError)
except Exception as e:
    outcome, yaml_cause = type(e).__name__, False
print(json.dumps({"outcome": outcome, "yaml_cause": yaml_cause,
                  "elapsed": time.monotonic() - start}))
"""


@pytest.mark.parametrize("placement", list(_BOMBS))
def test_an_alias_bomb_manifest_is_refused_fast_without_being_expanded(tmp_path, placement):
    text, bomb = _BOMBS[placement]()
    assert len(bomb) < 1024, "the bomb is not small"
    assert _expanded_leaves(yaml.safe_load(text)) >= 10**9, \
        "the fixture is not a bomb, so this arm tests nothing"
    path = write_manifest(tmp_path, text)

    try:
        child = subprocess.run(
            [sys.executable, "-c", _LOAD_IN_A_CHILD, str(path)], capture_output=True, text=True,
            timeout=BOMB_TIMEOUT, cwd=str(tmp_path),
            env=dict(os.environ, PYTHONPATH=str(T.DEFENDER.parent)))
    except subprocess.TimeoutExpired:
        pytest.fail(f"load_family did not return within {BOMB_TIMEOUT}s on a "
                    f"{len(bomb)}-byte alias bomb — the aliases were expanded")

    assert child.returncode == 0, child.stderr[-2000:]
    result = json.loads(child.stdout.strip().splitlines()[-1])
    assert result["outcome"] == "FamilyError", f"the alias bomb was not refused: {result}"
    assert result["yaml_cause"], "the alias bomb was refused, but not by the YAML loader"
    assert result["elapsed"] < BOMB_LOAD_SECONDS, \
        f"refusing the alias bomb took {result['elapsed']:.2f}s — it was walked, not refused"


def _scalar_across_top_level_fields() -> str:
    """`source_run_id` anchored, `base_story` its alias. (#1255 P4, D1: this was
    `continuation_prompt` anchored; that field is retired, and the refusal is the YAML loader's,
    which does not care which two top-level scalars the anchor links.)"""
    doc = T.family_doc()
    anchored = doc["source_run_id"]
    doc["source_run_id"], doc["base_story"] = "__ANCHORED__", "__STORY__"
    return spliced(doc, {"__ANCHORED__": "&s " + json.dumps(anchored), "__STORY__": "*s"})


def _sequence_across_worlds() -> str:
    """World b's fact's entities anchored, world c's fact's entities its alias."""
    doc = T.family_doc()
    b_fact, c_fact = doc["worlds"][1]["facts"][0], doc["worlds"][2]["facts"][0]
    entities = b_fact["entities"]
    b_fact["entities"], c_fact["entities"] = "__B_ENTITIES__", "__C_ENTITIES__"
    return spliced(doc, {"__B_ENTITIES__": "&e " + json.dumps(entities),
                         "__C_ENTITIES__": "*e"})


def _mapping_across_worlds() -> str:
    """World b's fact anchored, world c's one fact its alias (a fact_id is per world, so the
    written-out document is a legal one)."""
    doc = T.family_doc()
    fact = doc["worlds"][1]["facts"][0]
    doc["worlds"][1]["facts"], doc["worlds"][2]["facts"] = "__B_FACTS__", "__C_FACTS__"
    return spliced(doc, {"__B_FACTS__": "[&o " + json.dumps(fact) + "]",
                         "__C_FACTS__": "[*o]"})


_ANYWHERE = {
    "scalar-across-top-level-fields": _scalar_across_top_level_fields,
    "sequence-across-worlds": _sequence_across_worlds,
    "mapping-across-worlds": _mapping_across_worlds,
}


@pytest.mark.parametrize("where", list(_ANYWHERE))
def test_an_alias_anywhere_in_the_manifest_is_refused_at_load(tmp_path, where):
    text = _ANYWHERE[where]()
    assert _has_alias(text), "the fixture carries no alias, so this arm tests nothing"

    assert_refused_at_load(raised(lambda: load(write_manifest(tmp_path, text))),
                           f"an alias {where}")


@pytest.mark.parametrize("where", list(_ANYWHERE))
def test_the_same_document_written_longhand_loads(tmp_path, where):
    """The paired control: each document above with its aliases expanded — the same values,
    written out — loads, so the refusal is about the alias, not about what it carried."""
    text = json.dumps(yaml.safe_load(_ANYWHERE[where]()))
    assert _anchors_and_aliases(text) == []

    family = load(write_manifest(tmp_path, text))

    assert family.episode_id == T.EPISODE_ID


def _world_b_facts_on_disk(path: Path) -> Any:
    """What PyYAML's own (alias-honouring) loader makes of world b's facts."""
    return _world_b(yaml.safe_load(path.read_text(encoding="utf-8")))["facts"]


def test_a_cyclic_fact_list_built_by_a_yaml_anchor_is_refused_at_load(tmp_path):
    path = manifest(tmp_path, '&a [{"fact_id": "f1", "statement": "s", "entities": *a}]')
    facts = _world_b_facts_on_disk(path)
    assert facts[0]["entities"] is facts, "the spliced anchor did not load as a cycle"

    assert_refused_at_load(raised(lambda: load(path)), "a cyclic anchor")


def test_write_family_writes_a_shared_object_longhand_and_it_loads_back(tmp_path):
    doc = T.family_doc()
    shared = ["web-1", "10.0.0.9"]
    for world in doc["worlds"][1:]:
        world["facts"][0]["entities"] = shared
    assert _has_alias(yaml.safe_dump(doc, sort_keys=False)), \
        "the fixture shares no object, so this arm tests nothing"
    episode_dir = tmp_path / "episodes" / T.EPISODE_ID
    episode_dir.parent.mkdir(parents=True)

    with Episode.create(episode_dir) as episode:
        path = write_family(episode, doc)

    text = path.read_text(encoding="utf-8")
    assert _anchors_and_aliases(text) == [], \
        "write_family wrote YAML anchors/aliases, which the manifest loader refuses"
    assert yaml.safe_load(text) == doc
    assert load(path) == parse_family(doc)


# ── C at the questioner: an aliased reply is malformed YAML ────────────────────────────────


def _questioner():
    return T.mod("learning.branch.questioner")


def _fenced(text: str) -> str:
    """The questioner fixture's own fenced shape (`test_947`/`test_1018`)."""
    return f"```yaml\n{text}```"


def _shared_facts_doc() -> dict:
    """The family reply with world c's planned fact the SAME object as world b's."""
    doc = T.family_doc()
    doc["worlds"][2]["facts"] = [doc["worlds"][1]["facts"][0]]
    return doc


def _author(tmp_path: Path, agent: T.FakeAgent) -> dict:
    return _questioner().author_family(
        source_run_dir=tmp_path, episode_dir=T.episode(tmp_path),
        invoke=agent, leads=[], alert={}, frontier="")


def _seats() -> tuple[str, str]:
    return (_fenced(yaml.safe_dump(T.declaration(T.world_doc("b")), sort_keys=False)),
            _fenced(yaml.safe_dump(T.declaration(T.world_doc("c")), sort_keys=False)))


_ALIASED_REPLIES: dict[str, Callable[[], str]] = {
    # Block style, as a model writes it, with the anchor PyYAML itself names.
    "reused-anchor": lambda: yaml.safe_dump(_shared_facts_doc(), sort_keys=False),
    "cyclic-anchor": lambda: family_text(
        '&a [{"fact_id": "f1", "statement": "s", "entities": *a}]') + "\n",
}


@pytest.mark.parametrize("kind", list(_ALIASED_REPLIES))
def test_a_questioner_reply_carrying_a_yaml_alias_is_refused_naming_call_1(tmp_path, kind):
    text = _ALIASED_REPLIES[kind]()
    assert _has_alias(text), "the reply carries no alias, so this arm tests nothing"
    agent = T.FakeAgent(_fenced(text), *_seats())

    err = raised(lambda: _author(tmp_path, agent))

    assert err is not None, "an aliased questioner reply was accepted"
    assert isinstance(err, T.sym("runtime.branch", "BranchError")), \
        f"refused with {type(err).__name__}, not BranchError: {str(err)[:200]}"
    assert "call 1" in str(err)
    assert isinstance(err.__cause__, yaml.YAMLError), \
        f"refused, but not as malformed YAML (cause: {type(err.__cause__).__name__})"
    assert agent.calls == 1, "seat calls were paid against a refused family"


def _cyclic_facts_doc() -> dict:
    doc = T.family_doc()
    loop: dict[str, Any] = {"fact_id": "f1", "statement": "s"}
    loop["entities"] = [loop]
    _world_b(doc)["facts"] = [loop]
    return doc


@pytest.mark.parametrize("build", [_shared_facts_doc, _cyclic_facts_doc],
                         ids=["shared", "cyclic"])
def test_a_parsed_questioner_reply_with_shared_parts_is_refused_like_an_alias(tmp_path, build):
    agent = T.FakeAgent(build(), T.declaration(T.world_doc("b")), T.declaration(T.world_doc("c")))

    err = raised(lambda: _author(tmp_path, agent))

    assert isinstance(err, T.sym("runtime.branch", "BranchError")), \
        f"refused with {type(err).__name__}, not BranchError: {str(err)[:200]}"
    assert "call 1" in str(err)
    assert isinstance(err.__cause__, _yaml.AliasRefused)
    assert agent.calls == 1, "seat calls were paid against a refused family"


#: Seat B's reply (call 2) with its story's text reused as its axis through an alias.
_SEAT_B_ALIASED = ("story: &s a story\naxis: *s\n"
                   "disposition_declared: malicious\nlabel_basis: policy-rule\n")
#: Seat B's reply carrying the bomb under a key the questioner never reads — so no check of
#: the COMPOSED world would ever see it; only the loader can refuse it.
_SEAT_B_BOMB = ("story: a story\naxis: an axis\n"
                "disposition_declared: malicious\nlabel_basis: policy-rule\n"
                "scratch: {" + _bomb_members() + "}\n")

_ALIASED_SEAT_REPLIES = {"reused-scalar": _SEAT_B_ALIASED, "bomb-in-an-unread-key": _SEAT_B_BOMB}


def _family_reply() -> str:
    return _fenced(yaml.safe_dump(T.declaration(T.family_doc()), sort_keys=False))


@pytest.mark.parametrize("kind", list(_ALIASED_SEAT_REPLIES))
def test_a_seat_reply_carrying_a_yaml_alias_is_refused_naming_the_seat(tmp_path, kind):
    text = _ALIASED_SEAT_REPLIES[kind]
    assert _has_alias(text), "the reply carries no alias, so this arm tests nothing"
    agent = T.FakeAgent(_family_reply(), _fenced(text), _seats()[1])

    err = raised(lambda: _author(tmp_path, agent))

    assert err is not None, "an aliased seat reply was accepted"
    assert isinstance(err, T.sym("runtime.branch", "BranchError")), \
        f"refused with {type(err).__name__}, not BranchError: {str(err)[:200]}"
    assert "seat B" in str(err), f"the refusal does not name seat B: {str(err)[:200]}"
    assert isinstance(err.__cause__, yaml.YAMLError), \
        f"refused, but not as malformed YAML (cause: {type(err.__cause__).__name__})"
    assert agent.calls == 2, "the questioner went on to seat C after refusing seat B"
