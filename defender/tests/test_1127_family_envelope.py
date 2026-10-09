"""#1127 on the branch manifest — YAML aliases are refused at load, anywhere in the document.

The manifest is model-authored (the questioner writes `family.yaml`). YAML has no nesting bound
(C7), and an alias can make the loaded value cyclic (C10) or — nine anchors of ten aliases each,
a few hundred bytes — a billion leaves that any walk of the value visits one by one.

The design (issue #1127, as amended after the review of PR #1139):

* C — aliases are refused AT LOAD: `defender._yaml.safe_load(text)` (every reader there) raises a
  `yaml.YAMLError` subclass on any alias, and it is the loader behind `_family._read_document`
  (so `load_family` raises `FamilyError`, chained from that `YAMLError`, for an alias ANYWHERE
  in the manifest) and behind the questioner's reply parser (so an aliased reply to ANY of its
  calls is a `BranchError` like any malformed YAML). `write_family` therefore dumps with no
  aliases, so a document holding one object twice still round-trips through `load_family`.

(#1224 retired the discriminator's `envelope` — a world is now the natural-language `facts` it
asserts — and with it M4, the envelope-params depth bound. The splice point the arms below use
is world b's `facts`, the manifest's model-authored structure.)

Every manifest arm goes through `load(path)` over YAML text — the anchor cases only exist
in the text. The alias bomb is loaded in a CHILD PROCESS under a timeout: a loader that expands
it does not return, and a hang must fail the arm, not the run.
"""
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
from defender._episode_handle import Episode
from defender.runtime.branch._family import FamilyError, load_family, parse_family, write_family
from defender.tests import _triplet_947 as T
from defender.tests.test_1127_params_nesting_limit import raised

_PLACEHOLDER = "__WORLD_B_FACTS__"

#: How long the child that loads the alias bomb may run before it is killed. Generous: it
#: covers interpreter start and imports on a loaded box. The load itself is held to
#: `BOMB_LOAD_SECONDS`, timed inside the child.
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
    assert world["world_id"] == "b"
    return world


def family_text(facts_yaml: str) -> str:
    """The shared fixture's family document as text, world b's `facts` replaced by
    `facts_yaml` spliced in as YAML text."""
    doc = T.family_doc()
    _world_b(doc)["facts"] = _PLACEHOLDER
    return spliced(doc, {_PLACEHOLDER: facts_yaml})


def load(path: Path):
    """`load_family` over the episode whose manifest is at `path` (`<episode>/family.yaml`)."""
    with Episode.open(path.parent) as episode:
        return load_family(episode.view())


def write_manifest(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "family.yaml"
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
    """C, made the default (#1127 review): an alias — of a mapping, of a scalar, one that makes
    a cycle, or one a merge key spends — is refused by EVERY reader in `defender._yaml`, with
    the `AliasRefused` `yaml.YAMLError` every caller already catches for malformed YAML. No
    reader opts in, so no reader can be left out. PyYAML's own safe loader accepts each."""
    assert _has_alias(text), "the fixture carries no alias"
    assert yaml.safe_load(text) is not None

    err = raised(lambda: _READERS[reader](text))

    assert isinstance(err, _yaml.AliasRefused), \
        f"{reader} did not refuse an aliased document: {type(err).__name__} {err}"


_PLAIN = {
    "empty": "",
    "scalars": "a: 1\nb: [x, y, {c: true, d: null, e: 1.5}]\nwhen: 2026-07-25T07:48:37Z\n"
               "mode: 0755\nflag: yes\nq: '*not-an-alias'\n",
    "inline-merge": "base:\n  <<: {x: 1}\n  y: 2\n",
    "family-json": json.dumps(T.family_doc()),
    "family-block": yaml.safe_dump(T.family_doc(), sort_keys=False),
}


@pytest.mark.parametrize("text", list(_PLAIN.values()), ids=list(_PLAIN))
def test_an_alias_free_document_reads_exactly_as_pyyamls_safe_loader_reads_it(text):
    """The paired control: without an alias, `_yaml.safe_load` is PyYAML's safe loader — same
    document, same typed scalars (timestamps, octals, `yes`), a quoted `*` is text, and a merge
    of an inline mapping (no alias) still merges."""
    assert _anchors_and_aliases(text) == []

    assert _yaml.safe_load(text) == yaml.safe_load(text)


@pytest.mark.parametrize("text", ["a: [1, 2\n", "a: b: c\n", "[" * 3000 + "]" * 3000],
                         ids=["unclosed", "bad-mapping", "too-deep-to-compose"])
def test_malformed_yaml_is_a_yaml_error_never_an_interpreter_error(text):
    """Malformed text, including text nested past the composer's recursion, is a `YAMLError`
    from `_yaml.safe_load` — never a `RecursionError` a caller's `except yaml.YAMLError` would
    miss."""
    err = raised(lambda: _yaml.safe_load(text))

    assert isinstance(err, yaml.YAMLError), \
        f"refused with {type(err).__name__}, not a YAMLError"


def test_the_yaml_writer_writes_a_shared_value_in_full_and_refuses_a_cycle():
    """The writer's half: `_yaml.safe_dump` writes a value held twice out in full, so what the
    tree writes the tree can read back; PyYAML's own dumper writes `&id001`/`*id001` for it. A
    value that holds itself cannot be written in full, and is `AliasRefused`, not a
    `RecursionError`."""
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

from defender._episode_handle import Episode
from defender.runtime.branch._family import FamilyError, load_family

start = time.monotonic()
try:
    with Episode.open(Path(sys.argv[1]).parent) as episode:
        load_family(episode.view())
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
    """C against the billion-laughs shape, wherever it sits: `load_family` refuses it with a
    `FamilyError` from the YAML loader in well under two seconds. An alias-honouring loader
    builds it cheaply (shared references) and any walk then visits every one of its 10**9
    leaves; only refusing aliases EVERYWHERE in the document refuses it before it is built.
    (Each placement also carries a field its mapping does not declare, so the arm reads the
    refusal's CAUSE: a loader that built the bomb would still refuse, but not by `YAMLError`.)

    Loaded in a child process under a timeout, timed inside the child: a hang is killed and
    fails this arm; nothing is left spinning."""
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
    """`continuation_prompt` anchored, `base_story` its alias."""
    doc = T.family_doc()
    prompt = doc["continuation_prompt"]
    doc["continuation_prompt"], doc["base_story"] = "__PROMPT__", "__STORY__"
    return spliced(doc, {"__PROMPT__": "&s " + json.dumps(prompt), "__STORY__": "*s"})


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
    """C is about the DOCUMENT, not one field: an alias anywhere in the manifest — across two
    top-level fields, across two worlds' facts — is refused by the loader. A reader that
    honoured aliases and only checked one field would load every one of these."""
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
    """C10: an anchor whose body aliases itself would load as a CYCLIC value. It is refused by
    the loader, as an alias, before any walk of the value — so the refusal is the loader's
    `YAMLError`."""
    path = manifest(tmp_path, '&a [{"fact_id": "f1", "statement": "s", "entities": *a}]')
    facts = _world_b_facts_on_disk(path)
    assert facts[0]["entities"] is facts, "the spliced anchor did not load as a cycle"

    assert_refused_at_load(raised(lambda: load(path)), "a cyclic anchor")


_REUSED = ('[{"fact_id": "f1", "statement": "s", "entities": &e ["web-1", "10.0.0.9"]}, '
           '{"fact_id": "f2", "statement": "t", "entities": *e}]')
_LONGHAND = [{"fact_id": "f1", "statement": "s", "entities": ["web-1", "10.0.0.9"]},
             {"fact_id": "f2", "statement": "t", "entities": ["web-1", "10.0.0.9"]}]


def test_a_fact_list_that_reuses_a_yaml_anchor_is_refused_at_load(tmp_path):
    """C: a reused anchor makes a shared reference, not a cycle, and is shallow — but it is an
    alias, and the manifest loader refuses every alias."""
    path = manifest(tmp_path, _REUSED)
    facts = _world_b_facts_on_disk(path)
    assert facts[0]["entities"] is facts[1]["entities"], "the spliced anchor was not reused"
    assert facts == _LONGHAND

    assert_refused_at_load(raised(lambda: load(path)), "a reused anchor")


def test_the_same_fact_list_written_longhand_loads_whole(tmp_path):
    """The paired control: the same values spelled out, no alias, load — so the refusal above
    is about the alias, not about the values it carried."""
    path = manifest(tmp_path, json.dumps(_LONGHAND))
    assert _anchors_and_aliases(path.read_text(encoding="utf-8")) == []

    family = load(path)

    assert [(f.fact_id, f.statement, list(f.entities)) for f in family.world("b").facts] == [
        (f["fact_id"], f["statement"], f["entities"]) for f in _LONGHAND]


def test_write_family_writes_a_shared_object_longhand_and_it_loads_back(tmp_path):
    """C's other half: `write_family` dumps with no aliases, so a document holding one object
    in two places — the ordinary result of composing it in Python — round-trips through the
    loader that now refuses aliases. PyYAML's default dumper emits `&id001`/`*id001` for it."""
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
    return (_fenced(yaml.safe_dump(T.world_doc("b"), sort_keys=False)),
            _fenced(yaml.safe_dump(T.world_doc("c"), sort_keys=False)))


_ALIASED_REPLIES: dict[str, Callable[[], str]] = {
    # Block style, as a model writes it, with the anchor PyYAML itself names.
    "reused-anchor": lambda: yaml.safe_dump(_shared_facts_doc(), sort_keys=False),
    "cyclic-anchor": lambda: family_text(
        '&a [{"fact_id": "f1", "statement": "s", "entities": *a}]') + "\n",
}


@pytest.mark.parametrize("kind", list(_ALIASED_REPLIES))
def test_a_questioner_reply_carrying_a_yaml_alias_is_refused_naming_call_1(tmp_path, kind):
    """C at the questioner: call 1's reply is parsed by the alias-refusing loader, so an alias
    is refused like any other malformed YAML — `BranchError` naming call 1, chained from the
    loader's `YAMLError` — and no seat call is paid against it."""
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
    """#1127 review: a driver that hands back an already-parsed reply skipped the loader, so
    the family's "no shared or cyclic values" rule held only for text replies — and a cycle
    reached `parse_family` and the manifest writer. A parsed reply is held to the loader's rule:
    one holding a value twice, or inside itself, is the same `BranchError` naming call 1,
    chained from `AliasRefused`, and no seat call is paid against it. (The control, a parsed
    reply that is a tree, is every launcher test whose fake questioner hands back dicts.)"""
    agent = T.FakeAgent(build(), T.world_doc("b"), T.world_doc("c"))

    err = raised(lambda: _author(tmp_path, agent))

    assert isinstance(err, T.sym("runtime.branch", "BranchError")), \
        f"refused with {type(err).__name__}, not BranchError: {str(err)[:200]}"
    assert "call 1" in str(err)
    assert isinstance(err.__cause__, _yaml.AliasRefused)
    assert agent.calls == 1, "seat calls were paid against a refused family"


def test_the_same_questioner_reply_written_longhand_is_accepted(tmp_path):
    """The paired control: the reused-anchor reply's document with the sharing broken — the
    same values, no alias — composes, both seats are called, and each world carries the facts
    call 1 planned for it."""
    doc = json.loads(json.dumps(_shared_facts_doc()))
    text = yaml.safe_dump(doc, sort_keys=False)
    assert _anchors_and_aliases(text) == []
    agent = T.FakeAgent(_fenced(text), *_seats())

    family = _author(tmp_path, agent)

    assert agent.calls == 3
    assert [w["facts"] for w in family["worlds"][1:]] == [w["facts"] for w in doc["worlds"][1:]]


#: Seat B's reply (call 2) with its story's text reused as its axis through an alias.
_SEAT_B_ALIASED = ("world_id: b\nrole: B\nstory: &s a story\naxis: *s\n"
                   "disposition_declared: malicious\nlabel_basis: policy-rule\n")
#: The same reply, the alias written out.
_SEAT_B_LONGHAND = ("world_id: b\nrole: B\nstory: a story\naxis: a story\n"
                    "disposition_declared: malicious\nlabel_basis: policy-rule\n")
#: Seat B's reply carrying the bomb under a key the questioner never reads — so no check of
#: the COMPOSED world would ever see it; only the loader can refuse it.
_SEAT_B_BOMB = ("world_id: b\nrole: B\nstory: a story\naxis: an axis\n"
                "disposition_declared: malicious\nlabel_basis: policy-rule\n"
                "scratch: {" + _bomb_members() + "}\n")

_ALIASED_SEAT_REPLIES = {"reused-scalar": _SEAT_B_ALIASED, "bomb-in-an-unread-key": _SEAT_B_BOMB}


def _family_reply() -> str:
    return _fenced(yaml.safe_dump(T.family_doc(), sort_keys=False))


@pytest.mark.parametrize("kind", list(_ALIASED_SEAT_REPLIES))
def test_a_seat_reply_carrying_a_yaml_alias_is_refused_naming_the_seat(tmp_path, kind):
    """C on every questioner call, not only call 1: seat B's reply (call 2) is parsed by the
    same alias-refusing loader — `BranchError` naming seat B, chained from the loader's
    `YAMLError` — and the episode stops there: seat C is never called."""
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


def test_the_same_seat_reply_written_longhand_is_accepted(tmp_path):
    """The paired control: seat B's reply with the alias written out composes, seat C is
    called, and world b carries the story seat B wrote."""
    assert _anchors_and_aliases(_SEAT_B_LONGHAND) == []
    assert yaml.safe_load(_SEAT_B_LONGHAND) == yaml.safe_load(_SEAT_B_ALIASED)
    agent = T.FakeAgent(_family_reply(), _fenced(_SEAT_B_LONGHAND), _seats()[1])

    family = _author(tmp_path, agent)

    assert agent.calls == 3
    assert family["worlds"][1]["story"] == "a story"
