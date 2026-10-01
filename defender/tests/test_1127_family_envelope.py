"""#1127 on the branch manifest — too-deep envelopes and YAML aliases are refused at load.

The discriminator's `envelope` is a model-authored call (the questioner writes `family.yaml`),
and its `params` reach the branch ledger as a row's `params`. YAML has no nesting bound (C7),
and an alias can make the loaded value cyclic (C10) or — nine anchors of ten aliases each, a few
hundred bytes — a billion leaves that any walk of the value visits one by one.
`review.replay_one` runs the adapter BEFORE `book.record`, so the ledger's own backstop would
only refuse after the call already ran.

The design (issue #1127, as amended after the review of PR #1139):

* M4 — `parse_family` refuses a discriminator whose `envelope.params` nest past
  `PARAMS_NESTING_LIMIT` (32, the map counted), with a `FamilyError` naming it. In
  `parse_family`, so the questioner's in-memory authoring path is refused too.
* C — aliases are refused AT LOAD: `defender._yaml.safe_load_tree(text)` raises a
  `yaml.YAMLError` subclass on any alias, and it is the loader behind `_family._read_document`
  (so `load_family` raises `FamilyError`, chained from that `YAMLError`, for an alias ANYWHERE
  in the manifest, not only in the envelope) and behind the questioner's reply parser (so an
  aliased reply to ANY of its calls is a `BranchError` like any malformed YAML).
  `write_family` therefore dumps with no aliases, so a document holding one object twice still
  round-trips through `load_family`.

Every manifest arm goes through `load(path)` over YAML text — the anchor cases only exist
in the text. The alias bomb is loaded in a CHILD PROCESS under a timeout: a loader that expands
it does not return, and a hang must fail the arm, not the run.

Against 7ae2c429 (limit 99, aliases honoured, before the amendment) the depth-33 arms, every
alias refusal, the alias-bomb arms (the envelope one killed at its timeout), `write_family`'s
no-alias pin and every `safe_load_tree` arm were RED; the depth-31/32 controls, the longhand
controls, the unparseably-deep manifest and the round trip's own equality GREEN.
"""
from __future__ import annotations

import json
import os
import re
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
from defender.tests.test_1127_params_nesting_limit import LIMIT, dict_chain, list_chain, raised

_PLACEHOLDER = "__ENVELOPE_PARAMS__"

#: How long the child that loads the alias bomb may run before it is killed. Generous: it
#: covers interpreter start and imports on a loaded box. The load itself is held to
#: `BOMB_LOAD_SECONDS`, timed inside the child.
BOMB_TIMEOUT = 30
BOMB_LOAD_SECONDS = 2.0


def _query() -> str:
    """The fixture's own envelope query, spent rather than re-spelled."""
    return T.family_doc()["discriminator"]["envelope"]["params"]["query"]


def envelope_params(depth: int, chain: Callable[[int], Any] = dict_chain) -> dict:
    """The fixture's real envelope params plus one field, nested `depth` deep with the params
    map itself counted."""
    return {"query": _query(), "filt": chain(depth - 1)}


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


def family_text(params_yaml: str) -> str:
    """The shared fixture's family document as text, its `discriminator.envelope.params`
    replaced by `params_yaml` spliced in as YAML text."""
    doc = T.family_doc()
    doc["discriminator"]["envelope"]["params"] = _PLACEHOLDER
    return spliced(doc, {_PLACEHOLDER: params_yaml})


def load(path: Path):
    """`load_family` over the episode whose manifest is at `path` (`<episode>/family.yaml`)."""
    with Episode.open(path.parent) as episode:
        return load_family(episode.view())


def write_manifest(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "family.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def manifest(tmp_path: Path, params_yaml: str) -> Path:
    """A real `family.yaml` whose envelope params are `params_yaml`."""
    return write_manifest(tmp_path, family_text(params_yaml))


def _names_the_limit(message: str) -> bool:
    return re.search(rf"(?<!\d){LIMIT}(?!\d)", message) is not None


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


# ── M4: the envelope's depth ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize("depth", [LIMIT - 1, LIMIT])
def test_an_envelope_at_or_under_the_limit_loads_whole(tmp_path, depth):
    """The positive control: at the limit the manifest loads, and the envelope's params are
    the ones authored — whole, not cut."""
    params = envelope_params(depth)

    family = load(manifest(tmp_path, json.dumps(params)))

    assert family.discriminator["envelope"]["params"] == params


@pytest.mark.parametrize(("depth", "chain"), [
    (LIMIT + 1, dict_chain), (LIMIT + 50, dict_chain), (LIMIT + 1, list_chain),
], ids=["one-past-dict", "far-past-dict", "one-past-list"])
def test_an_envelope_past_the_limit_refuses_the_whole_family(tmp_path, depth, chain):
    """M4: a too-deep envelope refuses the manifest — the whole family, with a `FamilyError`
    naming the limit — so the review never runs a call whose ledger row could not be written.

    Lists count as levels exactly as mappings do (the predicate mirrors the cleaner)."""
    path = manifest(tmp_path, json.dumps(envelope_params(depth, chain)))

    with pytest.raises(FamilyError) as refused:
        load(path)

    assert _names_the_limit(str(refused.value)), \
        f"the refusal does not name the limit: {refused.value}"


def test_an_envelope_too_deep_for_the_yaml_parser_is_still_a_family_error(tmp_path):
    """Whatever loader `_read_document` uses, text nested past what the YAML parser's own
    recursion can compose is a `FamilyError`, never a `RecursionError` out of `load_family`.
    Green today (`_yaml.safe_load` translates it); the loader swap must keep it."""
    path = manifest(tmp_path, "[" * 3000 + '"x"' + "]" * 3000)

    err = raised(lambda: load(path))

    assert isinstance(err, FamilyError), \
        f"refused with {type(err).__name__}, not FamilyError: {str(err)[:200]}"


def test_the_in_memory_parse_refuses_too_not_only_the_file_reader(tmp_path):
    """M4's placement: the check lives in `parse_family`, not in the file reader. The
    questioner's authoring path (`cli._author`) hands `parse_family` the document it just
    decoded and reviews the in-memory `Family` — no file is read — so a check that only
    `load_family` ran would let the review run a too-deep envelope before `write_family`.

    Paired on the same entry point: the document at the limit parses, envelope whole."""
    at_limit = T.family_doc()
    at_limit["discriminator"]["envelope"]["params"] = envelope_params(LIMIT)
    one_past = T.family_doc()
    one_past["discriminator"]["envelope"]["params"] = envelope_params(LIMIT + 1)

    family = parse_family(at_limit)
    assert family.discriminator["envelope"]["params"] == envelope_params(LIMIT)

    with pytest.raises(FamilyError) as refused:
        parse_family(one_past)
    assert _names_the_limit(str(refused.value)), \
        f"the refusal does not name the limit: {refused.value}"


# ── C: the loader refuses aliases ──────────────────────────────────────────────────────────


def safe_load_tree() -> Callable[[str], Any]:
    """`defender._yaml.safe_load_tree`, resolved per arm so a missing name fails the arm."""
    load = getattr(_yaml, "safe_load_tree", None)
    assert callable(load), "defender._yaml.safe_load_tree does not exist"
    return load


_ALIASED = {
    "reused-mapping": "a: &h {host: x, tags: [p, q]}\nb: *h\n",
    "reused-scalar": "hosts: [&h web-1, *h]\n",
    "cyclic": "p: &a {k: [*a]}\n",
    "merge-key": "base: &b {x: 1}\nderived:\n  <<: *b\n  y: 2\n",
}


@pytest.mark.parametrize("text", list(_ALIASED.values()), ids=list(_ALIASED))
def test_safe_load_tree_refuses_any_alias_as_a_yaml_error(text):
    """C: an alias — of a mapping, of a scalar, one that makes a cycle, or one a merge key
    spends — is refused with a `yaml.YAMLError` subclass, the class every caller already
    catches for malformed YAML. PyYAML's own safe loader accepts each of them."""
    assert _has_alias(text), "the fixture carries no alias"
    assert yaml.safe_load(text) is not None

    load = safe_load_tree()
    err = raised(lambda: load(text))

    assert isinstance(err, yaml.YAMLError), \
        f"an aliased document was not refused as a YAMLError: {type(err).__name__} {err}"


_PLAIN = {
    "empty": "",
    "scalars": "a: 1\nb: [x, y, {c: true, d: null, e: 1.5}]\nwhen: 2026-07-25T07:48:37Z\n"
               "mode: 0755\nflag: yes\nq: '*not-an-alias'\n",
    "family-json": json.dumps(T.family_doc()),
    "family-block": yaml.safe_dump(T.family_doc(), sort_keys=False),
}


@pytest.mark.parametrize("text", list(_PLAIN.values()), ids=list(_PLAIN))
def test_safe_load_tree_reads_an_alias_free_document_exactly_as_safe_load_does(text):
    """The paired control: without an alias, `safe_load_tree` is `_yaml.safe_load` — same
    document, same typed scalars (timestamps, octals, `yes`), and a quoted `*` is text."""
    assert _anchors_and_aliases(text) == []

    assert safe_load_tree()(text) == _yaml.safe_load(text)


@pytest.mark.parametrize("text", ["a: [1, 2\n", "a: b: c\n", "[" * 3000 + "]" * 3000],
                         ids=["unclosed", "bad-mapping", "too-deep-to-compose"])
def test_safe_load_tree_refuses_what_safe_load_refuses_as_a_yaml_error(text):
    """Malformed text, including text nested past the composer's recursion, is a `YAMLError`
    from `safe_load_tree` exactly as from `_yaml.safe_load` — never a `RecursionError` a
    caller's `except yaml.YAMLError` would miss."""
    with pytest.raises(yaml.YAMLError):
        _yaml.safe_load(text)

    load = safe_load_tree()
    err = raised(lambda: load(text))

    assert isinstance(err, yaml.YAMLError), \
        f"refused with {type(err).__name__}, not a YAMLError"


def _bomb_members(levels: int = 9, fan_out: int = 10) -> str:
    """Mapping members that are a few hundred bytes of text and `fan_out ** levels` leaves once
    expanded: each anchor is a list of `fan_out` aliases of the one before. Depth is only
    `levels + 1`, far under the limit — only the alias count makes it expensive."""
    parts = ['"l0": &l0 [' + ", ".join(['"x"'] * fan_out) + "]"]
    for i in range(1, levels):
        parts.append(f'"l{i}": &l{i} [' + ", ".join([f"*l{i - 1}"] * fan_out) + "]")
    return ", ".join(parts)


def _bomb_in_envelope_params() -> tuple[str, str]:
    """The bomb as envelope params, where the review's depth walk would visit every leaf."""
    bomb = "{" + f'"query": {json.dumps(_query())}, ' + _bomb_members() + "}"
    return family_text(bomb), bomb


def _bomb_in_a_world_overlay() -> tuple[str, str]:
    """The bomb OUTSIDE the envelope: in world b's staged elastic document, which no depth
    check reads — only a loader that refuses aliases everywhere refuses it."""
    doc = T.family_doc()
    world = doc["worlds"][1]
    assert world["world_id"] == "b"
    (staged,) = world["overlay"]["elastic"].values()
    assert staged["inject"] == [{"_id": "i1"}]
    staged["inject"] = "__INJECT__"
    bomb = '[{"_id": "i1", ' + _bomb_members() + "}]"
    return spliced(doc, {"__INJECT__": bomb}), bomb


_BOMBS = {"envelope-params": _bomb_in_envelope_params, "world-overlay": _bomb_in_a_world_overlay}


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
    `FamilyError` from the YAML loader in well under two seconds. In envelope params the
    pre-amendment loader built it cheaply (shared references) and the depth walk then visited
    every one of its 10**9 leaves; in a world's overlay nothing walks it, so only refusing
    aliases EVERYWHERE in the document refuses it.

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


def _sequence_across_top_level_fields() -> str:
    """`configured_patterns` anchored, `captured_patterns` its alias."""
    doc = T.family_doc()
    patterns = doc["configured_patterns"]
    doc["configured_patterns"], doc["captured_patterns"] = "__CONFIGURED__", "__CAPTURED__"
    return spliced(doc, {"__CONFIGURED__": "&p " + json.dumps(patterns), "__CAPTURED__": "*p"})


def _mapping_inside_a_world_overlay() -> str:
    """Inside world c's patches: one host's patch anchored, a second host's the alias."""
    doc = T.family_doc()
    world = doc["worlds"][2]
    assert world["world_id"] == "c"
    world["overlay"] = "__OVERLAY__"
    return spliced(doc, {"__OVERLAY__": '{"patches": {"identity": {"web-1": &o {"owner": '
                                         '"platform"}, "web-2": *o}}}'})


_OUTSIDE_THE_ENVELOPE = {
    "scalar-across-top-level-fields": _scalar_across_top_level_fields,
    "sequence-across-top-level-fields": _sequence_across_top_level_fields,
    "mapping-inside-a-world-overlay": _mapping_inside_a_world_overlay,
}


@pytest.mark.parametrize("where", list(_OUTSIDE_THE_ENVELOPE))
def test_an_alias_outside_the_envelope_is_refused_at_load(tmp_path, where):
    """C is about the DOCUMENT, not the envelope: an alias anywhere in the manifest — across
    two top-level fields, inside a world's overlay — is refused by the loader, as the
    envelope's are. A reader that honoured aliases and only checked the envelope would load
    every one of these."""
    text = _OUTSIDE_THE_ENVELOPE[where]()
    assert _has_alias(text), "the fixture carries no alias, so this arm tests nothing"
    assert yaml.safe_load(text)["discriminator"] == T.family_doc()["discriminator"], \
        "the splice touched the discriminator, so this arm is not outside the envelope"

    assert_refused_at_load(raised(lambda: load(write_manifest(tmp_path, text))),
                           f"an alias {where}")


@pytest.mark.parametrize("where", list(_OUTSIDE_THE_ENVELOPE))
def test_the_same_document_written_longhand_loads(tmp_path, where):
    """The paired control: each document above with its aliases expanded — the same values,
    written out — loads, so the refusal is about the alias, not about what it carried."""
    text = json.dumps(yaml.safe_load(_OUTSIDE_THE_ENVELOPE[where]()))
    assert _anchors_and_aliases(text) == []

    family = load(write_manifest(tmp_path, text))

    assert family.episode_id == T.EPISODE_ID


def _envelope_params_on_disk(path: Path) -> Any:
    """What PyYAML's own (alias-honouring) loader makes of the manifest's envelope params."""
    return yaml.safe_load(path.read_text(encoding="utf-8"))["discriminator"]["envelope"]["params"]


def test_a_cyclic_envelope_built_by_a_yaml_anchor_is_refused_at_load(tmp_path):
    """C10: an anchor whose body aliases itself would load as a CYCLIC value. It is refused by
    the loader, as an alias, before any walk of the value — so the refusal is the loader's
    `YAMLError`. (Today the depth walk refuses it instead, naming the limit.)"""
    path = manifest(tmp_path, '&a {"k": [*a]}')
    params = _envelope_params_on_disk(path)
    assert params["k"][0] is params, "the spliced anchor did not load as a cycle"

    assert_refused_at_load(raised(lambda: load(path)), "a cyclic anchor")


_REUSED = ('{"query": ' + json.dumps(_query())
           + ', "a": &h {"host": "x"}, "b": *h, "c": [*h]}')
_LONGHAND = {"query": _query(), "a": {"host": "x"}, "b": {"host": "x"}, "c": [{"host": "x"}]}


def test_an_envelope_that_reuses_a_yaml_anchor_is_refused_at_load(tmp_path):
    """C: a reused anchor makes a shared reference, not a cycle, and is shallow — but it is an
    alias, and the manifest loader refuses every alias. (Before the amendment this arm pinned
    the opposite: that it loads.)"""
    path = manifest(tmp_path, _REUSED)
    params = _envelope_params_on_disk(path)
    assert params["a"] is params["b"], "the spliced anchor was not reused"
    assert params == _LONGHAND

    assert_refused_at_load(raised(lambda: load(path)), "a reused anchor")


def test_the_same_envelope_written_longhand_loads_whole(tmp_path):
    """The paired control: the same values spelled out, no alias, load — so the refusal above
    is about the alias, not about the values it carried."""
    path = manifest(tmp_path, json.dumps(_LONGHAND))
    assert _anchors_and_aliases(path.read_text(encoding="utf-8")) == []

    family = load(path)

    assert family.discriminator["envelope"]["params"] == _LONGHAND


def test_write_family_writes_a_shared_object_longhand_and_it_loads_back(tmp_path):
    """C's other half: `write_family` dumps with no aliases, so a document holding one object
    in two places — the ordinary result of composing it in Python — round-trips through the
    loader that now refuses aliases. PyYAML's default dumper emits `&id001`/`*id001` for it."""
    doc = T.family_doc()
    shared = {"host": "web-1", "tags": ["p", "q"]}
    doc["discriminator"]["envelope"]["params"] = {
        "query": _query(), "filt": shared, "also": shared, "each": [shared]}
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


def _shared_envelope_doc() -> dict:
    doc = T.family_doc()
    shared = {"host": "web-1"}
    doc["discriminator"]["envelope"]["params"] = {"query": _query(), "filt": shared, "also": shared}
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
    "reused-anchor": lambda: yaml.safe_dump(_shared_envelope_doc(), sort_keys=False),
    "cyclic-anchor": lambda: family_text('&a {"k": [*a]}') + "\n",
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


def test_the_same_questioner_reply_written_longhand_is_accepted(tmp_path):
    """The paired control: the reused-anchor reply's document with the sharing broken — the
    same values, no alias — composes, both seats are called, and the discriminator is the
    one authored."""
    doc = json.loads(json.dumps(_shared_envelope_doc()))
    text = yaml.safe_dump(doc, sort_keys=False)
    assert _anchors_and_aliases(text) == []
    agent = T.FakeAgent(_fenced(text), *_seats())

    family = _author(tmp_path, agent)

    assert agent.calls == 3
    assert family["discriminator"] == doc["discriminator"]


#: Seat B's reply (call 2) with its story's text reused as its axis through an alias.
_SEAT_B_ALIASED = ("world_id: b\nrole: B\nstory: &s a story\naxis: *s\n"
                   "disposition_declared: malicious\nlabel_basis: policy-rule\noverlay: {}\n")
#: The same reply, the alias written out.
_SEAT_B_LONGHAND = ("world_id: b\nrole: B\nstory: a story\naxis: a story\n"
                    "disposition_declared: malicious\nlabel_basis: policy-rule\noverlay: {}\n")
#: Seat B's reply carrying the bomb under a key the questioner never reads — so no check of
#: the COMPOSED world would ever see it; only the loader can refuse it.
_SEAT_B_BOMB = ("world_id: b\nrole: B\nstory: a story\naxis: an axis\n"
                "disposition_declared: malicious\nlabel_basis: policy-rule\noverlay: {}\n"
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
