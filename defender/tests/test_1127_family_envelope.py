"""#1127 M4 — the branch review refuses a too-deep discriminator envelope at manifest load.

The discriminator's `envelope` is a model-authored call (the questioner writes `family.yaml`),
and its `params` reach the branch ledger as a row's `params`. YAML has no nesting bound (C7)
and an anchor can even make the value cyclic (C10). `review.replay_one` runs the adapter BEFORE
`book.record`, so the ledger's own backstop (M3) would only refuse after the call already ran.

So `parse_family` refuses a discriminator whose `envelope.params` is too deep by M1's own
predicate, with a `FamilyError` naming the limit. Because the check sits in `parse_family`, it
also refuses a manifest already on disk — which is why every arm here goes through
`load_family(path)`, the real reader `run.py` and `episode.py` call, over YAML text rather than
a Python dict: the anchor case only exists in the text.

RED today: `parse_family` checks only that the discriminator is a non-empty mapping, so every
refusal arm loads. The depth-98/99 arms are the positive controls and pass today.
"""
from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from defender import _yaml
from defender._io import JSON_NESTING_LIMIT
from defender.runtime.branch._family import FamilyError, load_family, parse_family
from defender.tests import _triplet_947 as T
from defender.tests.test_1127_params_nesting_limit import (
    dict_chain,
    list_chain,
    run_to_completion,
)

#: The deepest params map a readable ledger row can carry (the map counted as 1).
LIMIT = JSON_NESTING_LIMIT - 1

_PLACEHOLDER = "__ENVELOPE_PARAMS__"


def _query() -> str:
    """The fixture's own envelope query, spent rather than re-spelled."""
    return T.family_doc()["discriminator"]["envelope"]["params"]["query"]


def envelope_params(depth: int, chain: Callable[[int], Any] = dict_chain) -> dict:
    """The fixture's real envelope params plus one field, nested `depth` deep with the params
    map itself counted."""
    return {"query": _query(), "filt": chain(depth - 1)}


def manifest(tmp_path: Path, params_yaml: str) -> Path:
    """A real `family.yaml` whose `discriminator.envelope.params` is `params_yaml`, spliced in
    as YAML text. JSON is YAML flow style, so every other field is the shared fixture's own
    document; only the envelope's params are this arm's."""
    doc = T.family_doc()
    doc["discriminator"]["envelope"]["params"] = _PLACEHOLDER
    text = json.dumps(doc).replace(json.dumps(_PLACEHOLDER), params_yaml)
    path = tmp_path / "family.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def _names_the_limit(message: str) -> bool:
    from defender.scripts.gather_tools.record_query import PARAMS_NESTING_LIMIT

    return re.search(rf"(?<!\d){PARAMS_NESTING_LIMIT}(?!\d)", message) is not None


@pytest.mark.parametrize("depth", [LIMIT - 1, LIMIT])
def test_an_envelope_at_or_under_the_limit_loads_whole(tmp_path, depth):
    """The positive control: at the limit the manifest loads, and the envelope's params are
    the ones authored — whole, not cut."""
    params = envelope_params(depth)

    family = load_family(manifest(tmp_path, json.dumps(params)))

    assert family.discriminator["envelope"]["params"] == params


@pytest.mark.parametrize(("depth", "chain"), [
    (LIMIT + 1, dict_chain), (LIMIT + 50, dict_chain), (LIMIT + 1, list_chain),
], ids=["one-past-dict", "far-past-dict", "one-past-list"])
def test_an_envelope_past_the_limit_refuses_the_whole_family(tmp_path, depth, chain):
    """M4: a too-deep envelope refuses the manifest — the whole family, with a `FamilyError`
    naming the limit — so the review never runs a call whose ledger row could not be read.

    Lists count as levels exactly as mappings do (M1 mirrors the cleaner)."""
    path = manifest(tmp_path, json.dumps(envelope_params(depth, chain)))

    with pytest.raises(FamilyError) as refused:
        load_family(path)

    assert _names_the_limit(str(refused.value)), \
        f"the refusal does not name the limit: {refused.value}"


def test_a_cyclic_envelope_built_by_a_yaml_anchor_is_refused_and_the_load_terminates(tmp_path):
    """C10: a YAML anchor whose body aliases itself loads as a CYCLIC value. M1's walk stops
    once past the limit, so the check terminates and refuses it — rather than letting through a
    value `json_safe` recurses on forever the moment anything tries to key or record it."""
    path = manifest(tmp_path, '&a {"k": [*a]}')
    doc = _yaml.safe_load(path.read_text(encoding="utf-8"))
    params = doc["discriminator"]["envelope"]["params"]
    assert params["k"][0] is params, "the spliced anchor did not load as a cycle"

    with pytest.raises(FamilyError) as refused:
        run_to_completion(lambda: load_family(path))

    assert _names_the_limit(str(refused.value)), \
        f"the refusal does not name the limit: {refused.value}"


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


def test_an_envelope_that_reuses_a_yaml_anchor_loads(tmp_path):
    """A reused anchor is the ordinary way to repeat a block in YAML, and it makes a SHARED
    reference, not a cycle. The envelope stays shallow, so the manifest must load — a check
    that called any container seen twice "too deep" would refuse it. The cyclic arm above is
    the complementary condition on the same splice."""
    path = manifest(tmp_path, '{"query": ' + json.dumps(_query())
                    + ', "a": &h {"host": "x"}, "b": *h, "c": [*h]}')
    doc = _yaml.safe_load(path.read_text(encoding="utf-8"))
    params = doc["discriminator"]["envelope"]["params"]
    assert params["a"] is params["b"], "the spliced anchor was not reused"

    family = run_to_completion(lambda: load_family(path))

    assert family.discriminator["envelope"]["params"] == {
        "query": _query(), "a": {"host": "x"}, "b": {"host": "x"}, "c": [{"host": "x"}]}
