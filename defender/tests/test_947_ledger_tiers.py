"""#947 Part B — the ledger's two family tiers, and the file each of them lives in."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from defender._io import append_jsonl, read_jsonl_rows
from defender._episode_handle import Episode
from defender._episode_paths import BASE_FILENAME, SERVED_DIRNAME
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


@pytest.mark.parametrize("world_id", [None, "w1"])
def test_the_ledger_refuses_a_captured_row_at_its_own_door(tmp_path, world_id):
    """`record` refuses `captured` outright, whichever tier the row claims."""
    root = episode(tmp_path)
    with Episode.open(root) as ep:
        ledger = Ledger.for_world(ep, "w1")

        with pytest.raises(LedgerError, match=CAPTURED):
            ledger.record(ServedCall(
                system="cmdb", verb="get-host", params={"host": "canary-1"},
                payload_text='{"owner": "estate"}', source=CAPTURED, world_id=world_id))

        assert read_jsonl_rows(root / SERVED_DIRNAME / "w1.jsonl") == []


# 2. the primed base is a precondition, not a parameter

def test_a_ledger_without_a_primed_base_does_not_construct(tmp_path):
    """`base_path` is REQUIRED"""
    root = episode(tmp_path)

    # 1067: a missing required field on a strict pydantic dataclass raises pydantic's
    # `ValidationError`, not stdlib `@dataclass`'s `TypeError`. The demand is unchanged —
    # the constructor refuses a ledger with no capture named — and `ValidationError` ALONE
    # is what is expected: a `TypeError` here would be some other fault raised before the
    # field check (a positional-argument mismatch, a broken `__post_init__`), not this one.
    with pytest.raises(ValidationError, match="base_path"):
        Ledger(root / SERVED_DIRNAME / "w1.jsonl")


@pytest.mark.parametrize("shape", ["absent", "directory"])
def test_a_base_path_that_is_not_a_file_is_refused_at_construction(tmp_path, shape):
    """A `base_path` that is not a file is a `LedgerError` at construction."""
    root = tmp_path / "episode"
    (root / SERVED_DIRNAME).mkdir(parents=True)
    base = base_file(root)
    if shape == "directory":
        base.mkdir()

    with Episode.open(root) as ep, pytest.raises(LedgerError):
        Ledger.for_world(ep, "w1")


def test_the_primed_capture_is_never_written_to(tmp_path):
    """A world's rows go to the world's own file"""
    root = episode(tmp_path, rows=[captured("cmdb", "get-host", {"host": "canary-1"},
                                            {"owner": "estate"})])
    before = base_file(root).read_bytes()
    with Episode.open(root) as ep:
        ledger = Ledger.for_world(ep, "w1")

        ledger.record(ServedCall(
            system="cmdb", verb="list-hosts", params={}, payload_text='{"hosts": []}',
            source=BASE, world_id=None))
        ledger.record(ServedCall(
            system="cmdb", verb="list-hosts", params={}, payload_text='{"hosts": []}',
            source=PASSTHROUGH, world_id="w1"))

        assert base_file(root).read_bytes() == before, "the run appended to the primed capture"
        assert len(read_jsonl_rows(ledger.path)) == 2


# 3. what `base_payload` reads

def test_a_primed_key_is_answered_without_the_world_ever_asking(tmp_path):
    """A key the capture holds resolves out of `base.jsonl` — the world's own file is empty."""
    root = episode(tmp_path, rows=[captured("cmdb", "get-host", {"host": "canary-1"},
                                            {"owner": "estate"})])
    with Episode.open(root) as ep:
        ledger = Ledger.for_world(ep, "w1")

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
        ledger = Ledger.for_world(ep, "w1")

        assert ledger.base_payload("elastic", "query", {"limit": 5, "native_query": "x"}) is not None


def test_a_worlds_own_live_read_is_answered_from_its_own_file(tmp_path):
    """A key the capture never held, read live and recorded as `base`, answers from the world's own rows on the next ask."""
    root = episode(tmp_path)
    with Episode.open(root) as ep:
        ledger = Ledger.for_world(ep, "w1")

        ledger.record(ServedCall(
            system="cmdb", verb="get-host", params={"host": "new-9"},
            payload_text='{"owner": "live"}', source=BASE, world_id=None))

        assert ledger.base_payload("cmdb", "get-host", {"host": "new-9"}) == '{"owner": "live"}'


def test_one_siblings_live_read_is_not_served_to_another(tmp_path):
    """World B does not read World A's own rows — only the shared capture crosses between them."""
    root = episode(tmp_path)
    with Episode.open(root) as ep:
        a = Ledger.for_world(ep, "a")
        b = Ledger.for_world(ep, "b")

        a.record(ServedCall(
            system="cmdb", verb="get-host", params={"host": "new-9"},
            payload_text='{"owner": "read-by-a"}', source=BASE, world_id=None))

        assert a.base_payload("cmdb", "get-host", {"host": "new-9"}) is not None
        assert b.base_payload("cmdb", "get-host", {"host": "new-9"}) is None, (
            "world b was served world a's own live read as though it were the family's capture")


def test_the_capture_outranks_a_live_row_for_the_same_key(tmp_path):
    """A key held by BOTH the capture and the world's own file resolves to the CAPTURE."""
    root = episode(tmp_path, rows=[captured("cmdb", "get-host", {"host": "canary-1"},
                                            {"owner": "captured"})])
    with Episode.open(root) as ep:
        ledger = Ledger.for_world(ep, "w1")
        append_jsonl(ledger.path, [ServedCall(
            system="cmdb", verb="get-host", params={"host": "canary-1"},
            payload_text='{"owner": "live"}', source=BASE, world_id=None).row()])

        reopened = Ledger.for_world(ep, "w1")

        assert json.loads(reopened.base_payload("cmdb", "get-host", {"host": "canary-1"})) == {
            "owner": "captured"}


def test_a_failed_write_leaves_no_memo_behind_it(tmp_path):
    """A `record` whose append FAILS must not leave the payload live in memory."""
    root = episode(tmp_path)
    with Episode.open(root) as ep:
        ledger = Ledger.for_world(ep, "w1")
        ledger.path.mkdir(parents=True)

        with pytest.raises(OSError, match="non-plain"):
            ledger.record(ServedCall(
                system="cmdb", verb="get-host", params={"host": "canary-1"},
                payload_text='{"owner": "never landed"}', source=BASE, world_id=None))

        assert ledger.base_payload("cmdb", "get-host", {"host": "canary-1"}) is None, (
            "the payload is memoized with no row behind it — every later call for this key serves "
            "bytes the table cannot account for, and any other process serves something else")


def test_two_staged_calls_for_one_question_pair_on_the_asked_form(tmp_path):
    """`correlation_key` is computed from `asked_params`, so two worlds' staged rows PAIR."""
    asked = {"query": "FROM logs-system.auth-*"}
    rows = [
        ServedCall(system="elastic", verb="esql", params={"query": f"FROM wv-{w}-logs-system.auth-"},
                   payload_text="{}", source=STAGED, world_id=w, asked_params=asked)
        for w in ("a", "b")
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
        ledger = Ledger.for_world(ep, "w1")

        assert ledger.base_payload("cmdb", "get-host", {"host": "canary-1"}) is None


def test_a_world_owned_row_never_answers_for_the_family_even_when_it_is_first(tmp_path):
    """A world's OWN row is not the family's answer, whatever order the file happens to hold."""
    root = episode(tmp_path)
    path = root / SERVED_DIRNAME / "w1.jsonl"
    call = dict(system="cmdb", verb="get-host", params={"host": "canary-1"})
    append_jsonl(path, [
        ServedCall(payload_text='{"owner": "world a made this"}', source="patched",
                   world_id="w1", **call).row(),
        ServedCall(payload_text='{"owner": "estate"}', source=BASE, world_id=None, **call).row(),
    ])

    with Episode.open(root) as ep:
        ledger = Ledger.for_world(ep, "w1")

        assert json.loads(ledger.base_payload("cmdb", "get-host", {"host": "canary-1"})) == {
            "owner": "estate"}


def test_a_duplicate_inside_one_file_resolves_to_the_first_row(tmp_path):
    """Two rows for one key resolve to the FIRST, in memory and on a rebuild alike."""
    root = episode(tmp_path)
    with Episode.open(root) as ep:
        ledger = Ledger.for_world(ep, "w1")
        call = dict(system="cmdb", verb="get-host", params={"host": "canary-1"},
                    source=BASE, world_id=None)

        ledger.record(ServedCall(payload_text='{"owner": "first"}', **call))
        ledger.record(ServedCall(payload_text='{"owner": "second"}', **call))

        assert ledger.base_payload("cmdb", "get-host", {"host": "canary-1"}) \
            == Ledger.for_world(ep, "w1").base_payload(
                "cmdb", "get-host", {"host": "canary-1"}) \
            == '{"owner": "first"}'


# 4. `for_world`: one file per world, under the episode's own capture

def test_for_world_opens_this_worlds_file_beside_the_shared_capture(tmp_path):
    """`for_world` is the naming rule"""
    root = episode(tmp_path, rows=[captured("cmdb", "get-host", {"host": "canary-1"},
                                            {"owner": "estate"})])

    with Episode.open(root) as ep:
        ledger = Ledger.for_world(ep, "w1")

        assert ledger.path == root / SERVED_DIRNAME / "w1.jsonl"
        assert ledger.base_payload("cmdb", "get-host", {"host": "canary-1"}) is not None
        ledger.record(ServedCall(
            system="cmdb", verb="get-host", params={"host": "canary-1"},
            payload_text='{"owner": "estate"}', source=PASSTHROUGH, world_id="w1"))
        assert [r["world_id"] for r in read_jsonl_rows(root / SERVED_DIRNAME / "w1.jsonl")] == ["w1"]


def test_for_world_refuses_an_episode_that_was_never_primed(tmp_path):
    """`for_world` over an episode with no `served/base.jsonl` is refused."""
    root = tmp_path / "episode"
    (root / SERVED_DIRNAME).mkdir(parents=True)

    with Episode.open(root) as ep, pytest.raises(LedgerError):
        Ledger.for_world(ep, "w1")


@pytest.mark.parametrize("world_id", ["", ".", "..", "a/b", "../base", "sub/w1", "w1/"])
def test_for_world_refuses_a_world_id_that_is_not_a_filename(tmp_path, world_id):
    """A world id that is not a single filename component is refused, not sanitized."""
    root = episode(tmp_path)

    with Episode.open(root) as ep, pytest.raises(LedgerError):
        Ledger.for_world(ep, world_id)
