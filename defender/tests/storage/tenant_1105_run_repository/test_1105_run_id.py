"""`RunId`: frozen value, parse/mint bounds (206 bytes), sidecar suffixes, unforgeability."""
from __future__ import annotations

import copy
import dataclasses
import pickle

import pytest

from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H


def _ascii_id(n: int) -> str:
    """A grammar-valid, case-stable run id of exactly `n` bytes."""
    return "r" + "1" * (n - 1)


def _forged_pickle(rid: object, text: str, forged: str) -> bytes:
    """A pickle of `rid` (protocol 2, unframed) with its run-id text swapped for `forged` —
    the bytes an attacker who can write a pickle would hand back. The text is located as the
    BINUNICODE string op carrying it and re-encoded with its own length prefix."""
    blob = pickle.dumps(rid, protocol=2)
    old = text.encode("utf-8")
    new = forged.encode("utf-8")
    needle = b"X" + len(old).to_bytes(4, "little") + old
    assert needle in blob, "the pickle carries the run id's text as a string (MF-02's rebuild)"
    return blob.replace(needle, b"X" + len(new).to_bytes(4, "little") + new)


def _forged_in_place(rid: object, text: str, forged: str, protocol: int) -> bytes:
    """A pickle of `rid` at `protocol` with its run-id text overwritten by `forged`, which has
    the same UTF-8 length, so every protocol's own string op (protocol 0's text line, BINUNICODE,
    SHORT_BINUNICODE) stays well formed. Fails the test if the stream does not carry the text
    exactly once."""
    blob = pickle.dumps(rid, protocol=protocol)
    old, new = text.encode("utf-8"), forged.encode("utf-8")
    if len(old) != len(new) or blob.count(old) != 1:
        pytest.fail(f"protocol {protocol}: the pickle does not carry the run id's text once "
                    f"(MF-02's rebuild needs it): {blob.count(old)} copies")
    return blob.replace(old, new)


def test_1105_run_id_is_a_frozen_value_ordered_by_its_text_and_never_equal_to_a_str():
    from defender.run_repository import RunId

    a = RunId.parse("a")
    assert str(a) == "a", f"str(RunId.parse('a')) is {str(a)!r}"
    assert not isinstance(a, str), "a RunId is not a str subclass"
    for attr in ("text", "_text", "value", "anything"):
        err = H.raised(setattr, a, attr, "b")
        assert err is not None, f"assigning {attr!r} on a RunId did not raise"
    assert str(a) == "a"
    for twin in (copy.copy(a), copy.deepcopy(a), pickle.loads(pickle.dumps(a))):
        assert H.is_a(twin, RunId)
        assert twin == a
        assert hash(twin) == hash(a)
    b, c = RunId.parse("b"), RunId.parse("c")
    assert RunId.parse("a") == a
    assert a != b
    assert a < b < c
    assert sorted([c, a, b]) == [a, b, c]
    assert len({a, RunId.parse("a"), b}) == 2
    assert (a == "a") is False
    assert (a == "a") is False
    assert (a != "a") is True
    keys = {a: 1, "a": 2}
    assert len(keys) == 2
    assert keys[a] == 1
    assert keys["a"] == 2


def test_1105_run_id_parse_refuses_what_refuse_bad_run_id_refuses_and_any_non_str_as_run_refused():
    from defender._run_id import refuse_bad_run_id
    from defender.run_repository import RunId, RunRefused

    for good in ("r1", "2026-x.y_z", _ascii_id(H.RUN_ID_BOUND)):
        assert str(RunId.parse(good)) == good
    refused_today = ("", "_episodes", "_tenant.json", "../x", "a/b", ".hidden", "r1\n", "Run1")
    for text in refused_today:
        assert isinstance(H.raised(refuse_bad_run_id, text), ValueError), text  # today's rule
    for bad in (*refused_today, 5, None, b"r1"):
        err = H.raised(RunId.parse, bad)
        assert H.is_a(err, RunRefused), f"RunId.parse({bad!r}) raised {err!r}"
        assert not isinstance(err, (ValueError, AttributeError)), (
            f"RunId.parse({bad!r}) raised {type(err).__name__}, which an except for "
            "ValueError/AttributeError would catch — the one error type is RunRefused")
    err = H.raised(RunId.mint, 5, clock=H.fixed_clock)
    assert H.is_a(err, RunRefused), err
    assert not isinstance(err, (ValueError, AttributeError)), err


def test_1105_run_id_parse_admits_206_bytes_and_refuses_207():
    from defender import _io
    from defender.run_repository import RunId, RunRefused

    assert str(RunId.parse(_ascii_id(206))) == _ascii_id(206)
    err = H.raised(RunId.parse, _ascii_id(207))
    assert H.is_a(err, RunRefused), f"a 207-byte id was not refused: {err!r}"
    # The census, derived from the real constants rather than restated (R4-35).
    from defender import run_repository as rr

    # #1235 F2 adds the case pointer's sidecar and retires the oracle-held one; neither is
    # longer than the accounting suffix, so the bound stays 206.
    suffixes = (rr.RUN_END_SIDECAR_SUFFIX, rr.SCRUB_VERDICT_SUFFIX,
                rr.ACCOUNTING_FAILURES_SUFFIX, rr.TICKET_WRITE_SUFFIX,
                rr.SESSION_POINTER_SUFFIX)
    assert sorted(suffixes) == sorted(H.SIDECAR_SUFFIXES)
    staged_tail = len(_io.staged_leaf("x")) - len("x")
    assert staged_tail == len(H.STAGED_TAIL) == 24
    assert 255 - max(len(s.encode()) for s in suffixes) - staged_tail == H.RUN_ID_BOUND
    assert "206" in (H.PACKAGE / "_id.py").read_text(encoding="utf-8"), (
        "the bound is kept as the literal 206 in the RunId submodule (NM-07)")


def test_1105_run_id_mint_folds_then_bounds_the_id_and_never_truncates():
    from defender.run_repository import RunId, RunRefused

    assert len(H.MINT_PREFIX) == 17
    assert str(RunId.mint("Alert-X", clock=H.fixed_clock)) == f"{H.MINT_PREFIX}alert-x"
    at_bound = RunId.mint("a" * 189, clock=H.fixed_clock)
    assert str(at_bound) == H.MINT_PREFIX + "a" * 189
    assert len(str(at_bound)) == 206
    folded = RunId.mint("ß" * 94, clock=H.fixed_clock)
    assert str(folded) == H.MINT_PREFIX + "ss" * 94
    assert len(str(folded).encode()) == 205
    for over in ("a" * 190, "ß" * 95):
        err = H.raised(RunId.mint, over, clock=H.fixed_clock)
        assert H.is_a(err, RunRefused), f"mint({len(over)} x {over[0]!r}) gave {err!r}"


def test_1105_run_id_parse_admits_a_sidecar_suffixed_id():
    from defender.run_repository import RunId

    names = [f"r1{s}" for s in H.SIDECAR_SUFFIXES] + [f"r1.run-end.json{H.STAGED_TAIL}"]
    for name in names:
        assert str(RunId.parse(name)) == name, name


def test_1105_run_id_is_unforgeable_every_copy_route_reparses_and_new_and_subclassing_are_refused():
    from defender.run_repository import RunId, RunRefused

    text = "abcd" * 50  # 200 bytes: room to forge each payload below in place
    rid = RunId.parse(text)
    assert pickle.loads(pickle.dumps(rid, protocol=2)) == rid, "a valid RunId round-trips"
    for forged in ("../x", "x" * 300, "_episodes"):
        payload = _forged_pickle(rid, text, forged)
        err = H.raised(pickle.loads, payload)
        assert H.is_a(err, RunRefused), f"an unpickled {forged[:12]!r}... gave {err!r}"
    for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
        assert pickle.loads(pickle.dumps(rid, protocol=protocol)) == rid, (
            f"protocol {protocol}: a valid RunId does not round-trip")
        for forged in ("../" + "x" * 197, "A" * 200, "_" + "x" * 199):
            err = H.raised(pickle.loads, _forged_in_place(rid, text, forged, protocol))
            assert H.is_a(err, RunRefused), (
                f"protocol {protocol}: an unpickled {forged[:12]!r}... gave {err!r}")
    assert copy.copy(rid) == rid, "copy.copy does not give an equal RunId"
    assert copy.deepcopy(rid) == rid, "copy.deepcopy does not give an equal RunId"
    routes = [("dataclasses.replace", dataclasses.replace)]
    if hasattr(copy, "replace"):  # Python 3.13+
        routes.append(("copy.replace", copy.replace))
    for name, replace in routes:
        got = H.raised(replace, rid)
        if isinstance(got, TypeError):
            continue  # the route does not exist for RunId: nothing to forge through
        assert got is None, f"{name}(rid) raised {got!r}"
        assert replace(rid) == rid, f"{name}(rid) does not give an equal RunId"
        for f in dataclasses.fields(rid) if dataclasses.is_dataclass(rid) else ():
            err = H.raised(replace, rid, **{f.name: "../x"})
            assert H.is_a(err, RunRefused), f"{name}(rid, {f.name}='../x') gave {err!r}"
    err = H.raised(RunId.__new__, RunId)
    assert H.is_a(err, RunRefused), f"RunId.__new__(RunId) gave {err!r}"
    err = H.raised(type, "Forged", (RunId,), {})
    assert H.is_a(err, RunRefused), f"subclassing RunId gave {err!r}"
