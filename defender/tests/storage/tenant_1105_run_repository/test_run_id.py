"""`RunId`: built only by `parse`/`mint`, canonical UUID text only, a frozen value, unforgeable."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_runs_base

import copy
import dataclasses
import pickle

import pytest

from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H
from defender.tests.storage.ids_1187 import _spec1187 as S


#: Three canonical uuid4 texts in text order, for the value-type tests that need distinct,
#: ordered ids.
U_A = "10000000-0000-4000-8000-000000000000"
U_B = "20000000-0000-4000-8000-000000000000"
U_C = "30000000-0000-4000-8000-000000000000"


def _ascii_id(n: int) -> str:
    """A grammar-valid, case-stable run id of exactly `n` bytes."""
    return "r" + "1" * (n - 1)


def _forged_pickle(rid: object, text: str, forged: str) -> bytes:
    """A pickle of `rid` (protocol 2, unframed) with its run-id text swapped for `forged`: the
    BINUNICODE op carrying the text is re-encoded with its own length prefix."""
    blob = pickle.dumps(rid, protocol=2)
    old = text.encode("utf-8")
    new = forged.encode("utf-8")
    needle = b"X" + len(old).to_bytes(4, "little") + old
    assert needle in blob, "precondition: the pickle does not carry the run id's text as a string"
    return blob.replace(needle, b"X" + len(new).to_bytes(4, "little") + new)


def _forged_in_place(rid: object, text: str, forged: str, protocol: int) -> bytes:
    """A pickle of `rid` at `protocol` with its run-id text overwritten by `forged`, which has
    the same UTF-8 length, so every protocol's own string op (protocol 0's text line, BINUNICODE,
    SHORT_BINUNICODE) stays well formed."""
    blob = pickle.dumps(rid, protocol=protocol)
    old, new = text.encode("utf-8"), forged.encode("utf-8")
    if len(old) != len(new) or blob.count(old) != 1:
        pytest.fail(f"protocol {protocol}: the pickle does not carry the run id's text once "
                    f"(MF-02's rebuild needs it): {blob.count(old)} copies")
    return blob.replace(old, new)


def test_1105_run_id_is_built_only_by_parse_and_mint():
    """`parse` and `mint()` (a bare UUID) return a `RunId`; a direct `RunId(...)` call, with any
    arguments, raises `RunRefused`."""
    from defender.records import RunId, RunRefused

    parsed = RunId.parse(S.SAMPLE_UUID)
    minted = RunId.mint()
    assert str(parsed) == S.SAMPLE_UUID
    assert S.is_canonical_uuid(str(minted)), str(minted)
    assert H.is_a(parsed, RunId)
    assert H.is_a(minted, RunId)
    for args, kwargs in (((), {}), (("r1",), {}), (("r1", "r2"), {}), ((), {"text": "r1"})):
        err = H.raised(RunId, *args, **kwargs)
        assert H.is_a(err, RunRefused), f"RunId(*{args}, **{kwargs}) raised {err!r}"


def test_1105_run_id_is_a_frozen_value_ordered_by_its_text_and_never_equal_to_a_str():
    """A `RunId` is frozen, not a `str` subclass, and survives copies and pickles equal to the
    original; it compares, hashes and sorts by its text, and never equals a `str` (a dict keeps
    the two as separate keys)."""
    from defender.records import RunId

    a = RunId.parse(U_A)
    assert str(a) == U_A, f"str(RunId.parse(U_A)) is {str(a)!r}"
    assert not isinstance(a, str), "a RunId is not a str subclass"
    for attr in ("text", "_text", "value", "anything"):
        err = H.raised(setattr, a, attr, U_B)
        assert err is not None, f"assigning {attr!r} on a RunId did not raise"
    assert str(a) == U_A
    for twin in (copy.copy(a), copy.deepcopy(a), pickle.loads(pickle.dumps(a))):
        assert H.is_a(twin, RunId)
        assert twin == a
        assert hash(twin) == hash(a)
    b, c = RunId.parse(U_B), RunId.parse(U_C)
    assert RunId.parse(U_A) == a
    assert a != b
    assert a < b < c
    assert sorted([c, a, b]) == [a, b, c]
    assert len({a, RunId.parse(U_A), b}) == 2
    assert (a == U_A) is False
    assert (U_A == a) is False  # noqa: SIM300 — the reflected order is what is under test
    assert (a != U_A) is True
    keys = {a: 1, U_A: 2}
    assert len(keys) == 2
    assert keys[a] == 1
    assert keys[U_A] == 2


def test_1105_run_id_parse_refuses_what_refuse_bad_run_id_refuses_and_any_non_str_as_run_refused():
    """A bad, non-case-stable or non-str id is `RunRefused`, never a `ValueError` or
    `AttributeError`; a canonical UUID parses."""
    from defender.records import RunId, RunRefused

    for good in (S.SAMPLE_UUID, S.new_id()):
        assert str(RunId.parse(good)) == good
    refused_today = ("", "_episodes", "_tenant.json", "../x", "a/b", ".hidden", "r1\n", "Run1")
    for bad in (*refused_today, 5, None, b"r1"):
        err = H.raised(RunId.parse, bad)
        assert H.is_a(err, RunRefused), f"RunId.parse({bad!r}) raised {err!r}"
        assert not isinstance(err, (ValueError, AttributeError)), (
            f"RunId.parse({bad!r}) raised a {type(err).__name__}")


def test_1105_run_id_parse_refuses_206_and_207_byte_ids_and_defines_no_bound():
    """Ids of 206 and 207 bytes are both `RunRefused` (neither is a UUID) and `_run_id` defines
    no bound constant."""
    from defender.records import _run_id
    from defender.records import RunId, RunRefused

    for size in (206, 207):
        err = H.raised(RunId.parse, _ascii_id(size))
        assert H.is_a(err, RunRefused), f"a {size}-byte id was not refused: {err!r}"
    assert not hasattr(_run_id, "RUN_ID_MAX_BYTES"), "the 206-byte bound's constant survives"


def test_1105_run_id_mint_refuses_a_label_and_mints_a_uuid():
    from defender.records import RunId

    for label in ("Alert-X", "a" * 189, "ß" * 94, "a" * 190, "ß" * 95):
        assert H.raised(RunId.mint, label) is not None, f"mint accepted the label {label[:12]!r}"
    assert S.is_canonical_uuid(str(RunId.mint()))


def test_1105_run_id_parse_refuses_a_sidecar_suffixed_id():
    """A UUID with a sidecar suffix, or in the staged shape, is no `RunId`, only the bare UUID
    is (the sidecar clause belongs to the repository's open and run setup)."""
    from defender.records import RunId, RunRefused

    run_id = S.new_id()
    assert str(RunId.parse(run_id)) == run_id
    names = [f"{run_id}{s}" for s in H.SIDECAR_SUFFIXES] + [
        f"{run_id}.run-end.json{H.STAGED_TAIL}"]
    for name in names:
        err = H.raised(RunId.parse, name)
        assert H.is_a(err, RunRefused), f"RunId.parse({name!r}) gave {err!r}"


def test_1105_the_handle_constructors_keep_taking_str_and_todays_run_id_check(tmp_path):
    """`Run.under` takes the id as a `str` or a `RunId` and admits it by `RunId.parse`: a bad or
    upper-case id is `RunRefused`, so no handle exists for a run whose sidecars could not be named."""
    import uuid

    from defender.records import Run, RunId, RunRefused

    runs = tmp_path / H.T_ID / "runs"
    runs.mkdir(parents=True)
    r2, r3 = str(uuid.uuid4()), str(uuid.uuid4())
    under = Run.under(fixture_runs_base(runs), r2, tenant_id=H.T_ID)
    assert under.run_dir == runs / r2
    assert under.tenant_id == H.T_ID
    assert Run.under(fixture_runs_base(runs), RunId.parse(r3)).run_dir == runs / r3, "a RunId is taken as is"
    assert not (runs / "_tenant.json").exists()
    for bad in ("Bad Name", "UPPER", "r1", "20260101t000000z-x", r2.upper(), "a" * 207):
        err = H.raised(Run.under, runs, bad)
        assert H.is_a(err, RunRefused), f"{bad[:20]!r}: {err!r}"


def test_1105_run_id_is_unforgeable_every_copy_route_reparses_and_new_and_subclassing_are_refused():
    """Every copy route (unpickling at each protocol, `copy`, `deepcopy`, `dataclasses.replace`,
    `copy.replace`) rebuilds through `RunId.parse`, so a forged pickle is `RunRefused` at load;
    `RunId.__new__` and subclassing are refused too. A valid `RunId` round-trips by each route."""
    from defender.records import RunId, RunRefused

    text = S.SAMPLE_UUID  # 36 bytes: each in-place forgery below is exactly as long
    rid = RunId.parse(text)
    assert pickle.loads(pickle.dumps(rid, protocol=2)) == rid, "a valid RunId round-trips"
    for forged in ("../x", "x" * 300, "_episodes"):
        payload = _forged_pickle(rid, text, forged)
        err = H.raised(pickle.loads, payload)
        assert H.is_a(err, RunRefused), f"an unpickled {forged[:12]!r}... gave {err!r}"
    for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
        assert pickle.loads(pickle.dumps(rid, protocol=protocol)) == rid, (
            f"protocol {protocol}: a valid RunId does not round-trip")
        n = len(text.encode("utf-8"))
        for forged in ("../" + "x" * (n - 3), text.upper(), "_" + "x" * (n - 1)):
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
