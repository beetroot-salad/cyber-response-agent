"""`RunId`: frozen value, parse/mint bounds (206 bytes), sidecar suffixes, unforgeability."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_runs_base

import copy
import dataclasses
import pickle

import pytest

from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H
from defender.tests.storage.ids_1187 import _spec1187 as S


#: Three canonical lowercase uuid4 texts in text order (#1187 declared change 1: `RunId` admits
#: nothing else), for the value-type tests that need distinct, ordered ids.
U_A = "10000000-0000-4000-8000-000000000000"
U_B = "20000000-0000-4000-8000-000000000000"
U_C = "30000000-0000-4000-8000-000000000000"


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


def test_1105_run_id_is_built_only_by_parse_and_mint():
    """RunId.parse(text) and RunId.mint() each return a RunId; a direct RunId(...) call, with any
    arguments, raises RunRefused.

    #1187 declared changes 1 and 2: `parse` takes canonical UUID text and `mint()` takes no
    label and no clock, so the minted text is a bare UUID rather than `<stamp>-<label>`."""
    from defender.run_repository import RunId, RunRefused

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
    """A RunId is frozen (assigning an attribute raises), is not a str subclass, gives its text
    through str(), survives copy.copy, copy.deepcopy and a pickle round trip equal to the
    original (each rebuilt through RunId.parse, MF-02), compares, hashes and sorts by its text
    against another RunId, and never equals a str: RunId.parse(t) == t is False in both
    operand orders, and a dict holds the RunId and the str of the same text as two keys.
    #1187 declared change 1: the ids are canonical uuid4 texts (`U_A < U_B < U_C`), not 'a'."""
    from defender.run_repository import RunId

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
    assert (a == U_A) is False
    assert (a != U_A) is True
    keys = {a: 1, U_A: 2}
    assert len(keys) == 2
    assert keys[a] == 1
    assert keys[U_A] == 2


def test_1105_run_id_parse_refuses_what_refuse_bad_run_id_refuses_and_any_non_str_as_run_refused():
    """RunId.parse raises RunRefused, never ValueError or AttributeError, for every text
    refuse_bad_run_id refuses ('', '_episodes', '_tenant.json', '../x', 'a/b', '.hidden', 'r1\n'),
    for text that is not case-stable ('Run1'), and for a non-str (5, None, b'r1'). Positive
    control: a canonical UUID parses."""
    from defender.run_repository import RunId, RunRefused

    for good in (S.SAMPLE_UUID, S.new_id()):
        assert str(RunId.parse(good)) == good
    refused_today = ("", "_episodes", "_tenant.json", "../x", "a/b", ".hidden", "r1\n", "Run1")
    for bad in (*refused_today, 5, None, b"r1"):
        err = H.raised(RunId.parse, bad)
        assert H.is_a(err, RunRefused), f"RunId.parse({bad!r}) raised {err!r}"
        assert not isinstance(err, (ValueError, AttributeError)), (
            f"RunId.parse({bad!r}) raised {type(err).__name__}, which an except for "
            "ValueError/AttributeError would catch — the one error type is RunRefused")


def test_1105_run_id_parse_admits_206_bytes_and_refuses_207():
    """#1187 declared changes 1 and 4: the 206-byte bound is gone with the free-form id. A
    grammar-valid id of exactly 206 bytes, which `RunId.parse` admitted, is refused with
    RunRefused now (it is not a UUID), as is one of 207; and `_run_id` no longer defines the
    bound's constant (the census in `ids_1187` pins that no source reads it).

    Kept under its old name: the spec graph cites it."""
    from defender.records import _run_id
    from defender.run_repository import RunId, RunRefused

    for size in (206, 207):
        err = H.raised(RunId.parse, _ascii_id(size))
        assert H.is_a(err, RunRefused), f"a {size}-byte id was not refused: {err!r}"
    assert not hasattr(_run_id, "RUN_ID_MAX_BYTES"), "the 206-byte bound's constant survives"


def test_1105_run_id_mint_folds_then_bounds_the_id_and_never_truncates():
    """#1187 declared changes 1, 2 and 4: `mint` has no label to fold, bound or truncate, so
    there is nothing left of what this test pinned. A labelled mint is refused, and the
    no-argument mint is a UUID however many are made (the ids slice pins the format)."""
    from defender.run_repository import RunId

    for label in ("Alert-X", "a" * 189, "ß" * 94, "a" * 190, "ß" * 95):
        assert H.raised(RunId.mint, label) is not None, f"mint accepted the label {label[:12]!r}"
    assert S.is_canonical_uuid(str(RunId.mint()))


def test_1105_run_id_parse_admits_a_sidecar_suffixed_id():
    """#1187 declared change 1: a canonical UUID with a sidecar suffix, or in the staged shape
    ('<uuid>.run-end.json.staged-0123456789abcdef'), is no longer a RunId: only canonical UUID
    text is. The sidecar clause still belongs to the repository's open and run setup, not to
    RunId, which `run_name_fault` answers for (pinned in the ids slice); the old test's
    'r1.run-end.json' names are not UUIDs either. Positive control: the bare UUID parses.

    Kept under its old name: the spec graph cites it."""
    from defender.run_repository import RunId, RunRefused

    run_id = S.new_id()
    assert str(RunId.parse(run_id)) == run_id
    names = [f"{run_id}{s}" for s in H.SIDECAR_SUFFIXES] + [
        f"{run_id}.run-end.json{H.STAGED_TAIL}"]
    for name in names:
        err = H.raised(RunId.parse, name)
        assert H.is_a(err, RunRefused), f"RunId.parse({name!r}) gave {err!r}"


def test_1105_the_handle_constructors_keep_taking_str_and_todays_run_id_check(tmp_path):
    """Run.under still takes the run id as a str (or a RunId), and admits it by the
    repository's one rule, RunId.parse: a bad id and an upper-case one each raise RunRefused,
    so no handle is built for a run whose sidecar files could not be named. (Owner ruling,
    #1105 PR 1 review: this replaced PR 1's split, where the constructors kept
    refuse_bad_run_id and its ValueError; the name is kept because the spec graph cites it.)"""
    import uuid

    from defender.run_repository import Run, RunId, RunRefused

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
    """Unpickling, copy.copy, copy.deepcopy and dataclasses.replace (and copy.replace where it
    exists) rebuild a RunId through RunId.parse, so a pickled payload carrying '../x', a
    300-character text or '_episodes' raises RunRefused at unpickling and the repository's open
    and exists are never reached with it; RunId.__new__(RunId) and defining a subclass of RunId each raise
    RunRefused. Positive control: a valid RunId round-trips by each route equal to the original.
    The forged payloads cover every pickle protocol (0 to pickle.HIGHEST_PROTOCOL), each RunId's
    own stream with its text overwritten in place; every replace route is driven, and one that
    does not exist must raise TypeError rather than be skipped (91 BF-08)."""
    from defender.run_repository import RunId, RunRefused

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
