"""#1366 (repair round 9, G6 G7): the guards of the operator's write commands, one test per family.

G6 (O5, O8, P5): every write command names the version it replaces (`--replaces N`, `--for-version N`); when another
operator's write has moved the current version past N, the command is refused, names the version that is current, and
changes nothing stored. One test, parametrized over every write command and over the ways the current version can
move: a base move (the credential generation rises) and a settings-only edit or a disable (the generation stays), for a
system; a rewrite and a delete-and-recreate, for the case record. `set-credentials` is asked twice: with the move
already made (the up-front check), and with the move landing while the credentials are being written (the re-read).

G7 (O4, P1, P2, H2, DC8): what the operator's input channels can yield is refused unless it is declared.
(a) any key a `config.env` line can spell (`tenant_settings.assignments` yields the text before the first `=`:
lower case, hyphens, dots, non-ASCII, a case variant of a declared key) that the adapter does not declare is refused,
naming the system and the key, and is stored nowhere, at `set-system` and at `import`; (b) a `set-credentials` file
that is not one JSON object whose keys are exactly `kind` and `fields` is refused and writes nothing to the KV.
"""
from __future__ import annotations

import asyncio
import json
import random
import threading
from collections.abc import Callable
from typing import Any

import pytest

from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — the fixture
from defender.tests.support.tenancy import _systems1366 as R
from defender.tests.tenancy.tenant_1108_p4 import test_system_records_1366 as W
from defender.tests.tenancy.tenant_1108_p4._support import published_tenant

IDENTITY_CONFIG, IDENTITY_ACCESS = R.FIXTURE_FOLDERS["identity"]
CMDB_CONFIG, CMDB_ACCESS = R.FIXTURE_FOLDERS["cmdb"]


class _HookKv(R.KvStandIn):
    """The KV stand-in; `on_write`, when set, runs once during the first write it is sent (another operator moving the
    system while the credentials are being stored)."""

    def __init__(self) -> None:
        super().__init__()
        self.on_write: Callable[[], None] | None = None

    def _handle(self, request: Any) -> Any:
        if request.method in ("POST", "PUT") and self.on_write is not None:
            hook, self.on_write = self.on_write, None
            hook()
        return super()._handle(request)


@pytest.fixture
def guarded(tmp_path, data_root, migrated_database, capsys, monkeypatch):  # noqa: F811 — the imported fixture
    """The fixture tenant, imported, with an operator whose KV stand-in can be hooked."""
    kv = _HookKv()
    with published_tenant(tmp_path / "forge", root=data_root, files=R.import_files()) as tenant:
        op = W._operator(tenant, migrated_database, tmp_path, capsys, monkeypatch, kv=kv)
        rc, said = op.import_()
        assert rc == 0, said
        yield op


def _other_operator(op: R.Operator, call: Callable[[Any], Any]) -> None:
    """Another operator's write: `call(store)` through the write door, on a thread of its own (the caller may be inside
    a running event loop)."""
    failed: list[BaseException] = []

    def target() -> None:
        try:
            asyncio.run(W._door(op, call))
        except BaseException as e:  # noqa: BLE001 — surfaced to the test thread
            failed.append(e)
    thread = threading.Thread(target=target)
    thread.start()
    thread.join(60)
    assert not failed, failed


def _move_system(op: R.Operator, how: str) -> None:
    """Identity from version 1 to version 2 by another operator: a new base (generation 1 -> 2), a settings edit alone,
    or a disable (both keep generation 1)."""
    new = {"base": (IDENTITY_CONFIG, R.bearer_access("http://identity.moved:8005"), True),
           "settings": ({"IDENTITY_TIMEOUT_SEC": "20"}, IDENTITY_ACCESS, True),
           "disable": (IDENTITY_CONFIG, IDENTITY_ACCESS, False)}[how]

    async def put(store: Any) -> None:
        await store.put_system(op.tid, "identity", replaces=1, adapter="identity", enabled=new[2], settings=dict(new[0]),
                               access=new[1], author="other operator")
    _other_operator(op, put)


def _move_case(op: R.Operator, how: str) -> None:
    """The case record from version 1 to 2 (rewritten) or to 3 (deleted, then written again)."""
    async def move(store: Any) -> None:
        if how == "delete-recreate":
            await store.delete_case(op.tid, replaces=1, author="other operator")
        await store.put_case(op.tid, replaces=1 if how == "rewrite" else 2, system_id=R.FIXTURE_CASE_SYSTEM,
                             comment_body="{disposition} (moved)", author="other operator")
    _other_operator(op, move)


SYSTEM_MOVES = ("base", "settings", "disable")
CASE_MOVES = ("rewrite", "delete-recreate")
WRITES = [
    *((command, move) for command in ("set-system", "delete-system", "set-credentials", "set-credentials-while-written")
      for move in SYSTEM_MOVES),
    *((command, move) for command in ("set-case", "delete-case") for move in CASE_MOVES),
]


@pytest.mark.postgres
@pytest.mark.parametrize(("command", "move"), WRITES, ids=[f"{c}-{m}" for c, m in WRITES])
def test_1366_o5_a_write_that_names_a_version_no_longer_current_is_refused_naming_the_current_one_and_changes_nothing(
        guarded, command, move):
    """Every operator write names the version it replaces. Another operator's write moves the record to the next version
    (identity: by a new base, so its credential generation rises; by a settings edit or a disable, so it does not; the
    case record: rewritten, or deleted and written again). The command, asked for the version it was prepared for, is
    refused, names the version now current, and the stored records and the KV hold exactly what the other operator left;
    `set-credentials` is asked both after the move and while its credentials are being written. (#1366 O5, O8, P5)"""
    op, kv = guarded, guarded.kv
    case = command in ("set-case", "delete-case")
    now = 2 if move != "delete-recreate" else 3
    if command == "set-credentials-while-written":
        kv.on_write = lambda: _move_system(op, move)
    elif case:
        _move_case(op, move)
    else:
        _move_system(op, move)
    before = W._state(op)
    held = {p: list(v) for p, v in kv.held.items()}

    rc, said = {
        "set-system": lambda: op.set_system("identity", replaces=1, config={"IDENTITY_TIMEOUT_SEC": "30"}, access=IDENTITY_ACCESS),
        "delete-system": lambda: op.delete_system("identity", replaces=1),
        "set-credentials": lambda: op.set_credentials("identity", {"api_key": "k-1366"}, for_version=1),
        "set-credentials-while-written": lambda: op.set_credentials("identity", {"api_key": "k-1366"}, for_version=1),
        "set-case": lambda: op.set_case(replaces=1, body="{cause}"),
        "delete-case": lambda: op.delete_case(replaces=1),
    }[command]()

    if command == "set-credentials-while-written":
        assert kv.on_write is None, "premise: the move landed during the credential write"
        before = W._state(op)  # the other operator's write is the state the command must leave
        assert [n[0] for n in before[0]["identity"]] == [1, 2], "premise: the other operator wrote version 2"
    assert rc != 0, said
    assert "Traceback" not in said, said
    assert W._numbered(said, "case" if case else "identity", now), (now, said)
    assert W._state(op) == before, "a refused write changed the stored records"
    if command == "set-credentials-while-written":
        # whatever the write left sits at the path of the version it was prepared for, and nowhere else
        assert kv.written() == [f"{op.tid}/identity/g1"], kv.written()
    else:
        assert {p: list(v) for p, v in kv.held.items()} == held, "a refused write changed the KV"
        assert kv.written() == [], kv.written()
    generation = {"base": 2, "settings": 1, "disable": 1}.get(move) if not case else None
    if generation is not None:
        assert op.current()["identity"].credential_generation == generation, "premise: the other operator's move"
        assert op.current()["identity"].version == 2


# --- G7 (a): a key the adapter does not declare is never stored -------------------------------------------------------

def _undeclared_keys() -> list[str]:
    """Keys a `config.env` line can spell that cmdb does not declare (it declares `CMDB_TIMEOUT_SEC`): spellings of the
    declared key, lower case, hyphen, dot, non-ASCII and mixed, and seeded random text over those alphabets."""
    rng = random.Random(13662)
    fixed = ["cmdb_timeout_sec", "Cmdb_Timeout_Sec", "CMDB-TIMEOUT-SEC", "CMDB.TIMEOUT.SEC", "cmdb_api_token", "cmdb-key",
             "token", "timeout_sec", "CMDB_TIMEOUT_SÉC", "ключ", "日本語", "k.e.y", "a-b", "_leading", "9digit"]
    alphabets = ["abcdefghijklmnopqrstuvwxyz_", "abcdefghijklmnopqrstuvwxyz-.", "abcdefgABCDEFG0123456789_-.", "éßжя日本_a-z"]
    generated = ["".join(rng.choice(rng.choice(alphabets)) for _ in range(rng.randint(2, 12))) for _ in range(12)]
    return [key for key in dict.fromkeys([*fixed, *generated]) if key != "CMDB_TIMEOUT_SEC" and "=" not in key]


UNDECLARED_KEYS = _undeclared_keys()
#: A smaller sample goes through the import (one Postgres import per row).
IMPORT_KEYS = ["cmdb_api_token", "CMDB-TIMEOUT-SEC", "日本語", UNDECLARED_KEYS[-1]]
KEY_ROWS = [("set-system", key) for key in UNDECLARED_KEYS] + [("import", key) for key in IMPORT_KEYS]


def _config_with(key: str) -> str:
    """cmdb's `config.env`: the declared key, and one more line spelling `key`."""
    return f'CMDB_TIMEOUT_SEC="10"\n{key}="s3cr3t-1366"\n'


@pytest.mark.postgres
@pytest.mark.parametrize(("channel", "key"), KEY_ROWS, ids=[f"{c}-{i}" for i, (c, _) in enumerate(KEY_ROWS)])
def test_1366_o4_a_settings_key_the_adapter_does_not_declare_is_refused_whatever_its_spelling_and_never_stored(
        tmp_path, data_root, migrated_database, capsys, monkeypatch, channel, key):  # noqa: F811
    """A `config.env` holding cmdb's declared key and one more `KEY="..."` line is refused at `set-system` and at
    `import` when the key is not one cmdb declares, whatever it is spelt like (a case variant of the declared key, lower
    case, hyphens, dots, non-ASCII): the refusal names the system and the key, no traceback, and no version is stored
    nor a secret value left in a record (a whole import refused marks nothing). Control: the declared key alone is
    stored. (#1366 O4, P1, P2, H2)"""
    files = R.import_files()
    if channel == "import":
        files["settings/systems/cmdb/config.env"] = _config_with(key)
    with W._planted(tmp_path, data_root, migrated_database, capsys, monkeypatch, files=files) as op:
        if channel == "set-system":
            assert op.import_()[0] == 0
            folder = op.tmp / "raw" / "cmdb"
            folder.mkdir(parents=True)
            (folder / "access.yaml").write_text(CMDB_ACCESS, encoding="utf-8")
            (folder / "config.env").write_text(_config_with(key), encoding="utf-8")
            before = W._state(op)
            rc, said = op.run(R.SET_SYSTEM, op.tid, "cmdb", str(folder), R.REPLACES, "1")
        else:
            rc, said = op.import_()
            before = W._state(op)
        assert rc != 0, said
        assert R.lines_naming(said, "cmdb", key), (key, said)
        assert "Traceback" not in said, said
        assert W._state(op) == before, "a refused key changed the records"
        assert "s3cr3t-1366" not in repr([op.versions(s) for s in R.FIXTURE_SYSTEMS]), "a value of the refused line was stored"
        if channel == "import":
            assert not R.imported(op.dsn, op.tid), "an import with a refused part marked the tenant imported"
        else:
            rc, said = op.set_system("cmdb", replaces=1, config=W.CMDB_NEW, access=CMDB_ACCESS)
            assert rc == 0, said  # control: the declared key alone is stored as the next version


# --- G7 (b): a credential file is exactly {kind, fields} ------------------------------------------------------------------

def _credential_files() -> list[tuple[str, Any]]:
    """JSON objects whose key set is not exactly {kind, fields}: every other subset of the two names with extra keys
    (and misspellings of them), plus seeded random extras."""
    rng = random.Random(13663)
    base = {"kind": "static", "fields": {"api_key": "k-1366"}}
    extras = ["extra", "Kind", "FIELDS", "kind ", "token", "note", "api_key", "fields2", "日本", "x" * 8]
    extras += ["".join(rng.choice("abcdefghijklmnopqrstuvwxyz_-") for _ in range(rng.randint(1, 9))) for _ in range(4)]
    rows: list[tuple[str, Any]] = []
    for extra in extras:
        rows.append((f"extra-{extra!r}", {**base, extra: "x"}))
        rows.append((f"only-extra-{extra!r}", {extra: "x"}))
        rows.append((f"kind-and-extra-{extra!r}", {"kind": "static", extra: {"api_key": "k-1366"}}))
        rows.append((f"fields-and-extra-{extra!r}", {"fields": {"api_key": "k-1366"}, extra: "static"}))
    rows += [("no-kind", {"fields": base["fields"]}), ("no-fields", {"kind": "static"}), ("empty", {})]
    return rows


CREDENTIAL_FILES = _credential_files()


@pytest.mark.postgres
@pytest.mark.parametrize("row", CREDENTIAL_FILES, ids=[f"{n}-{i}" for i, (n, _) in enumerate(CREDENTIAL_FILES)])
def test_1366_dc8_a_credential_file_that_is_not_exactly_kind_and_fields_is_refused_and_writes_nothing(guarded, row):
    """`set-credentials` takes one JSON object `{kind, fields}`. A file whose key set is anything else (an extra key
    beside both, a missing one, misspelt names, an empty object) is refused, prints none of its values, and nothing is
    sent to the KV. Control: the exact object is written at the current generation's path. (#1366 DC8, O8, P1)"""
    op, kv = guarded, guarded.kv
    _, document = row
    file = op.tmp / "creds.json"
    op.tmp.mkdir(parents=True, exist_ok=True)
    file.write_text(json.dumps(document), encoding="utf-8")

    rc, said = op.run(R.SET_CREDENTIALS, op.tid, "identity", str(file), R.FOR_VERSION, "1")

    assert rc != 0, said
    assert "Traceback" not in said, said
    assert "k-1366" not in said, "a credential value was printed"
    assert kv.requests == [], kv.requests
    file.write_text(json.dumps({"kind": "static", "fields": {"api_key": "k-1366"}}), encoding="utf-8")
    rc, said = op.run(R.SET_CREDENTIALS, op.tid, "identity", str(file), R.FOR_VERSION, "1")
    assert rc == 0, said
    assert kv.written() == [f"{op.tid}/identity/g1"], kv.written()
