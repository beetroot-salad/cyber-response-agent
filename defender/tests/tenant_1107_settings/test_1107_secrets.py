"""#1107 — secrets are references into a per-tenant store (D3, O2's exemption, O3, O4, S1-S3).

A config key ending `_SECRET_REF` names an entry of the tenant's git-ignored `settings/secrets.env`.
`RunTenant.secrets` (a `SecretLookup`) resolves a name only when some all-uppercase `*_SECRET_REF`
key anywhere in the tenant's systems declares it (MF-1: tenant-wide; F2: uppercase only), reads
`secrets.env` on EACH lookup (O2 exempts secrets; MF-2: declarations ride the run's start, values
each lookup), refuses a link or a non-regular file at that name on every lookup (MF-6), and faults
naming the DECLARING KEY, never a value or the string the key holds (MF-15). A transport asked for
a secret by its declared name sets the value into that one child's environment under a variable
it picks, and replaces the value with a fixed marker in any text it returns (O4, NF-8, MF-5 i).

How each surface is observed:
  * the lookup — `record.secrets.get(name)` on a record the REAL `run_tenant.resolve_tenant` built
    over a folder planted in the test (every fault a real file on disk: the deleted or blank
    entry, the symlink, the FIFO, the directory, the non-UTF-8 bytes);
  * delivery — the REAL `_stub_transport.docker_exec_curl`, reaching a `docker` shim first on the
    PATH of the env the transport forks with (CX8, executed: `subprocess.run(env=E)` resolves
    `docker` on E's PATH, so the shim receives the argv and the child's whole environment — no
    runner seam, no monkeypatch; F5, auto). Assertions scan env VALUES: the variable's name is the
    transport's to pick (NF-8), so no test pins it;
  * a whole run — the replay harness (`_replay_harness.drive`) with a "test adapter" verb injected
    through its `verbs=` seam, whose body makes the secret-bearing docker-exec call; the shim is
    put on the PATH the run env is built from (`monkeypatch.setenv`), then the run dir, the log
    and both models' visible text are scanned for the planted value (O4's "nowhere else").

The shim's replies are canned in curl's body + `\\n<status>` shape (the transport's own `-w`
contract). The echoing target of MF-5 and s024 is demand-specified INPUT (premises #23, #24, #27):
no ledger claim observed a real target or a real curl reflecting a credential; the channel the
echo rides is CX8's.
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from defender.runtime import run_tenant
from defender.scripts.adapters import _stub_transport as transport
from defender.scripts.adapters.faults import ConfigFault, TransportFault, UpstreamFault
from defender.skills.connect import validate_scaffold
from defender.tests import _tenants1106 as T1106
from defender.tests.tenant_1107_settings import _spec1107 as S

PID = S.PLAYGROUND_ID
RESOLVE = {"defender_dir": S.DEFENDER, "dispatches_lead_zero": False}

#: The gather grant is cmdb's three verbs and nothing else: the test adapter rides cmdb's grant,
#: and no row names the correlation lead, so no lead-zero correlation lead consumes the gather
#: model's scripted turns (TABLE_B's shape: withholding the lead is legal).
TABLE_CMDB = """\
dispositions:
  cmdb:
    get-host: {roles: [gather]}
    health-check: {roles: [gather]}
    list-hosts: {roles: [gather]}
"""

BASTION = "bastion-o4"


def _planted(tag: str) -> str:
    """A secret value no fixture, checkout file or environment could hold by accident."""
    return f"planted-{tag}-{uuid.uuid4().hex}"


def _values_seen(shim: S.DockerShim) -> list[str]:
    return [v for c in shim.calls() for v in c["env"].values()]


def _argv_seen(shim: S.DockerShim) -> list[str]:
    return [a for c in shim.calls() for a in c["argv"]]


def _fails(report: Any) -> list[str]:
    return [msg for status, msg in report.rows if status == validate_scaffold.FAIL]


def _raises(fn: Any) -> Any:
    """What `fn()` returned, or the exception it raised."""
    try:
        return fn()
    except BaseException as e:  # noqa: BLE001 — the test judges which it was
        return e


def _file_texts(root: Path) -> dict[str, str]:
    return {str(p): p.read_text(encoding="utf-8", errors="replace") for p in S.files_under(root)}


# ---- the test adapter and the whole-run scenario ------------------------------------------------

def _test_adapter(seen: list[Any], declared: str) -> Any:
    """A connector's verb that needs one secret: it asks the REAL transport for `declared` by name
    and turns the reply into a payload or a fault as the shipped stubs do (a non-zero exec is a
    TransportFault carrying stderr, a >=400 an UpstreamFault carrying the body, a non-JSON body a
    TransportFault carrying the body) — so every text a model or a row sees is built from what
    the transport RETURNED."""

    def get_host(ctx: Any, *, host: str) -> dict:
        seen.append(ctx)
        rc, stdout, stderr = transport.docker_exec_curl(
            ctx, BASTION, f"http://cmdb-o4:8080/hosts/{host}", system="cmdb",
            **{S.SECRETS_KW: (declared,)})
        if rc != 0:
            raise TransportFault(f"docker exec failed (rc={rc}): {stderr.strip()}")
        body, status = transport.split_status(stdout)
        code = int(status) if status.isdigit() else 0
        if code == 0:
            raise TransportFault(f"no response (rc={rc}): {stderr.strip()}")
        if code >= 400:
            raise UpstreamFault(f"HTTP {code} from /hosts/{host}: {body}")
        try:
            payload = json.loads(body)
        except json.JSONDecodeError as e:
            raise TransportFault(f"non-JSON response from /hosts/{host}: {e} (body: {body!r})") from e
        return {"host": host, "answer": payload}

    return get_host


def _undeclared_asker(seen: list[Any], name: str) -> Any:
    """A verb asking the transport for a name no `*_SECRET_REF` declares: the lookup's own
    ConfigFault is what reaches the query tool's fault digest and model view."""

    def list_hosts(ctx: Any, *, role: str | None = None) -> dict:
        seen.append(ctx)
        transport.docker_exec_curl(ctx, BASTION, "http://cmdb-o4:8080/hosts", system="cmdb",
                                   **{S.SECRETS_KW: (name,)})
        return {"hosts": []}

    return list_hosts


@dataclass
class SecretRun:
    run_dir: Path
    shim: S.DockerShim
    main: Any
    gather: Any
    ctxs: list[Any]
    value: str
    undeclared_value: str


def _secret_run(where: Path, monkeypatch: Any, caplog: Any, *, answers: list[dict],
                value: str | None = None, hosts: tuple[str, ...] = ("web-1",),
                ask_undeclared: bool = False) -> SecretRun:
    """One replay-driven run: the tenant's cmdb declares X_TOKEN_SECRET_REF=X_TOKEN and its
    secrets.env holds X_TOKEN=<value> (plus an entry no reference declares); the gather lead calls
    the test adapter once per host and, when `ask_undeclared`, asks for the undeclared name.
    Returns everything a nowhere-else scan reads; asserts nothing."""
    from defender.tests.e2e._replay_harness import (
        GOLDEN_AB3,
        FakeVerbs,
        ReplayFn,
        Turn,
        drive,
        materialize,
    )

    where.mkdir(parents=True, exist_ok=True)
    value = value if value is not None else _planted("o4")  # lint-default: ok — a FRESH planted value per run; a signature default would be one shared value
    undeclared = _planted("undeclared")
    root = where / "tenants"
    folder = S.plant(root, marker="o4", table=TABLE_CMDB,
                     secrets={"X_TOKEN": value, "NOT_DECLARED": undeclared})
    S.set_key(folder, "cmdb", "X_TOKEN_SECRET_REF", "X_TOKEN")
    shim = S.DockerShim(where / "shim", answers)
    # CX8: the run env is built from this process's env (`run_common.run_env`), so the shim leads
    # the PATH every docker child of the run is forked with.
    monkeypatch.setenv("PATH", shim.path_value())
    ctxs: list[Any] = []
    verbs = FakeVerbs({"cmdb": {
        "get-host": _test_adapter(ctxs, "X_TOKEN"),
        "list-hosts": _undeclared_asker(ctxs, "NOT_DECLARED"),
    }})
    run_dir = materialize(where / "run", GOLDEN_AB3)
    main = ReplayFn([
        Turn(tool_calls=[("gather", {
            "lead_id": "l-001", "system": "cmdb", "goal": "measure the cmdb lead",
            "what_to_summarize": ["what the system says"],
        })]),
        Turn(text="Investigation complete."),
    ])
    turns = [Turn(tool_calls=[("query", {"system": "cmdb", "verb": "get-host",
                                         "params": {"host": h}})]) for h in hosts]
    if ask_undeclared:
        turns.append(Turn(tool_calls=[("query", {"system": "cmdb", "verb": "list-hosts",
                                                 "params": {}})]))
    turns.append(Turn(text="Summary: measured the lead."))
    gather = ReplayFn(turns)
    caplog.set_level(logging.DEBUG)
    drive(run_dir, run_id="o4-secret", main=main, gather=gather, verbs=verbs,
          tenant=S.tenant_folder_of(root))
    return SecretRun(run_dir=run_dir, shim=shim, main=main, gather=gather, ctxs=ctxs,
                     value=value, undeclared_value=undeclared)


def _model_visible(run: SecretRun) -> str:
    return "\n".join([*run.main.seen, *run.gather.seen])


# ======================================================================================
# O3 — only the tenant's own, only the declared.
# ======================================================================================

def test_o3_declared_name_resolves(tmp_path):
    """A name that some *_SECRET_REF key in the tenant's systems declares, with a non-empty entry
    in that tenant's secrets.env, is returned by the lookup. repr(record.secrets) lists the
    declared names. Neither repr(record.secrets) nor the record formatted whole into text carries
    a secret value (NF-28, auto)."""
    value = _planted("o3")
    root = tmp_path / "tenants"
    folder = S.plant(root, marker="o3", secrets={"X_TOKEN": value})
    S.set_key(folder, "cmdb", "X_TOKEN_SECRET_REF", "X_TOKEN")
    # Premise #5: a second system declaring the SAME name is legitimate — the declared set is a set.
    S.set_key(folder, "identity", "IDENTITY_TOKEN_SECRET_REF", "X_TOKEN")

    record = run_tenant.resolve_tenant(root, PID, **RESOLVE)

    assert isinstance(record.secrets, S.record_type("SecretLookup")), type(record.secrets)
    assert record.secrets.get("X_TOKEN") == value, "a declared name with an entry must resolve"
    shown = repr(record.secrets)
    assert "X_TOKEN" in shown, f"repr(record.secrets) must list the declared names: {shown!r}"
    for text in (shown, str(record.secrets), repr(record), str(record), f"{record}"):
        assert value not in text, f"a secret value leaked into the record's text: {text!r}"


def test_o3_undeclared_name_refused(tmp_path):
    """A name that no *_SECRET_REF key declares is refused with ConfigFault, even when the
    tenant's secrets.env holds an entry for it."""
    declared, stray = _planted("declared"), _planted("stray")
    root = tmp_path / "tenants"
    folder = S.plant(root, marker="o3u", secrets={"X_TOKEN": declared, "Z_TOKEN": stray})
    S.set_key(folder, "cmdb", "X_TOKEN_SECRET_REF", "X_TOKEN")

    record = run_tenant.resolve_tenant(root, PID, **RESOLVE)

    # In-test control: the lookup answers for a declared name out of the same file.
    assert record.secrets.get("X_TOKEN") == declared, "control: the declared name resolves"
    with pytest.raises(ConfigFault) as refused:
        record.secrets.get("Z_TOKEN")
    assert stray not in str(refused.value), f"the refusal carries the value: {refused.value}"


def test_o3_other_tenant_refused(tmp_path):
    """With two tenant folders A and B, A's lookup of a name that only B declares (and only B's
    secrets.env holds) is refused with ConfigFault. A name that both declare returns A's value
    from A's file, never B's."""
    root = tmp_path / "tenants"
    a_shared, b_shared, b_only = _planted("a-shared"), _planted("b-shared"), _planted("b-only")
    a = S.plant(root, "alpha", marker="alpha", secrets={"SHARED": a_shared})
    b = S.plant(root, "bravo", marker="bravo", secrets={"SHARED": b_shared, "B_ONLY": b_only})
    S.set_key(a, "cmdb", "SHARED_SECRET_REF", "SHARED")
    S.set_key(b, "cmdb", "SHARED_SECRET_REF", "SHARED")
    S.set_key(b, "identity", "B_ONLY_SECRET_REF", "B_ONLY")

    rec_a = run_tenant.resolve_tenant(root, "alpha", **RESOLVE)
    rec_b = run_tenant.resolve_tenant(root, "bravo", **RESOLVE)

    # Control: B's own lookup answers for B's name, so the refusal below is A's boundary.
    assert rec_b.secrets.get("B_ONLY") == b_only, "control: B resolves its own name"
    with pytest.raises(ConfigFault) as refused:
        rec_a.secrets.get("B_ONLY")
    assert b_only not in str(refused.value), refused.value
    got = rec_a.secrets.get("SHARED")
    assert got == a_shared, f"A's lookup must read A's file, got {got!r}"


def test_o3_fault_at_ask(tmp_path):
    """A declared reference whose secrets.env is absent, whose entry is missing, or whose value is
    blank does not stop resolve_tenant. The lookup raises ConfigFault when the name is asked for,
    and the fault names the reference, never any value. The fault names the declaring key (for
    example X_TOKEN_SECRET_REF), never a value or the string the key holds (MF-15, human)."""
    other = _planted("other")
    # The held string differs from the key, so "names the key, never the held string" is a
    # substring test that can tell the two apart.
    key, held = "CMDB_API_SECRET_REF", "VAULT_ENTRY_7Q"
    arms = {
        "secrets-env-absent": None,
        "entry-missing": {"OTHER": other},
        "value-blank": {"OTHER": other, held: ""},
    }
    for arm, entries in arms.items():
        root = tmp_path / arm
        folder = S.plant(root, marker="ask", secrets=entries)
        S.set_key(folder, "cmdb", key, held)
        record = run_tenant.resolve_tenant(root, PID, **RESOLVE)  # must not raise
        with pytest.raises(ConfigFault) as fault:
            record.secrets.get(held)
        text = str(fault.value)
        assert key in text, f"{arm}: the fault must name the declaring key {key}: {text!r}"
        assert held not in text, f"{arm}: the fault names the held string: {text!r}"
        assert other not in text, f"{arm}: the fault carries a value: {text!r}"


def test_o2_secrets_read_per_lookup(tmp_path):
    """The next lookup returns a secrets.env value rotated after the record was built: secrets are
    read when asked for."""
    before, after = _planted("before"), _planted("after")
    root = tmp_path / "tenants"
    folder = S.plant(root, marker="rot", secrets={"X_TOKEN": before})
    S.set_key(folder, "cmdb", "X_TOKEN_SECRET_REF", "X_TOKEN")
    record = run_tenant.resolve_tenant(root, PID, **RESOLVE)

    assert record.secrets.get("X_TOKEN") == before, "control: the value at build time"
    S.write_secrets(folder, {"X_TOKEN": after})  # rotated by write-then-rename (NF-12)
    assert record.secrets.get("X_TOKEN") == after, "the lookup answered from a stale read"


# ======================================================================================
# O4 — the one channel: that child's environment.
# ======================================================================================

def test_o4_secret_in_child_env(tmp_path, monkeypatch, caplog):
    """A test adapter's config.env declares X_TOKEN_SECRET_REF=X_TOKEN, and the tenant's
    secrets.env holds X_TOKEN=<planted value>. The adapter makes one docker-exec call through a
    fake docker shim on the run env's PATH (F5 resolved auto: no new runner seam and no
    monkeypatch; CX8 shows the shim receives argv and the whole child environment). The planted
    value is present in that child's environment, under whatever variable name the transport
    picks."""
    run = _secret_run(tmp_path, monkeypatch, caplog,
                      answers=[S.answer(json.dumps({"host": "web-1"}), "200")])

    assert run.ctxs, "the test adapter was never called: the run never reached the query tool"
    # One host, no other verb: the run's one docker call is the adapter's (its argv shape is
    # the transport's — a forwarded `-e NAME` may sit before the container — so it is not read).
    calls = [c for c in run.shim.calls() if BASTION in c["argv"]]
    assert len(calls) == 1, f"the adapter's one docker-exec call: {[c['argv'] for c in calls]}"
    assert run.value in calls[0]["env"].values(), (
        "the planted secret is not in the child's environment under any variable")


def test_o4_secret_nowhere_else(tmp_path, monkeypatch, caplog):
    """In that same run the planted value appears nowhere else. It is not in the child's argv, not
    in any file under the run dir (the receipt included), not in any log record, and not in
    model-visible text (the query tool's fault digest and model view). It is not in
    repr(record.secrets), and not in the text of any ConfigFault the lookup raises."""
    # rejected: N2: `elastic:${ELASTIC_PASSWORD}` on the elastic argv is expanded inside the container and is not a tenant secret
    # rejected: C8: no production system declares a secret, so the scan runs over the test adapter only
    run = _secret_run(tmp_path, monkeypatch, caplog, ask_undeclared=True,
                      answers=[S.answer(json.dumps({"host": "web-1"}), "200")])

    # Positive control, same run: the value DID reach its one channel, the undeclared ask DID run
    # inside the run (so its fault reached the digest channel scanned below), and the queries
    # table the run-dir scan covers (F6) was written.
    assert run.value in _values_seen(run.shim), "the value never reached the child's env"
    assert len(run.ctxs) == 2, f"get-host and the undeclared ask did not both run: {len(run.ctxs)}"
    assert S.mod("_run_paths").RunPaths(run.run_dir).executed_queries.is_file(), (
        "the queries table was never written — the run-dir scan would prove nothing")
    for secret in (run.value, run.undeclared_value):
        assert all(secret not in a for a in _argv_seen(run.shim)), "a secret is on a child argv"
        found = S.holders(run.run_dir, secret)
        assert found == [], f"a secret was written under the run dir: {found}"
        assert secret not in caplog.text, "a secret reached a log record"
        assert secret not in _model_visible(run), "a secret reached model-visible text"
    record = S.record_on(run.ctxs[0])
    assert run.value not in repr(record.secrets), "repr(record.secrets) carries the value"
    with pytest.raises(ConfigFault) as fault:
        record.secrets.get("NOT_DECLARED")
    for secret in (run.value, run.undeclared_value):
        assert secret not in str(fault.value), f"the lookup's fault carries a value: {fault.value}"


def test_o4_secret_single_child(tmp_path):
    """The secret is set for that one child only. ctx.env is unchanged after the call. A second
    docker-exec call in the same run, whether the same system without the secret or another
    system, gets a child environment without the planted value."""
    value = _planted("single")
    root = tmp_path / "tenants"
    folder = S.plant(root, marker="one", secrets={"X_TOKEN": value})
    S.set_key(folder, "cmdb", "X_TOKEN_SECRET_REF", "X_TOKEN")
    record = run_tenant.resolve_tenant(root, PID, **RESOLVE)
    shim = S.DockerShim(tmp_path / "shim", [S.answer("{}", "200")])
    ctx = S.verb_context(record, tmp_path / "run", shim.env())
    env_before = dict(ctx.env)

    transport.docker_exec_curl(ctx, "bastion-one", "http://cmdb-one:8080/hosts/web-1",
                               system="cmdb", **{S.SECRETS_KW: ("X_TOKEN",)})
    transport.docker_exec_curl(ctx, "bastion-one", "http://cmdb-one:8080/hosts/web-2",
                               system="cmdb")
    transport.docker_exec_raw(ctx, "web-1", ["ps", "-ef"],  # host-state's lane: another system
                              system="host-state")

    calls = shim.calls()
    assert len(calls) == 3, [c["argv"] for c in calls]
    assert value in calls[0]["env"].values(), "control: the asking call's child got the value"
    assert value not in calls[1]["env"].values(), "the same system's next call inherited it"
    assert value not in calls[2]["env"].values(), "another system's call inherited it"
    assert dict(ctx.env) == env_before, "the secret (or anything else) was added to ctx.env"
    assert value not in os.environ.values(), "the secret was put in the process environment"


def test_s7_nf8_transport_names_the_child_variable(tmp_path):
    """A secret-bearing docker call's child environment is the run's ctx.env passed through plus
    the resolved value under a variable the transport picks. The tenant's declared name is only a
    key into secrets.env and never becomes a child variable (a declared name of DOCKER_HOST, PATH
    or LD_PRELOAD sets nothing of that name); if ctx.env already carries the transport's chosen
    name, the child sees the resolved secret, never the operator's value; two secrets for one
    child each get their own transport-chosen variable, and neither goes on argv."""
    vals = {n: _planted(n.lower()) for n in ("X_TOKEN", "Y_TOKEN", "DOCKER_HOST", "PATH",
                                             "LD_PRELOAD")}
    root = tmp_path / "tenants"
    folder = S.plant(root, marker="nf8", secrets=vals)
    for i, name in enumerate(vals):
        S.set_key(folder, "cmdb", f"REF{i}_SECRET_REF", name)
    record = run_tenant.resolve_tenant(root, PID, **RESOLVE)
    shim = S.DockerShim(tmp_path / "shim", [S.answer("{}", "200")])
    # A small, known ctx.env (the shim first on its PATH), so "passed through" is checkable.
    base_env = shim.env({"PATH": os.environ.get("PATH", "")}, DEFENDER_NF8_MARK="kept")
    ctx = S.verb_context(record, tmp_path / "run", base_env)
    url = "http://cmdb-nf8:8080/hosts/web-1"

    # 1) One secret: ctx.env passed through untouched, plus the value under SOME new variable.
    transport.docker_exec_curl(ctx, "b", url, system="cmdb", **{S.SECRETS_KW: ("X_TOKEN",)})
    child = shim.calls()[-1]["env"]
    for k, v in base_env.items():
        assert child.get(k) == v, f"ctx.env's {k} was not passed through untouched"
    chosen = [k for k, v in child.items() if v == vals["X_TOKEN"]]
    assert chosen, "the resolved secret is in no child variable"
    assert "X_TOKEN" not in child, "the declared name became a child variable"

    # 2) An operator value already under the transport's chosen name: the child sees the secret.
    clash_env = {**base_env, **{k: "operator-value" for k in chosen}}
    clash_ctx = S.verb_context(record, tmp_path / "run", clash_env)
    transport.docker_exec_curl(clash_ctx, "b", url, system="cmdb", **{S.SECRETS_KW: ("X_TOKEN",)})
    child = shim.calls()[-1]["env"]
    assert vals["X_TOKEN"] in child.values(), (
        "with ctx.env already carrying the transport's chosen name, the child lost the secret")

    # 3) Declared names docker or the loader would interpret set nothing of that name.
    for name in ("DOCKER_HOST", "PATH", "LD_PRELOAD"):
        transport.docker_exec_curl(ctx, "b", url, system="cmdb", **{S.SECRETS_KW: (name,)})
        child = shim.calls()[-1]["env"]
        assert child.get(name) == base_env.get(name), (
            f"the declared name {name} became a child variable: {child.get(name)!r}")
        assert vals[name] in child.values(), f"{name}'s value was not delivered under another name"

    # 4) Two secrets, one child: each under its own variable, neither value on argv.
    transport.docker_exec_curl(ctx, "b", url, system="cmdb",
                               **{S.SECRETS_KW: ("X_TOKEN", "Y_TOKEN")})
    child = shim.calls()[-1]["env"]
    names_x = {k for k, v in child.items() if v == vals["X_TOKEN"]}
    names_y = {k for k, v in child.items() if v == vals["Y_TOKEN"]}
    assert names_x, f"a secret of the pair is missing: {names_x}, {names_y}"
    assert names_y, f"a secret of the pair is missing: {names_x}, {names_y}"
    for v in vals.values():
        assert all(v not in a for a in _argv_seen(shim)), "a secret value went on argv"


_MARKED = re.compile(r"@@BEGIN@@(.*?)@@END@@", re.S)


def _echo(value: str) -> str:
    """The value as an echoing target reflects it, between delimiters the scan can find."""
    return f"@@BEGIN@@{value}@@END@@"


def test_s7_mf5_reflected_secret_scrubbed(tmp_path, monkeypatch, caplog):
    """A fake target that echoes the planted secret value back, once in an HTTP error body and once
    in a truncated response, does not carry the value into any text the transport returns or
    raises: the fault text, the returned stdout, the queries table (executed_queries.jsonl), a
    capture, any file under the run dir and model-visible text each hold a fixed marker where the
    value was. The transport replaces every secret value it placed in that child's environment,
    for any access method (transport-agnostic)."""
    # rejected: O4 stopping at the host's own transmission, with the planted-value scan run only against a non-reflecting fake (MF-5 i B)
    # The echo is demand-specified INPUT (MF-5 i; premises #23, #27), not a probed target's
    # behaviour; CX8 is the channel it rides. KNOWN LIMIT (handoff.deviations): only the literal
    # value is scrubbed, so the echo carries it literally.
    value = _planted("mf5")
    ok = json.dumps({"echo": _echo(value)})
    error = json.dumps({"detail": f"bad credential {_echo(value)}"})
    truncated = '{"echo": "' + _echo(value) + '", "rest": "cut'
    run = _secret_run(tmp_path, monkeypatch, caplog, value=value,
                      hosts=("web-1", "web-2", "web-3"),
                      answers=[S.answer(ok, "200"), S.answer(error, "401"),
                               S.answer(truncated, "200")])

    assert value in _values_seen(run.shim), "control: the value reached the child's env"
    assert len(run.ctxs) == 3, f"the three echoing calls were not all made: {len(run.ctxs)}"
    table = S.mod("_run_paths").RunPaths(run.run_dir).executed_queries
    assert table.is_file(), "the queries table was never written — the scan would prove nothing"
    surfaces = {"model-visible text": _model_visible(run), "log records": caplog.text,
                **_file_texts(run.run_dir)}
    for where, text in surfaces.items():
        assert value not in text, f"the reflected secret reached {where}"
    marked = [m for text in surfaces.values() for m in _MARKED.findall(text)]
    assert marked, "the echoed text vanished wholesale instead of holding a marker"
    assert all(m.strip() and value not in m for m in marked), f"no marker in place: {marked}"

    # Straight off the transport: the text it RETURNS holds the same fixed marker. The echo is a
    # body on an HTTP 500, curl exiting 0 — the shape a real reflecting target was observed to
    # produce (AP1, 82-author-probes.md). No stderr echo is fed: the real tooling never repeats
    # the request on stderr (AP2, refuted — the transport passes no -v/--trace).
    ctx = S.verb_context(S.record_on(run.ctxs[0]), run.run_dir, run.shim.env())
    run.shim.respond(S.answer(error, "500"))
    _rc, out, err = transport.docker_exec_curl(ctx, BASTION, "http://cmdb-o4:8080/x",
                                               system="cmdb", **{S.SECRETS_KW: ("X_TOKEN",)})
    assert value not in out, "the transport returned the value"
    assert value not in err, "the transport returned the value"
    markers = set(_MARKED.findall(out)) | set(_MARKED.findall(err))
    assert len(markers) == 1, f"the replacement is not one fixed marker: {sorted(markers)}"
    assert all(m.strip() for m in markers), f"the replacement is not one fixed marker: {sorted(markers)}"


def test_transport_error_output_carries_request_headers(tmp_path, monkeypatch, caplog):
    """Fault text built from the transport's own tooling output carries no secret value. For each
    failure shape the real tooling was observed to produce (82-author-probes.md: curl's refused
    connection and its --max-time timeout, the daemon's "No such container" and "is not
    running", and an HTTP 500 whose body reflects the credential), the value is absent from the
    fault text, from every file under the run dir and from model-visible text. The premise's
    stderr channel (curl or docker stderr repeating the request, headers included) was refuted by
    probe: the transport never passes -v or --trace, so no such text reaches a fault."""
    # Re-derived (AF-1): every answer below is an OBSERVED shape — AP3 for the four tooling
    # failures, AP1 for the reflecting 500 body. The premise-#24 header dump is AP2 (refuted) and
    # is no longer fed. Two runs, two failing calls each: PER_SYSTEM_FAIL_LIMIT is 2, so a third
    # infra failure in one run would be refused by the breaker before it reached docker.
    value = _planted("s024")
    reflected = json.dumps({"detail": f"bad credential, saw header: Bearer {value}"})
    runs = {
        "http-and-curl": ([S.answer(reflected, "500"), S.curl_refused("cmdb-o4")],
                          ("bad credential, saw header: Bearer", "Failed to connect")),
        "timeout-and-daemon": ([S.curl_timed_out(), S.no_such_container(BASTION)],
                               ("Operation timed out", "No such container")),
    }
    for lane, (answers, diagnostics) in runs.items():
        run = _secret_run(tmp_path / lane, monkeypatch, caplog, value=value,
                          hosts=("web-1", "web-2"), answers=answers)
        calls = run.shim.calls()
        assert len(calls) == 2, f"{lane}: both failing calls were not made: {len(calls)}"
        assert all(value in c["env"].values() for c in calls), \
            f"{lane}: control: the value did not reach every child's env"
        visible = _model_visible(run)
        for text in diagnostics:
            assert text in visible or S.holders(run.run_dir, text), (
                f"{lane}: the tooling's own text {text!r} reached no fault text — the scan would "
                f"prove nothing")
        assert value not in visible, f"{lane}: the value reached model-visible text"
        assert S.holders(run.run_dir, value) == [], f"{lane}: the value was written under the run dir"
    assert value not in caplog.text, "the value reached a log record"

    # The text each fault is built from, straight off the transport's return: the value is gone
    # and the tooling's own diagnostic survives.
    ctx = S.verb_context(S.record_on(run.ctxs[0]), run.run_dir, run.shim.env())
    for answer, kept in ((S.answer(reflected, "500"), "bad credential, saw header: Bearer"),
                         (S.curl_refused("cmdb-o4"), "Failed to connect"),
                         (S.curl_timed_out(), "Operation timed out"),
                         (S.no_such_container(BASTION), "No such container"),
                         (S.container_not_running(), "is not running")):
        run.shim.respond(answer)
        _rc, out, err = transport.docker_exec_curl(ctx, BASTION, "http://cmdb-o4:8080/x",
                                                   system="cmdb", **{S.SECRETS_KW: ("X_TOKEN",)})
        assert kept in out + err, f"the tooling's own diagnostic was lost: {out!r} {err!r}"
        assert value not in out, f"the transport returned the value: {out!r}"
        assert value not in err, f"the transport returned the value: {err!r}"


def test_secret_needed_from_a_lane_other_than_the_query_tool(tmp_path, monkeypatch, caplog, capsys):  # noqa: PLR0915 — five lanes, one scan each, read top to bottom
    """O4's nowhere-else guarantee holds on every lane that makes a secret-bearing docker-exec
    call, not only the query tool: lead-zero item 1, a gather lead's replaced deps, the ticket
    writer, review's replay contexts and the branch launcher's write door each deliver the value
    only into that call's child environment."""
    from defender.scripts.case_history import ticket_writer
    from defender.tests.e2e import _lead_zero_808 as LZ
    from defender.tests.e2e._replay_harness import FakeVerbs, VerbRecorder

    # Lane 1 — a gather lead's replaced deps: the MAIN-dispatched lead's verb makes the call.
    run = _secret_run(tmp_path / "gather-lane", monkeypatch, caplog,
                      answers=[S.answer(json.dumps({"host": "web-1"}), "200")])
    assert run.value in _values_seen(run.shim), "gather lane: the value never reached its child"
    assert all(run.value not in a for a in _argv_seen(run.shim)), "gather lane: value on argv"
    assert S.holders(run.run_dir, run.value) == [], "gather lane: the value is in the run dir"
    assert run.value not in _model_visible(run), "gather lane: the value is model-visible"

    # Lane 2 — lead-zero item 1: its by-alert_id fetch is served by an elastic verb that needs
    # the secret (the verb wraps `_lead_zero_808`'s backend, same signature, same answers).
    value = _planted("lz")
    lz_root = tmp_path / "lz-tenants"
    folder = S.plant(lz_root, marker="lz", table=T1106.TABLE_A, secrets={"ES_TOKEN": value})
    S.set_key(folder, "elastic", "ES_API_SECRET_REF", "ES_TOKEN")
    shim = S.DockerShim(tmp_path / "lz-shim", [S.answer("{}", "200")])
    monkeypatch.setenv("PATH", shim.path_value())  # CX8
    backend = dict(LZ.elastic_backend(VerbRecorder(), LZ.answer_hits([])).verbs("elastic"))

    def _needs_secret(inner: Any) -> Any:
        def fn(ctx: Any, *, native_query: str, start: str | None = None,
               end: str | None = None, limit: int = 20, index: str | None = None,
               sort: str = "desc") -> dict:
            transport.docker_exec_curl(ctx, "es-lz", "https://es-lz:9200/_search",
                                       system="elastic", **{S.SECRETS_KW: ("ES_TOKEN",)})
            return inner(ctx, native_query=native_query, start=start, end=end, limit=limit,
                         index=index, sort=sort)
        return fn

    backend["query"], backend["alerts"] = (_needs_secret(backend["query"]),
                                           _needs_secret(backend["alerts"]))
    (tmp_path / "lz-run").mkdir()
    caplog.clear()
    res = LZ.run(tmp_path / "lz-run", run_id="lz1107-secret", alert=LZ.alert_doc(),
                 verbs=FakeVerbs({"elastic": backend}), tenant=S.tenant_folder_of(lz_root))
    assert value in _values_seen(shim), "lead-zero lane: item 1's call never carried the value"
    assert all(value not in a for a in _argv_seen(shim)), "lead-zero lane: value on argv"
    assert value not in res.message_zero, "lead-zero lane: the value reached message zero"
    assert S.holders(res.run_dir, value) == [], "lead-zero lane: the value is in the run dir"
    assert value not in caplog.text, "lead-zero lane: the value reached a log record"

    # Lane 3 — the ticket writer: its store call goes through the `TicketWriterDeps(request=...)`
    # seam, whose fake makes the call through the REAL transport asking for the case-history
    # secret; the writer then logs and writes its receipt from what that call returned.
    wvalue = _planted("writer")
    wroot = tmp_path / "w-tenants"
    wfolder = S.plant(wroot, marker="wr", secrets={"CH_TOKEN": wvalue})
    S.set_key(wfolder, "case-history", "CH_API_SECRET_REF", "CH_TOKEN")
    record = run_tenant.resolve_tenant(wroot, PID, **RESOLVE)
    wshim = S.DockerShim(tmp_path / "w-shim", S.store_answers_ok("w1"))
    run_dir = tmp_path / "w-runs" / "w1"
    S.plant_alert(run_dir)
    wctx = S.verb_context(record, run_dir, wshim.env())

    def request(config: Any, method: str, path: str, body: Any = None, **_kw: Any) -> tuple:
        _rc, stdout, _err = transport.docker_exec_curl(
            wctx, "bastion-wr", f"http://case-history-wr:8080{path}", method=method, body=body,
            system="case-history", **{S.SECRETS_KW: ("CH_TOKEN",)})
        text, status = transport.split_status(stdout)
        return (status or None), text

    caplog.clear()
    S.record_step(run_dir, record, env=wshim.env(), truncated_by="aborted",
                  deps=ticket_writer.TicketWriterDeps(request=request))
    assert wvalue in _values_seen(wshim), "ticket-writer lane: its call never carried the value"
    assert S.receipt(run_dir) is not None, "ticket-writer lane: no receipt — the scan is vacuous"
    assert all(wvalue not in a for a in _argv_seen(wshim)), "ticket-writer lane: value on argv"
    assert S.holders(run_dir, wvalue) == [], "ticket-writer lane: the value is in the run dir"
    assert wvalue not in caplog.text, "ticket-writer lane: the value reached a log record"

    # Lane 4 — review's replay contexts (Phase F re-open, O4 lanes, human). The launcher's REAL
    # read side (`seams.adapter_seam` over the episode tenant's record, whose ctx
    # `review.verb_context` builds) with its registry swapped for one secret-bearing elastic verb
    # (constructor injection, `EpisodeAdapters(registry=, ctx=)`), replayed by the REAL review():
    # the capture is re-asked on the base arm AND through each world's `for_world` view, so a
    # context copy that dropped the record would lose the lookup.
    from defender.learning.branch import seams as branch_seams
    from defender.tests import _world_1007 as W

    rvalue = _planted("review")
    lane4 = tmp_path / "review-lane"
    _rb, _rsrc, episodes_root = W.configured_layout(lane4, monkeypatch)
    rroot = lane4 / "tenants"
    rfolder = S.plant(rroot, marker="rl", secrets={"ELASTIC_TOKEN": rvalue},
                      configs=S.config_texts("rl", events_index=W.EVENTS_PATTERN,
                                             alerts_index=W.ALERTS_PATTERN))
    S.set_key(rfolder, "elastic", "ELASTIC_TOKEN_SECRET_REF", "ELASTIC_TOKEN")
    rrecord = run_tenant.resolve_tenant(rroot, PID, **RESOLVE)
    rshim = S.DockerShim(lane4 / "shim", [S.answer(json.dumps({"hits": {"hits": []}}), "200")])
    monkeypatch.setenv("PATH", rshim.path_value())  # CX8: the lane's ctx env is built from here
    doc = W.family_doc(worlds=[
        W.base_world(),
        W.world_doc("b", ov=W.overlay(elastic=W.elastic_overlay(inject=[{"_id": "i1"}])))])
    episode_dir = W.episode(lane4, doc=doc, root=episodes_root)
    W.base_capture(episode_dir, [W.captured_row(key="k1")])
    runs_base = episode_dir.parent / "runs-base"
    review_ctxs: list[Any] = []

    def secret_query(ctx: Any, **params: Any) -> dict:
        review_ctxs.append(ctx)
        transport.docker_exec_curl(ctx, S.es_container("rl"), "http://localhost:9200/_search",
                                   system="elastic", **{S.SECRETS_KW: ("ELASTIC_TOKEN",)})
        return {"hits": [{"host": {"name": "web-1"}}]}

    read_side = branch_seams.adapter_seam(episode_dir, rrecord, runs_base=runs_base)
    lane = branch_seams.EpisodeAdapters(
        registry=FakeVerbs({"elastic": {"query": secret_query}}), ctx=read_side.ctx)
    caplog.clear()
    reviewed = S.review_run(W.mod("runtime.branch._family").parse_family(doc), episode_dir,
                            rrecord, adapters=lane, door=W.FakeDoor(),
                            invoke=W.FakeAgent("same"), runs_base=runs_base)
    assert (episode_dir / "review.yaml").is_file(), "review lane: no review.yaml — the scan is vacuous"
    assert any(getattr(c, "world_id", None) for c in review_ctxs), \
        "review lane: no replay went through a world's for_world view"
    rcalls = rshim.calls()
    assert len(rcalls) == len(review_ctxs), "review lane: a replay made no docker call"
    assert all(rvalue in c["env"].values() for c in rcalls), \
        "review lane: a replay's child never carried the value"
    assert all(rvalue not in a for a in _argv_seen(rshim)), "review lane: value on argv"
    assert S.holders(episodes_root, rvalue) == [], "review lane: the value is in the episode tree"
    assert rvalue not in json.dumps(reviewed, default=str), "review lane: the value is in the record"
    assert all(rvalue not in c.env.values() for c in review_ctxs), \
        "review lane: the value is in a replay context's env"
    assert rvalue not in caplog.text, "review lane: the value reached a log record"

    # Lane 5 — the branch launcher's write door, through the REAL launcher. The door is the one
    # the launcher builds from the episode tenant's record; only its transport is the test's
    # (the `door_transport=` seam, d_launcher_door_transport_seam), forwarding every door call to
    # the REAL transport with the declared secret named. The shim answers the door's probe with
    # AP3's observed missing-container shape, so the launch stops at `_probe_cluster` (G26) after
    # exactly the calls the probe made, before any episode dir.
    from defender.tests import _triplet_947 as T947
    from defender.tests._data_root_1078 import DATA_ROOT_ENV
    from defender.tests.tenant_1078_pass_a import _spec1078 as H

    dvalue = _planted("door")
    lane5 = tmp_path / "door-lane"
    for var in S.BRANCH_CONFIG_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv(DATA_ROOT_ENV, str(lane5 / "data"))  # a fresh data root: one tenant row
    monkeypatch.setenv(T947.EPISODES_BASE_ENV, str(lane5 / "episodes"))
    _dbase, dsrc = H.tenant_source(lane5 / "data", "door-t1107")
    droot = lane5 / "tenants"
    dfolder = S.plant(droot, "door-t1107", marker="dl", secrets={"ELASTIC_TOKEN": dvalue})
    S.set_key(dfolder, "elastic", "ELASTIC_TOKEN_SECRET_REF", "ELASTIC_TOKEN")
    dshim = S.DockerShim(lane5 / "shim", [S.no_such_container(S.es_container("dl"))])
    monkeypatch.setenv("PATH", dshim.path_value())
    door_ctxs: list[Any] = []

    def door_transport(ctx: Any, container: str, url: str, **kw: Any) -> tuple[int, str, str]:
        door_ctxs.append(ctx)
        return transport.docker_exec_curl(ctx, container, url, **kw,
                                          **{S.SECRETS_KW: ("ELASTIC_TOKEN",)})

    caplog.clear()
    capsys.readouterr()
    _rc, refused = S.launch_branch(dsrc, droot, door=None, **{S.DOOR_TRANSPORT_KW: door_transport})
    assert door_ctxs, "door lane: the launcher's door never called its transport"
    dcalls = dshim.calls()
    assert dcalls, "door lane: the door made no docker call"
    assert all(dvalue in c["env"].values() for c in dcalls), \
        "door lane: a door call's child never carried the value"
    assert all(dvalue not in a for a in _argv_seen(dshim)), "door lane: value on argv"
    if refused is not None:
        assert dvalue not in H.refusal_text(refused), "door lane: the value is in the refusal"
    out, err = capsys.readouterr()
    assert dvalue not in out, "door lane: the value reached the launcher's output"
    assert dvalue not in err, "door lane: the value reached the launcher's output"
    assert dvalue not in caplog.text, "door lane: the value reached a log record"
    assert S.holders(lane5 / "data", dvalue) == [], "door lane: the value is under the data root"
    assert S.holders(lane5 / "episodes", dvalue) == [], "door lane: the value is in the episodes root"


# ======================================================================================
# The declared set and the lookup's reads.
# ======================================================================================

def test_declared_secret_set_spans_a_faulted_sibling_config(tmp_path):
    """A sibling system whose config.env is missing or unparsable does not narrow what another,
    successfully parsed system declares: that system's *_SECRET_REF name still resolves."""
    for arm in ("missing", "unparsable"):
        value = _planted(arm)
        root = tmp_path / arm
        folder = S.plant(root, marker="sib", secrets={"X_TOKEN": value})
        S.set_key(folder, "cmdb", "X_TOKEN_SECRET_REF", "X_TOKEN")
        sibling = S.config_path(folder, "identity")
        if arm == "missing":
            sibling.unlink()
        else:
            sibling.write_bytes(b'IDENTITY_URL_BASE="http://\xff\xfe:8080"\n')
        record = run_tenant.resolve_tenant(root, PID, **RESOLVE)
        assert isinstance(record.systems["identity"], ConfigFault), (
            f"{arm}: the sibling is not the faulted entry this scenario needs")
        assert record.secrets.get("X_TOKEN") == value, f"{arm}: the faulted sibling narrowed it"


def test_env_secret_rotated_to_blank_between_two_lookups_in_one_run(tmp_path):
    """A secret rotated to blank between two lookups in one run: the second lookup raises
    ConfigFault cleanly, in O5's shape (that system down, the run goes on)."""
    value = _planted("blank")
    root = tmp_path / "tenants"
    folder = S.plant(root, marker="bl", secrets={"X_TOKEN": value})
    S.set_key(folder, "cmdb", "X_TOKEN_SECRET_REF", "X_TOKEN")
    record = run_tenant.resolve_tenant(root, PID, **RESOLVE)

    assert record.secrets.get("X_TOKEN") == value, "control: the first lookup resolves"
    S.write_secrets(folder, {"X_TOKEN": ""})
    with pytest.raises(ConfigFault) as fault:
        record.secrets.get("X_TOKEN")
    # RG6: a ConfigFault exits 2 like a TransportFault — the system-down class the breaker counts.
    assert fault.value.exit_code == 2, f"not O5's system-down shape: {fault.value.exit_code}"
    assert "X_TOKEN_SECRET_REF" in str(fault.value), fault.value


def test_secrets_env_becomes_unreadable_between_two_lookups_same_run(tmp_path):
    """secrets.env becoming unreadable between two lookups in one run: the next lookup faults per
    lookup, in O5's shape; the first lookup's already-delivered value stands."""
    value = _planted("gone")
    root = tmp_path / "tenants"
    folder = S.plant(root, marker="gone", secrets={"X_TOKEN": value})
    S.set_key(folder, "cmdb", "X_TOKEN_SECRET_REF", "X_TOKEN")
    record = run_tenant.resolve_tenant(root, PID, **RESOLVE)

    first = record.secrets.get("X_TOKEN")
    S.secrets_path(folder).unlink()
    for _ in range(2):  # per lookup: every ask faults, none is answered from a remembered read
        with pytest.raises(ConfigFault) as fault:
            record.secrets.get("X_TOKEN")
        assert fault.value.exit_code == 2, "RG6: O5's system-down shape is exit 2"
    assert first == value, "the first lookup's delivered value must stand"


def test_s7_mf1_declared_set_is_tenant_wide(tmp_path):
    """In one tenant, a name only the ticket system's config.env declares
    (TICKET_TOKEN_SECRET_REF=TICKET_TOKEN) resolves when a cmdb verb asks for it: the declared set
    is the whole tenant's. A declaration in a system whose own config is otherwise down (its
    <PREFIX>_TRANSPORT missing, so its calls fault) still declares its name for the rest of the
    tenant."""
    from defender.scripts.adapters import threat_intel_adapter

    ticket_value, ti_value = _planted("ticket"), _planted("ti")
    root = tmp_path / "tenants"
    folder = S.plant(root, marker="mf1",
                     secrets={"TICKET_TOKEN": ticket_value, "TI_KEY": ti_value})
    S.set_key(folder, "ticket", "TICKET_TOKEN_SECRET_REF", "TICKET_TOKEN")
    S.set_key(folder, "threat-intel", "TI_KEY_SECRET_REF", "TI_KEY")
    S.drop_key(folder, "threat-intel", "THREAT_INTEL_TRANSPORT")
    record = run_tenant.resolve_tenant(root, PID, **RESOLVE)
    shim = S.DockerShim(tmp_path / "shim", [S.answer("{}", "200")])
    ctx = S.verb_context(record, tmp_path / "run", shim.env())

    # A cmdb-shaped call (cmdb's bastion and URL) asking for the ticket system's name.
    transport.docker_exec_curl(ctx, "bastion-mf1", "http://cmdb-mf1:8080/hosts/web-1",
                               system="cmdb", **{S.SECRETS_KW: ("TICKET_TOKEN",)})
    assert ticket_value in _values_seen(shim), "a name another system declares was refused"
    assert record.secrets.get("TICKET_TOKEN") == ticket_value
    # Control: threat-intel IS down for its own calls ...
    down = _raises(lambda: threat_intel_adapter.health_check(ctx))
    assert isinstance(down, ConfigFault), f"threat-intel without a TRANSPORT line answered: {down!r}"
    # ... yet its declaration still counts for the tenant.
    assert record.secrets.get("TI_KEY") == ti_value, "a down system's declaration was dropped"


def test_s7_mf2_declarations_fixed_at_start(tmp_path):
    """Declarations ride the run's start, values each lookup. A *_SECRET_REF line added to a
    config.env after the record is built does not make its name resolvable: asking for it is
    refused as undeclared. When an operator renames a secrets.env entry X to Y and repoints
    config.env to Y mid-run, the lookup of X raises ConfigFault for a missing entry naming X's
    declaring key, and Y is refused as undeclared."""
    x_value, late = _planted("x"), _planted("late")
    root = tmp_path / "tenants"
    folder = S.plant(root, marker="mf2", secrets={"OLD_ENTRY": x_value, "LATE": late})
    S.set_key(folder, "cmdb", "CMDB_API_SECRET_REF", "OLD_ENTRY")
    record = run_tenant.resolve_tenant(root, PID, **RESOLVE)
    assert record.secrets.get("OLD_ENTRY") == x_value, "control: the start-time declaration"

    S.set_key(folder, "identity", "LATE_SECRET_REF", "LATE")
    with pytest.raises(ConfigFault) as undeclared_late:
        record.secrets.get("LATE")
    assert late not in str(undeclared_late.value)

    S.write_secrets(folder, {"NEW_ENTRY": x_value, "LATE": late})
    S.set_key(folder, "cmdb", "CMDB_API_SECRET_REF", "NEW_ENTRY")
    with pytest.raises(ConfigFault) as missing:
        record.secrets.get("OLD_ENTRY")
    assert "CMDB_API_SECRET_REF" in str(missing.value), missing.value
    with pytest.raises(ConfigFault) as undeclared:
        record.secrets.get("NEW_ENTRY")
    assert x_value not in str(undeclared.value)
    assert x_value not in str(missing.value)


def _lookup_in_thread(record: Any, name: str, timeout: float = 10.0) -> tuple[bool, Any]:
    """`record.secrets.get(name)` on a worker thread: `(finished, result-or-exception)`."""
    box: dict[str, Any] = {}

    def work() -> None:
        box["out"] = _raises(lambda: record.secrets.get(name))

    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(timeout)
    return (not t.is_alive()), box.get("out")


def test_s7_mf6_lookup_refuses_link_or_nonregular(tmp_path):  # noqa: PLR0915 — one demand: every link shape at secrets.env, each with its control
    """Each lookup opens settings/secrets.env refusing a link at every path component from the
    tenant folder down to secrets.env, and anything at that path that is not a regular file (a
    no-follow open or an lstat check of each component). A secrets.env swapped for a symlink after
    resolve, to another tenant's secrets.env or to a box-writable file, makes the next lookup
    raise ConfigFault naming the reference and read nothing through the link; so does the
    settings/ folder, or the tenant folder itself, swapped for a link to another tenant's (R2). A
    hard link made at secrets.env after resolve (a regular file with more than one name, such as a
    second name for another tenant's secrets.env) faults the same way, matching the refusal
    resolve already makes (_tenants._refuse_links, RV1). A FIFO with no writer, or a directory, at
    that path faults the same way and never blocks (NF-12)."""
    own, other, boxed = _planted("own"), _planted("other"), _planted("boxed")
    root = tmp_path / "tenants"
    folder = S.plant(root, marker="mf6", secrets={"X_TOKEN": own})
    S.set_key(folder, "cmdb", "X_TOKEN_SECRET_REF", "X_TOKEN")
    other_folder = S.plant(root, "bravo", marker="bravo", secrets={"X_TOKEN": other})
    box_file = tmp_path / "runs" / "r1" / "planted.env"  # a file under a run dir: box-writable
    box_file.parent.mkdir(parents=True)
    box_file.write_text(f'X_TOKEN="{boxed}"\n', encoding="utf-8")
    record = run_tenant.resolve_tenant(root, PID, **RESOLVE)
    assert record.secrets.get("X_TOKEN") == own, "control: the plain file resolves"

    target = S.secrets_path(folder)
    for label, planted_value, link_to in (
            ("another tenant's", other, S.secrets_path(other_folder)),
            ("a box-writable", boxed, box_file)):
        target.unlink()
        target.symlink_to(link_to)
        done, out = _lookup_in_thread(record, "X_TOKEN")
        assert done, f"the lookup blocked on a link to {label} file"
        assert isinstance(out, ConfigFault), f"a link to {label} file was followed: {out!r}"
        assert "X_TOKEN_SECRET_REF" in str(out), out
        assert planted_value not in str(out), f"the link target's bytes reached the fault: {out}"

    target.unlink()
    os.mkfifo(target)
    done, out = _lookup_in_thread(record, "X_TOKEN")
    if not done:  # open a writer so the blocked reader returns and the worker exits
        os.close(os.open(target, os.O_WRONLY | os.O_NONBLOCK))
    assert done, "a FIFO with no writer at secrets.env blocked the lookup"
    assert isinstance(out, ConfigFault), f"a FIFO at secrets.env: {out!r}"
    assert "X_TOKEN_SECRET_REF" in str(out), out

    target.unlink()
    target.mkdir()
    done, out = _lookup_in_thread(record, "X_TOKEN")
    assert done, f"a directory at secrets.env: {out!r}"
    assert isinstance(out, ConfigFault), f"a directory at secrets.env: {out!r}"
    assert "X_TOKEN_SECRET_REF" in str(out), out

    # R2 (human): the refusal reaches EVERY component, not just the last. Swap a directory above
    # secrets.env for a link to bravo's — the path then ends at bravo's REGULAR file, which a
    # last-component no-follow open or lstat would accept. bravo declares the same name, so its
    # own record is the positive control that the target file itself is readable.
    target.rmdir()
    S.write_secrets(folder, {"X_TOKEN": own})
    assert record.secrets.get("X_TOKEN") == own, "control: the restored plain file resolves again"
    S.set_key(other_folder, "cmdb", "X_TOKEN_SECRET_REF", "X_TOKEN")
    bravo = run_tenant.resolve_tenant(root, "bravo", **RESOLVE)
    assert bravo.secrets.get("X_TOKEN") == other, "control: bravo's own file resolves for bravo"
    for label, swapped, link_to in (
            ("the settings/ folder", S.settings_of(folder), S.settings_of(other_folder)),
            ("the tenant folder", folder, other_folder)):
        aside = swapped.with_name(swapped.name + ".aside")
        swapped.rename(aside)
        swapped.symlink_to(link_to, target_is_directory=True)
        try:
            assert S.secrets_path(folder).is_file(), (
                f"precondition: through the link to {label}, secrets.env is a regular file")
            done, out = _lookup_in_thread(record, "X_TOKEN")
            assert done, f"the lookup blocked with {label} swapped for a link"
            assert isinstance(out, ConfigFault), (
                f"{label} swapped for a link to bravo's was followed: {out!r}")
            assert "X_TOKEN_SECRET_REF" in str(out), out
            assert other not in str(out), f"bravo's bytes reached the fault: {out}"
            assert bravo.secrets.get("X_TOKEN") == other, "control: bravo's own lookup still works"
        finally:
            swapped.unlink()
            aside.rename(swapped)
        assert record.secrets.get("X_TOKEN") == own, f"control: restoring {label} restores the lookup"

    # RV1 (human, reading A): a HARD link made at secrets.env after resolve is a regular file with
    # st_nlink > 1, which a no-follow open or an lstat of each component accepts. Resolve already
    # refuses one present at resolve (_tenants._refuse_links, _tenants.py:108-113; AP5); each
    # lookup refuses it too. Positive control: once the link is gone, the same record's lookup
    # answers its own value again, and bravo's answers bravo's.
    for label, planted_value, link_to in (
            ("another tenant's", other, S.secrets_path(other_folder)),
            ("a box-writable", boxed, box_file)):
        target.unlink()
        os.link(link_to, target)
        try:
            assert not target.is_symlink(), f"precondition: a hard link to {label} file is no symlink"
            assert target.lstat().st_nlink == 2, (
                f"precondition: secrets.env is a second name for {label} file")
            done, out = _lookup_in_thread(record, "X_TOKEN")
            assert done, f"the lookup blocked on a hard link to {label} file"
            assert isinstance(out, ConfigFault), f"a hard link to {label} file was read: {out!r}"
            assert "X_TOKEN_SECRET_REF" in str(out), out
            assert planted_value not in str(out), f"the hard link's bytes reached the fault: {out}"
        finally:
            target.unlink()
        S.write_secrets(folder, {"X_TOKEN": own})
        assert record.secrets.get("X_TOKEN") == own, (
            f"control: with the hard link to {label} file gone, the same lookup answers")
    assert bravo.secrets.get("X_TOKEN") == other, "control: bravo's own lookup answers once unlinked"


def test_s7_mf15_runtime_fault_names_declaring_key(tmp_path):
    """At runtime a declared reference whose held string is not a secrets.env key (malformed, or the
    secret itself) faults as a missing entry, and the ConfigFault text names the declaring key (for
    example FOO_TOKEN_SECRET_REF), never the string it holds."""
    good = _planted("good")
    root = tmp_path / "tenants"
    folder = S.plant(root, marker="mf15", secrets={"GOOD_TOKEN": good})
    S.set_key(folder, "cmdb", "GOOD_TOKEN_SECRET_REF", "GOOD_TOKEN")
    S.set_key(folder, "cmdb", "FOO_TOKEN_SECRET_REF", "hunter2-value!")  # the secret itself
    S.set_key(folder, "identity", "BAR_TOKEN_SECRET_REF", "has space=eq")  # malformed
    record = run_tenant.resolve_tenant(root, PID, **RESOLVE)

    assert record.secrets.get("GOOD_TOKEN") == good, "control: a well-formed reference resolves"
    for key, held in (("FOO_TOKEN_SECRET_REF", "hunter2-value!"),
                      ("BAR_TOKEN_SECRET_REF", "has space=eq")):
        with pytest.raises(ConfigFault) as fault:
            record.secrets.get(held)
        text = str(fault.value)
        assert key in text, f"the fault must name the declaring key {key}: {text!r}"
        assert held not in text, f"the fault carries the held string: {text!r}"
        assert good not in text, f"the fault carries a value: {text!r}"


def test_s7_f2_runtime_honours_uppercase_ref_only(tmp_path):
    """The runtime lookup declares names only from all-uppercase *_SECRET_REF keys: a name held by
    x_secret_ref or X_Secret_Ref, with a good secrets.env entry, is refused as undeclared, while the
    same reference spelled X_SECRET_REF resolves. The validator FAILs the other spellings
    (o8_ref_key_any_case), so the two readers agree."""
    vals = {n: _planted(n.lower()) for n in ("LOWER_NAME", "MIXED_NAME", "UPPER_NAME")}
    root = tmp_path / "tenants"
    folder = S.plant(root, marker="f2", secrets=vals)
    S.set_key(folder, "cmdb", "x_secret_ref", "LOWER_NAME")
    S.set_key(folder, "cmdb", "X_Secret_Ref", "MIXED_NAME")
    S.set_key(folder, "cmdb", "X_SECRET_REF", "UPPER_NAME")
    record = run_tenant.resolve_tenant(root, PID, **RESOLVE)

    assert record.secrets.get("UPPER_NAME") == vals["UPPER_NAME"], "control: uppercase resolves"
    for name in ("LOWER_NAME", "MIXED_NAME"):
        with pytest.raises(ConfigFault):
            record.secrets.get(name)
    report = validate_scaffold.Report()
    validate_scaffold.check_config(report, S.settings_of(folder), "cmdb")
    fails = _fails(report)
    for key in ("x_secret_ref", "X_Secret_Ref"):
        assert any(key in f for f in fails), f"the validator does not FAIL {key}: {report.rows}"
    about_upper = [f for f in fails if "UPPER_NAME" in f]
    assert about_upper == [], f"the validator FAILs the uppercase reference: {about_upper}"


# ======================================================================================
# S3 — the store is host-only.
# ======================================================================================

def test_model_asks_to_read_the_tenants_secrets_env(tmp_path):
    """The model's read tool and bash are refused settings/secrets.env, a git-ignored file outside
    today's committed-file census (G32), the same as any other file under the settings half, while a
    corpus file stays readable (the control)."""
    from defender.runtime import permission
    from defender.runtime.agent_definition import compile_policy_for
    from defender.runtime.permission.files import read_allowed_path

    # G32: the read surfaces deny settings by location (deny-by-default over the run dir and
    # defender_dir roots) — this pins that the location rule covers a file no census names.
    folder = S.plant(tmp_path / "tenants", marker="s048", secrets={"X_TOKEN": _planted("s048")})
    planted = S.secrets_path(folder)
    committed_spelling = S.PLAYGROUND / "settings" / S.SECRETS_ENV  # the operator's own path
    sibling = S.config_path(folder, "cmdb")
    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    driver = S.mod("runtime.driver")
    policies = {
        "main": compile_policy_for(driver.MAIN_DEF, run_dir, defender_dir=S.DEFENDER),
        "gather": compile_policy_for(T1106.playground_gather_def(), run_dir,
                                     defender_dir=S.DEFENDER),
    }
    control = S.DEFENDER / "skills" / "gather" / "SKILL.md"
    assert planted.is_file(), "the planted secrets.env is not there to be refused"
    for role, policy in policies.items():
        for path in (planted, committed_spelling, sibling):
            assert not permission.decide_read(
                path, run_dir=run_dir, defender_dir=S.DEFENDER, policy=policy).allow, (
                f"{role}'s read tool may read {path}")
            assert not read_allowed_path(
                path, run_dir=run_dir, defender_dir=S.DEFENDER, policy=policy), (
                f"{role}'s bash may read {path}")
        assert permission.decide_read(
            control, run_dir=run_dir, defender_dir=S.DEFENDER, policy=policy).allow, (
            f"control: {role}'s read tool is refused a corpus file")
        assert read_allowed_path(control, run_dir=run_dir, defender_dir=S.DEFENDER,
                                 policy=policy), f"control: {role}'s bash is refused a corpus file"


def test_s3_secrets_env_gitignored():
    """`git check-ignore` reports settings/secrets.env ignored wherever a tenant folder can sit in the
    checkout: knowledge/tenants/<id>/settings/secrets.env for the playground id and an arbitrary
    one, knowledge/tenant-template/settings/secrets.env, and a settings/secrets.env under any other
    directory (NF-30, auto, security-relevant). The test is red at base (CX7)."""
    paths = [
        "knowledge/tenants/playground/settings/secrets.env",
        f"knowledge/tenants/t{uuid.uuid4().hex[:8]}/settings/secrets.env",
        "knowledge/tenant-template/settings/secrets.env",
        "some/other/dir/settings/secrets.env",
    ]
    probe = ["git", "-C", str(S.REPO_ROOT), "check-ignore", "-q"]
    # Control: the probe CAN answer "not ignored" — a committed settings file beside it.
    committed = "knowledge/tenants/playground/settings/verb-grants.yaml"
    assert subprocess.run([*probe, committed], check=False).returncode == 1, (
        "git check-ignore reports a committed settings file ignored — the probe cannot discriminate")
    not_ignored = [p for p in paths if subprocess.run([*probe, p], check=False).returncode != 0]
    assert not_ignored == [], f"secrets.env is not git-ignored at: {not_ignored}"


def test_s7_nf13_fixture_copy_omits_secrets_env(tmp_path):
    """#1078's test-harness copy of the committed playground folder
    (_spec1078.tenants_root_beside_data_root) omits settings/secrets.env even when one exists on
    disk under the playground folder, while every other file is copied (the control); a scenario
    that needs a secret plants its own, and no test resolves a value it did not plant."""
    import inspect
    import shutil

    from defender.tests._data_root_1078 import ensure_d9_tenant
    from defender.tests.tenant_1078_pass_a import _spec1078

    # AF-7: nothing is written into the checkout. The source is a copy of the committed playground
    # under tmp_path with a secrets.env planted in its settings folder, handed to the helper under
    # the coined `source=` keyword (FIXTURE_SOURCE_KW) — no concurrent test can see the plant.
    copy_helper = _spec1078.tenants_root_beside_data_root
    assert S.FIXTURE_SOURCE_KW in inspect.signature(copy_helper).parameters, (
        f"the fixture copy takes no {S.FIXTURE_SOURCE_KW}= tree to copy from, so a test cannot "
        f"plant a secrets.env anywhere but the checkout: {inspect.signature(copy_helper)}")
    tenant_id = ensure_d9_tenant()
    source = tmp_path / "playground-source"
    shutil.copytree(S.PLAYGROUND, source)
    planted = source / "settings" / S.SECRETS_ENV
    planted.write_text(f'X_TOKEN="{_planted("nf13")}"\n', encoding="utf-8")

    tenants = copy_helper(**{S.FIXTURE_SOURCE_KW: source})
    copy = tenants / tenant_id
    committed = {p.relative_to(source).as_posix() for p in source.rglob("*")
                 if p.is_file() and p.name != S.SECRETS_ENV}
    copied = {p.relative_to(copy).as_posix() for p in copy.rglob("*") if p.is_file()}
    assert committed, "control: the source tree holds no committed file"
    assert committed <= copied, (
        f"control: the copy dropped committed files: {sorted(committed - copied)}")
    assert not (copy / "settings" / S.SECRETS_ENV).exists(), (
        "the harness copied the source tree's on-disk secrets.env into a test tenants root")


# ======================================================================================
# One parser, one blank rule — the validator and the lookup agree.
# ======================================================================================

def test_s7_nf10_blank_rule_shared(tmp_path):
    """validate_scaffold and the runtime lookup read secrets.env with the same parser and the same
    blank rule: a whitespace-only value counts as blank, a ConfigFault naming the reference when
    asked for and a FAIL in the validator, exactly as an empty value does."""
    good = _planted("good")
    root = tmp_path / "tenants"
    folder = S.plant(root, marker="nf10",
                     secrets=f'WS_ENTRY="   "\nEMPTY_ENTRY=""\nGOOD_ENTRY="{good}"\n')
    refs = {"A_WS_SECRET_REF": "WS_ENTRY", "B_EMPTY_SECRET_REF": "EMPTY_ENTRY",
            "C_GOOD_SECRET_REF": "GOOD_ENTRY"}
    for key, name in refs.items():
        S.set_key(folder, "cmdb", key, name)
    record = run_tenant.resolve_tenant(root, PID, **RESOLVE)
    report = validate_scaffold.Report()
    validate_scaffold.check_config(report, S.settings_of(folder), "cmdb")
    fails = _fails(report)

    assert record.secrets.get("GOOD_ENTRY") == good, "control: a non-blank entry resolves"
    assert not any("C_GOOD_SECRET_REF" in f for f in fails), f"a good reference FAILed: {fails}"
    for key in ("A_WS_SECRET_REF", "B_EMPTY_SECRET_REF"):
        with pytest.raises(ConfigFault) as fault:
            record.secrets.get(refs[key])
        assert key in str(fault.value), fault.value
        assert any(key in f for f in fails), f"the validator does not FAIL {key}: {report.rows}"


def test_s7_nf11_secrets_env_uses_the_one_parser(tmp_path):
    """secrets.env is read by the one config.env parser, with its rules: KEY=VALUE per line and one
    matched pair of quotes trimmed. An export-prefixed line and a quoted value spanning a newline
    are not entries of the intended name, and a name given twice resolves to the one value the
    parser keeps for a duplicate, identically in the validator and the lookup."""
    good = _planted("good")
    text = (
        'export EXP_ENTRY="exp-value"\n'
        'ML_ENTRY="line1\n'
        'line2"\n'
        'DUP_ENTRY="first"\n'
        'DUP_ENTRY="second"\n'
        f'GOOD_ENTRY="{good}"\n'
    )
    root = tmp_path / "tenants"
    folder = S.plant(root, marker="nf11", secrets=text)
    refs = {"A_EXP_SECRET_REF": "EXP_ENTRY", "B_ML_SECRET_REF": "ML_ENTRY",
            "C_DUP_SECRET_REF": "DUP_ENTRY", "D_GOOD_SECRET_REF": "GOOD_ENTRY"}
    for key, name in refs.items():
        S.set_key(folder, "cmdb", key, name)
    record = run_tenant.resolve_tenant(root, PID, **RESOLVE)
    report = validate_scaffold.Report()
    validate_scaffold.check_config(report, S.settings_of(folder), "cmdb")
    fails = _fails(report)

    assert record.secrets.get("GOOD_ENTRY") == good, "one matched pair of quotes is trimmed"
    # The parser keeps the later line of a duplicate (observed in both of today's parsers, in
    # RG4's executed OBS).
    assert record.secrets.get("DUP_ENTRY") == "second", "a duplicate resolved to another value"
    with pytest.raises(ConfigFault):
        record.secrets.get("EXP_ENTRY")  # an export-prefixed line is not EXP_ENTRY's entry
    multi = _raises(lambda: record.secrets.get("ML_ENTRY"))
    assert not (isinstance(multi, str) and "line2" in multi), (
        f"a quoted value spanning a newline became the intended entry: {multi!r}")
    # Identically in the validator: it FAILs a reference exactly when the lookup refuses it.
    for key, name in refs.items():
        refused = isinstance(_raises(lambda n=name: record.secrets.get(n)), ConfigFault)
        failed = any(key in f for f in fails)
        assert refused == failed, (
            f"{key}: the lookup {'refuses' if refused else 'resolves'} {name} but the validator "
            f"{'FAILs' if failed else 'passes'} it: {report.rows}")
