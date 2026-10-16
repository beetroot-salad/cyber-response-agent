"""Adapters read their system's settings from the run's tenant record (config.env), never the process env; config faults, docker destinations and breaker accounting."""
from __future__ import annotations

import http.server
import json
import shutil
import threading
from pathlib import Path

import pytest

from defender.runtime import circuit_breaker
from defender.runtime.circuit_breaker import RunAborted
from defender.scripts.adapters import _stub_transport as transport
from defender.scripts.adapters import (
    change_mgmt_adapter,
    cmdb_adapter,
    elastic_adapter,
    host_state_adapter,
    identity_adapter,
    threat_intel_adapter,
    ticket_adapter,
)
from defender.scripts.adapters.faults import AdapterFault, ConfigFault, TransportFault
from defender.tests import _tenants1106 as T1106
from defender.tests._by_path import load_module
from defender.tests.tenant_1107_settings import _spec1107 as S

# ---------------------------------------------------------------------------------------------
# Canned docker answers. Each is the transport's own contract: curl's body, then `-w
# '\n%{http_code}'`'s status on a trailing line (`split_status`), or a bare stdout for a non-curl
# docker call. None is a fault, so none needs a claim beyond that contract.
# ---------------------------------------------------------------------------------------------

_OK = S.answer('{"status": "ok"}')
_HOST = S.answer('{"hostname": "web-1"}')
_SEARCH = S.answer(json.dumps({"hits": {"total": {"value": 0}, "hits": []}}))
_ES_HEALTH = S.answer(json.dumps({"status": "green", "number_of_nodes": 1}))
_KB_STATUS = S.answer(json.dumps({"status": {"overall": {"level": "available"}}}))
_PS = S.answer("PID PPID USER\n1 0 root", None)
#: `docker inspect --format '{{json .Name}}\t{{json .Config.Image}}'`'s observed success shape, and
#: its observed answer for a container that does not exist (AP4, executed on docker 29.x): the
#: daemon's text is lower-case "error: no such object: <id>" on stderr, rc=1.
_INSPECT = S.answer('"/web-1"\t"nginx:1.27"\n', None)
_INSPECT_MISSING = S.answer("", None, rc=1, stderr="error: no such object: c0ffee1107\n")
_NAMES = S.answer("web-1\nweb-2", None)

#: The five stub systems that have an adapter module (case-history's reader is the ticket writer).
_STUB_ADAPTERS = {
    "cmdb": cmdb_adapter,
    "identity": identity_adapter,
    "ticket": ticket_adapter,
    "change-mgmt": change_mgmt_adapter,
    "threat-intel": threat_intel_adapter,
}


def _tenant(tmp_path: Path, marker: str, *, name: str = "t", **kw) -> tuple[Path, Path]:
    """A planted #1107 tenant under `tmp_path/<name>`: (tenants root, tenant folder)."""
    root = tmp_path / name
    return root, S.plant(root, marker=marker, **kw)


def _ctx(record, where: Path, shim: S.DockerShim, **env: str):
    """A `VerbContext` over `record` whose env puts `shim` first on PATH."""
    run_dir = where / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    return S.verb_context(record, run_dir, shim.env(**env))


def _argvs(shim: S.DockerShim, since: int = 0) -> list[list[str]]:
    return [c["argv"] for c in shim.calls()[since:]]


def _raised(fn, *args, **kw) -> BaseException | None:
    """What `fn(*args, **kw)` raised, or None when it returned."""
    try:
        fn(*args, **kw)
    except Exception as exc:  # noqa: BLE001 — the test inspects whatever the verb raised
        return exc
    return None


def _max_time(argv: list[str]) -> str | None:
    """The `--max-time` value a docker-exec'd curl carries."""
    return argv[argv.index("--max-time") + 1] if "--max-time" in argv else None


def _run_state(run_dir: Path):
    """A run's state over `run_dir` (#1235 round 2): the breaker lives on the run's one
    `RunState`, no longer in a table keyed by the folder."""
    from defender.runtime.run_state import RunState

    return RunState(run_dir, "t1107")


def _breaker_run(run_dir: Path, outcomes: list[tuple[str, int]]) -> tuple[list[int], RunAborted | None]:
    """Feed `(system, exit_code)` outcomes to the real breaker of one run over `run_dir`, in
    order: the running total after each call that did not abort, and the `RunAborted` that
    stopped the run (None if none did)."""
    run_state = _run_state(run_dir)
    totals: list[int] = []
    for system, code in outcomes:
        try:
            state = circuit_breaker.record_outcome(run_state, system, code)
        except RunAborted as aborted:
            return totals, aborted
        totals.append(state.get("total_failures", 0))
    return totals, None


# ---------------------------------------------------------------------------------------------
# load_config and the record
# ---------------------------------------------------------------------------------------------

def test_d_load_config_shape_survives(tmp_path):
    """An adapter's load_config still returns its prefix-stripped keys (URL_BASE, BASTION_HOST,
    TIMEOUT_SEC for a stub system, and the elastic key set for elastic). It still raises
    ConfigFault naming each missing required key. It now reads them from the record's systems
    entry: with the config.env file deleted after the record is built, load_config still answers
    from the entry."""
    m = "lcs"
    root, folder = _tenant(tmp_path, m)
    record = S.resolve(root)
    for system in ("cmdb", "elastic"):
        S.config_path(folder, system).unlink()
    assert not S.config_path(folder, "cmdb").exists(), "precondition: cmdb's file is gone"
    shim = S.DockerShim(tmp_path / "shim")
    ctx = _ctx(record, tmp_path, shim)

    cmdb = transport.load_config(ctx, "cmdb", "CMDB")
    want = {"URL_BASE": f"http://cmdb-{m}:8080", "BASTION_HOST": f"bastion-{m}",
            "TIMEOUT_SEC": "10"}
    assert {k: cmdb.get(k) for k in want} == want, \
        f"cmdb's load_config lost its prefix-stripped keys or their file values: {cmdb}"
    assert not [k for k in cmdb if k.startswith("CMDB_")], \
        f"cmdb's load_config returned prefixed keys (its shape changed): {sorted(cmdb)}"

    elastic = elastic_adapter.load_config(ctx)
    want_es = {"ELASTICSEARCH_URL": f"https://es-{m}:9200", "KIBANA_URL": f"http://kibana-{m}:5601",
               "ELASTIC_EVENTS_INDEX": f"{m}-events-*", "ELASTIC_ALERTS_INDEX": f"{m}-alerts-*"}
    assert {k: elastic.get(k) for k in want_es} == want_es, \
        f"elastic's load_config lost its key set or their file values: {elastic}"
    assert shim.calls() == [], "load_config spawned a docker child"

    # Missing required keys, judged from the entry: the file is deleted after resolve here too.
    root2, folder2 = _tenant(tmp_path, "lcm", name="t2")
    S.drop_key(folder2, "cmdb", "CMDB_BASTION_HOST")
    S.drop_key(folder2, "elastic", "KIBANA_URL")
    record2 = S.resolve(root2)
    for system in ("cmdb", "elastic"):
        S.config_path(folder2, system).unlink()
    ctx2 = _ctx(record2, tmp_path / "t2", shim)
    fault = _raised(transport.load_config, ctx2, "cmdb", "CMDB")
    assert isinstance(fault, ConfigFault), f"a missing CMDB_BASTION_HOST must be a ConfigFault naming it, got {fault!r}"
    assert "CMDB_BASTION_HOST" in str(fault), f"a missing CMDB_BASTION_HOST must be a ConfigFault naming it, got {fault!r}"
    fault = _raised(elastic_adapter.load_config, ctx2)
    assert isinstance(fault, ConfigFault), f"a missing KIBANA_URL must be a ConfigFault naming it, got {fault!r}"
    assert "KIBANA_URL" in str(fault), f"a missing KIBANA_URL must be a ConfigFault naming it, got {fault!r}"




# ---------------------------------------------------------------------------------------------
# D2: the access method, per system
# ---------------------------------------------------------------------------------------------

def test_d2_transport_domain(tmp_path):
    """A system's <PREFIX>_TRANSPORT decides how the system is reached. With docker-exec it is
    reached through docker exec on its own Docker context. With the key absent, the system's
    calls raise ConfigFault naming the missing key: the system is down and the run goes on. With
    the key blank, a near-miss spelling (Docker-Exec, docker_exec) or any other value (http,
    documented as future by N1), the system's calls raise ConfigFault naming the unimplemented
    method (F4, human; NF-29: an exact match after the one parser's trimming): the system is
    down and the run goes on."""
    # rejected: N1: no plain-HTTP transport in this issue
    root, _ = _tenant(tmp_path, "tdok", name="ok")
    shim = S.DockerShim(tmp_path / "ok" / "shim", [_OK])
    cmdb_adapter.health_check(_ctx(S.resolve(root), tmp_path / "ok", shim))
    [argv] = _argvs(shim)
    assert S.context_of(argv) == S.context_name("tdok", "cmdb"), f"docker-exec must reach cmdb by docker exec on its own context: {argv}"
    assert "exec" in argv, f"docker-exec must reach cmdb by docker exec on its own context: {argv}"
    assert S.curl_url(argv) == "http://cmdb-tdok:8080/health", f"wrong target: {argv}"

    variants = {"absent": None, "blank": "", "Docker-Exec": "Docker-Exec",
                "docker_exec": "docker_exec", "http": "http", "other": "kubectl-exec"}
    for i, (label, value) in enumerate(variants.items()):
        m = f"td{i}"
        root, folder = _tenant(tmp_path, m, name=f"v{i}")
        if value is None:
            S.drop_key(folder, "cmdb", "CMDB_TRANSPORT")
        else:
            S.set_key(folder, "cmdb", "CMDB_TRANSPORT", value)
        record = S.resolve(root)  # the run is not refused: the system is down, not the run
        shim = S.DockerShim(tmp_path / f"v{i}" / "shim", [_OK])
        ctx = _ctx(record, tmp_path / f"v{i}", shim)
        fault = _raised(cmdb_adapter.health_check, ctx)
        assert isinstance(fault, ConfigFault), f"CMDB_TRANSPORT {label}: expected ConfigFault (exit 2), got {fault!r}"
        assert fault.exit_code == 2, f"CMDB_TRANSPORT {label}: expected ConfigFault (exit 2), got {fault!r}"
        assert _argvs(shim) == [], f"CMDB_TRANSPORT {label}: a docker child ran: {_argvs(shim)}"
        if value is None:
            assert "CMDB_TRANSPORT" in str(fault), f"absent: the fault must name the key: {fault}"
        elif value:
            assert value in str(fault), f"{label}: the fault must name the method {value!r}: {fault}"
        # The run goes on: the sibling system in the same record still answers.
        identity_adapter.health_check(ctx)
        assert [S.context_of(a) for a in _argvs(shim)] == [S.context_name(m, "identity")], \
            f"CMDB_TRANSPORT {label}: identity no longer answers on its own context"


def test_d2_docker_context_per_system(tmp_path):
    """Each system's docker exec runs against that system's own <PREFIX>_DOCKER_CONTEXT, and so
    does host-state's docker inspect (container_inspect, docker_inspect_raw's call site, CX13).
    Two systems whose config.env files name different contexts produce child argv that each carry
    `--context <its own>`. A system whose config lacks the key raises ConfigFault when called,
    and no call, and no fault text, falls back to soc-playground."""
    m = "dcp"
    root, _ = _tenant(tmp_path, m)
    shim = S.DockerShim(tmp_path / "shim", [_OK])
    ctx = _ctx(S.resolve(root), tmp_path, shim)
    cmdb_adapter.health_check(ctx)
    identity_adapter.health_check(ctx)
    shim.respond(_PS)
    host_state_adapter.proc_tree(ctx, host="web-1")  # docker_exec_raw's call site
    shim.respond(_INSPECT)
    inspected = host_state_adapter.container_inspect(ctx, container_id="c0ffee1107")  # R5, CX13
    assert inspected.get("name") == "web-1", f"control: the inspect answer was parsed: {inspected}"
    got = [S.context_of(a) for a in _argvs(shim)]
    want = [S.context_name(m, s) for s in ("cmdb", "identity", "host-state", "host-state")]
    assert got == want, f"each system's child must carry --context <its own>: {got} != {want}"
    assert "inspect" in _argvs(shim)[-1], f"control: the last child is docker inspect: {_argvs(shim)[-1]}"
    # The not-found answer (AP4): the call still addresses host-state's own context, and whatever
    # fault it raises names no fallback context.
    shim.respond(_INSPECT_MISSING)
    missing = _raised(host_state_adapter.container_inspect, ctx, container_id="c0ffee1107")
    assert isinstance(missing, AdapterFault), f"a missing container must fault, got {missing!r}"
    assert S.context_of(_argvs(shim)[-1]) == S.context_name(m, "host-state"), _argvs(shim)[-1]
    assert "soc-playground" not in str(missing), f"the inspect fault names a fallback context: {missing}"

    root2, folder2 = _tenant(tmp_path, "dcx", name="t2")
    S.drop_key(folder2, "cmdb", "CMDB_DOCKER_CONTEXT")
    shim2 = S.DockerShim(tmp_path / "shim2", [_OK])
    ctx2 = _ctx(S.resolve(root2), tmp_path / "t2", shim2)
    fault = _raised(cmdb_adapter.health_check, ctx2)
    assert isinstance(fault, ConfigFault), f"a cmdb config without CMDB_DOCKER_CONTEXT must fault naming it, got {fault!r}"
    assert "CMDB_DOCKER_CONTEXT" in str(fault), f"a cmdb config without CMDB_DOCKER_CONTEXT must fault naming it, got {fault!r}"
    assert _argvs(shim2) == [], f"cmdb without a context spawned a child: {_argvs(shim2)}"
    identity_adapter.health_check(ctx2)
    assert [S.context_of(a) for a in _argvs(shim2)] == [S.context_name("dcx", "identity")], \
        "positive control: identity, which names its context, still answers on it"
    every = [tok for a in _argvs(shim) + _argvs(shim2) for tok in a]
    assert "soc-playground" not in every, "a call fell back to soc-playground (CX17's default)"


def test_d2_elastic_containers_no_default(tmp_path):
    """Elastic's docker exec targets the tenant file's ELASTIC_ES_CONTAINER for Elasticsearch
    URLs and its ELASTIC_KIBANA_CONTAINER for Kibana URLs. The write door takes its container
    from the same key. With either key absent elastic
    calls fault; nothing falls back to 'elasticsearch' or 'kibana' (CX17)."""
    # This slice drives the adapter half only; the write door's half is fork E1's (the door's
    # new signature is not named by the design, so it is not guessed here).
    m = "ecn"
    root, _ = _tenant(tmp_path, m)
    shim_q = S.DockerShim(tmp_path / "shim", [_SEARCH])
    ctx = _ctx(S.resolve(root), tmp_path, shim_q)
    elastic_adapter.query(ctx, native_query="*")
    shim_h = S.DockerShim(tmp_path / "shim-h", [_ES_HEALTH, _KB_STATUS])
    elastic_adapter.health_check(_ctx(S.record_on(ctx), tmp_path, shim_h))
    [es_argv] = _argvs(shim_q)
    assert S.exec_target(es_argv) == S.es_container(m), \
        f"an Elasticsearch URL must target ELASTIC_ES_CONTAINER: {es_argv}"
    health = _argvs(shim_h)
    assert [S.exec_target(a) for a in health] == [S.es_container(m), S.kibana_container(m)], \
        f"health_check must target ES then Kibana by the file's containers: {health}"

    for key in ("ELASTIC_ES_CONTAINER", "ELASTIC_KIBANA_CONTAINER"):
        name = key.lower()
        root_k, folder_k = _tenant(tmp_path, "ecx", name=name)
        S.drop_key(folder_k, "elastic", key)
        record = S.resolve(root_k)
        shim_k = S.DockerShim(tmp_path / name / "shim", [_SEARCH])
        ctx_k = _ctx(record, tmp_path / name, shim_k)
        if key == "ELASTIC_ES_CONTAINER":
            fault = _raised(elastic_adapter.query, ctx_k, native_query="*")
            assert isinstance(fault, ConfigFault), f"{key} absent: query must fault, got {fault!r}"
            assert _argvs(shim_k) == [], f"{key} absent: a docker child ran: {_argvs(shim_k)}"
        else:
            shim_k.respond(_ES_HEALTH, _KB_STATUS)
            _raised(elastic_adapter.health_check, ctx_k)
        targets = [S.exec_target(a) for a in _argvs(shim_k)]
        assert not {"elasticsearch", "kibana", "", None} & set(targets), \
            f"{key} absent: a call fell back to a built-in container (CX17): {targets}"




# ---------------------------------------------------------------------------------------------
# O1 / O2: the file as of resolve, never the environment
# ---------------------------------------------------------------------------------------------



def test_o2_adapter_config_snapshot(tmp_path):
    """After the record is built, editing a system's config.env (cmdb's URL, elastic's index)
    does not change the next adapter call, which still addresses the value as of the run's
    start."""
    # rejected: N7: no run snapshot file is written
    # rejected: N6: siblings of one episode each build their own record at their own start
    m = "ocs"
    root, folder = _tenant(tmp_path, m)
    record = S.resolve(root)
    S.set_key(folder, "cmdb", "CMDB_URL_BASE", "http://edited-cmdb:9")
    S.set_key(folder, "elastic", "ELASTIC_EVENTS_INDEX", "edited-*")
    shim = S.DockerShim(tmp_path / "shim", [_HOST])
    ctx = _ctx(record, tmp_path, shim)
    cmdb_adapter.get_host(ctx, host="web-1")
    shim.respond(_SEARCH)
    elastic_adapter.query(ctx, native_query="*")
    cmdb_argv, es_argv = _argvs(shim)
    assert S.curl_url(cmdb_argv) == f"http://cmdb-{m}:8080/hosts/web-1", \
        f"cmdb's call followed an edit made after resolve: {cmdb_argv}"
    assert f"/{m}-events-*/_search" in (S.curl_url(es_argv) or ""), \
        f"elastic's call followed an index edit made after resolve: {es_argv}"

    # Positive control: the edit is real, so a record built after it does address it.
    shim2 = S.DockerShim(tmp_path / "shim2", [_HOST])
    cmdb_adapter.get_host(_ctx(S.resolve(root), tmp_path / "later", shim2), host="web-1")
    assert S.curl_url(_argvs(shim2)[0]) == "http://edited-cmdb:9/hosts/web-1", \
        "precondition: a record resolved after the edit must see it"


# ---------------------------------------------------------------------------------------------
# §6/§7 value domains: empty, absent, dash-leading
# ---------------------------------------------------------------------------------------------

def test_s60_url_base_empty_is_missing(tmp_path):
    """A stub system's <PREFIX>_URL_BASE set to the empty string counts as missing to
    load_config's required-key check (design doc, Data model): load_config raises ConfigFault
    naming URL_BASE, the same as if the key were absent."""
    root, folder = _tenant(tmp_path, "sue")
    shim = S.DockerShim(tmp_path / "shim", [_HOST])
    present = transport.load_config(_ctx(S.resolve(root), tmp_path / "p", shim), "cmdb", "CMDB")
    assert present.get("URL_BASE") == "http://cmdb-sue:8080", \
        f"precondition: with the key set, load_config returns it: {present}"

    faults = {}
    for label in ("empty", "absent"):
        if label == "empty":
            S.set_key(folder, "cmdb", "CMDB_URL_BASE", "")
        else:
            S.drop_key(folder, "cmdb", "CMDB_URL_BASE")
        ctx = _ctx(S.resolve(root), tmp_path / label, shim)
        faults[label] = _raised(transport.load_config, ctx, "cmdb", "CMDB")
        assert isinstance(faults[label], ConfigFault), f"CMDB_URL_BASE {label}: expected a ConfigFault naming it, got {faults[label]!r}"
        assert "CMDB_URL_BASE" in str(faults[label]), f"CMDB_URL_BASE {label}: expected a ConfigFault naming it, got {faults[label]!r}"
        assert isinstance(_raised(cmdb_adapter.get_host, ctx, host="web-1"), ConfigFault), \
            f"CMDB_URL_BASE {label}: the verb must fault too"
    assert str(faults["empty"]) == str(faults["absent"]), \
        f"an empty CMDB_URL_BASE must fault the same as an absent one: {faults}"
    assert _argvs(shim) == [], f"a call with no URL_BASE spawned a child: {_argvs(shim)}"


def test_s60_timeout_sec_empty_and_request_reads_current_value(tmp_path):
    """An empty <PREFIX>_TIMEOUT_SEC counts as missing (the design: empty counts as missing), and a
    non-digit one is bad config, that system down (O5): either way the call raises a ConfigFault
    naming the key at call time, not at resolve, and spawns no docker child. After the migration
    to load_config reading the record's systems entry, _request still sees the tenant's current
    TIMEOUT_SEC value (not a stale copy)."""
    # AF-3a (auto, text-grounded): the seed's ValueError carried F29's non-digit observation over
    # to '' unprobed; the design's "empty counts as missing" decides it — a ConfigFault, the same
    # required-key shape as s60_url_base_empty_is_missing. R3 (human-confirmed): a non-digit value
    # is a ConfigFault too. F29 stays a true observation of BASE (int()'s ValueError at
    # `_stub_transport._request`); this change replaces that behaviour, it is not the contract.
    records = {}
    for name, timeout in (("a", "7"), ("b", "3"), ("e", ""), ("n", "ten")):
        root, folder = _tenant(tmp_path, f"st{name}", name=name)
        S.set_key(folder, "cmdb", "CMDB_TIMEOUT_SEC", timeout)
        records[name] = S.resolve(root)  # an empty TIMEOUT_SEC does not refuse the run

    shim = S.DockerShim(tmp_path / "shim", [_HOST])
    for name in ("a", "b", "a"):
        cmdb_adapter.get_host(_ctx(records[name], tmp_path / name, shim), host="web-1")
    got = [_max_time(a) for a in _argvs(shim)]
    assert got == ["7", "3", "7"], \
        f"_request must use each call's own record's TIMEOUT_SEC, never a stale copy: {got}"

    for name, what in (("e", "an empty"), ("n", "a non-digit")):
        before = len(shim.calls())
        fault = _raised(cmdb_adapter.get_host, _ctx(records[name], tmp_path / name, shim),
                        host="web-1")
        assert isinstance(fault, ConfigFault), \
            f"{what} TIMEOUT_SEC must be a ConfigFault at call time (system down), got {fault!r}"
        assert "CMDB_TIMEOUT_SEC" in str(fault), f"{what} TIMEOUT_SEC: the ConfigFault must name the key: {fault!r}"
        assert _argvs(shim, before) == [], f"{what} TIMEOUT_SEC spawned a child: {_argvs(shim, before)}"




def test_s7_mf3_empty_destination_is_config_fault(tmp_path):
    """An empty or missing destination value is that system down, never a deferral. With
    <PREFIX>_DOCKER_CONTEXT absent, empty or whitespace-only in a system's config.env, that
    system's calls raise ConfigFault naming the key and spawn no docker child, so docker's own
    deferral of --context '' to DOCKER_CONTEXT or the current context never happens
    (F1/G23/RG1). The same holds for elastic's ELASTIC_ES_CONTAINER and
    ELASTIC_KIBANA_CONTAINER: an empty value makes elastic
    calls fault. The rule is stated over the value the access method addresses, not over docker
    (transport-agnostic)."""
    # G23: `--context ''` answers rc=0 on the default daemon, or on DOCKER_CONTEXT's name when
    # that is set — so the only safe empty context is one that never reaches docker.
    root, _ = _tenant(tmp_path, "mdp", name="p")
    shim = S.DockerShim(tmp_path / "p" / "shim", [_OK])
    cmdb_adapter.health_check(_ctx(S.resolve(root), tmp_path / "p", shim))
    assert [S.context_of(a) for a in _argvs(shim)] == [S.context_name("mdp", "cmdb")], \
        "precondition: a configured context reaches docker as its own name"

    for i, value in enumerate((None, "", "   ")):
        root, folder = _tenant(tmp_path, f"md{i}", name=f"c{i}")
        if value is None:
            S.drop_key(folder, "cmdb", "CMDB_DOCKER_CONTEXT")
        else:
            S.set_key(folder, "cmdb", "CMDB_DOCKER_CONTEXT", value)
        shim = S.DockerShim(tmp_path / f"c{i}" / "shim", [_OK])
        ctx = _ctx(S.resolve(root), tmp_path / f"c{i}", shim, DOCKER_CONTEXT="steered-elsewhere")
        fault = _raised(cmdb_adapter.health_check, ctx)
        assert isinstance(fault, ConfigFault), f"CMDB_DOCKER_CONTEXT={value!r}: expected a ConfigFault naming it, got {fault!r}"
        assert "CMDB_DOCKER_CONTEXT" in str(fault), f"CMDB_DOCKER_CONTEXT={value!r}: expected a ConfigFault naming it, got {fault!r}"
        assert _argvs(shim) == [], f"CMDB_DOCKER_CONTEXT={value!r} spawned a child: {_argvs(shim)}"

    for key in ("ELASTIC_ES_CONTAINER", "ELASTIC_KIBANA_CONTAINER"):
        name = key.lower()
        root, folder = _tenant(tmp_path, "mde", name=name)
        S.set_key(folder, "elastic", key, "")
        record = S.resolve(root)
        shim = S.DockerShim(tmp_path / name / "shim", [_ES_HEALTH, _KB_STATUS])
        ctx = _ctx(record, tmp_path / name, shim)
        if key == "ELASTIC_ES_CONTAINER":
            fault = _raised(elastic_adapter.query, ctx, native_query="*")
            assert isinstance(fault, ConfigFault), f"{key}='': query must fault, got {fault!r}"
            assert _argvs(shim) == [], f"{key}='': a docker child ran: {_argvs(shim)}"
        else:
            _raised(elastic_adapter.health_check, ctx)
            kibana = [a for a in _argvs(shim)
                      if (S.curl_url(a) or "").startswith("http://kibana-mde:5601")]
            assert kibana == [], f"{key}='': a Kibana call still reached docker: {kibana}"
        empty = [a for a in _argvs(shim) if S.exec_target(a) in ("", None)]
        assert empty == [], f"{key}='': a child targeted an empty container: {empty}"


def test_s7_mf3_destination_never_from_process_env(tmp_path, monkeypatch):
    """With DOCKER_CONTEXT, SOC_PLAYGROUND_DOCKER_CONTEXT, SOC_PLAYGROUND_ES_CONTAINER and
    SOC_PLAYGROUND_KIBANA_CONTAINER exported in the launching process and present in ctx.env,
    every docker child a configured system's call spawns names the tenant file's context
    explicitly as its --context value (never omitted, never empty) and targets the tenant file's
    container: no destination is taken from the process environment."""
    # rejected: stripping docker's own steering variables from the child environment: waived (w_mf3_docker_steering_vars) to the per-tenant hands box follow-up
    exported = {"DOCKER_CONTEXT": "env-docker-ctx", "SOC_PLAYGROUND_DOCKER_CONTEXT": "env-spg-ctx",
                "SOC_PLAYGROUND_ES_CONTAINER": "env-es-c", "SOC_PLAYGROUND_KIBANA_CONTAINER": "env-kb-c"}
    for key, value in exported.items():
        monkeypatch.setenv(key, value)
    m = "mdn"
    root, _ = _tenant(tmp_path, m)
    shim = S.DockerShim(tmp_path / "shim", [_HOST])
    ctx = _ctx(S.resolve(root), tmp_path, shim, **exported)
    assert {k: ctx.env.get(k) for k in exported} == exported, \
        "precondition: the steering variables are in the run's ctx.env"

    expected: list[tuple[str, str | None]] = []  # (context, container) per child, in order

    def call(answers, fn, *, want, **kw):
        shim.respond(*answers)
        before = len(shim.calls())
        fn(ctx, **kw)
        return _argvs(shim, before), want

    groups = [
        call([_HOST], cmdb_adapter.get_host, host="web-1",
             want=[("cmdb", f"bastion-{m}")]),
        call([_PS], host_state_adapter.proc_tree, host="web-1",
             want=[("host-state", "web-1")]),
        call([_NAMES], host_state_adapter.health_check,
             want=[("host-state", None)]),
        call([_SEARCH], elastic_adapter.query, native_query="*",
             want=[("elastic", S.es_container(m))]),
    ]
    fresh = S.DockerShim(tmp_path / "shim-h", [_ES_HEALTH, _KB_STATUS])
    elastic_adapter.health_check(_ctx(S.record_on(ctx), tmp_path, fresh, **exported))
    groups.append((_argvs(fresh), [("elastic", S.es_container(m)), ("elastic", S.kibana_container(m))]))

    for argvs, want in groups:
        assert len(argvs) == len(want), f"unexpected child count {argvs} for {want}"
        for argv, (system, container) in zip(argvs, want, strict=True):
            expected.append((S.context_name(m, system), container))
            assert S.context_of(argv) == S.context_name(m, system), \
                f"{system}'s child must name the file's context explicitly: {argv}"
            if container is not None:
                assert S.exec_target(argv) == container, \
                    f"{system}'s child must target the file's container {container}: {argv}"
            leaked = [v for v in exported.values() if any(v in tok for tok in argv)]
            assert leaked == [], f"{system}'s child took a destination from the env: {leaked}"
    assert len(expected) == 6, f"precondition: every call spawned its children: {expected}"


def test_s7_nf6_dash_leading_context_is_a_name(tmp_path):
    """A <PREFIX>_DOCKER_CONTEXT value that starts with a dash (-tlsverify,
    --host=tcp://elsewhere) reaches docker only as the context name: the child argv carries it
    as the --context value, never as a flag of its own, and a name docker does not know faults
    as that system being down (an exit-2 fault the breaker counts, as today) with no call
    reaching any daemon."""
    for i, value in enumerate(("-tlsverify", "--host=tcp://elsewhere")):
        root, folder = _tenant(tmp_path, f"nf{i}", name=f"t{i}")
        S.set_key(folder, "cmdb", "CMDB_DOCKER_CONTEXT", value)
        # G23/RG3: docker answers an unknown name — a dash-leading one included, taken literally
        # in both argv shapes — rc=1 'context not found'.
        shim = S.DockerShim(tmp_path / f"t{i}" / "shim", [S.context_not_found(value)])
        ctx = _ctx(S.resolve(root), tmp_path / f"t{i}", shim)
        fault = _raised(cmdb_adapter.health_check, ctx)
        [argv] = _argvs(shim)
        assert S.context_of(argv) == value, f"{value!r} must be the --context value: {argv}"
        loose = [j for j, tok in enumerate(argv) if tok == value and argv[j - 1] != "--context"]
        assert loose == [], f"{value!r} appears as a flag of its own in {argv}"
        assert isinstance(fault, AdapterFault), f"an unknown context must be the system down (exit 2), got {fault!r}"
        assert fault.exit_code == 2, f"an unknown context must be the system down (exit 2), got {fault!r}"
        state = circuit_breaker.record_outcome(_run_state(ctx.run_dir), "cmdb", fault.exit_code)
        assert state.get("systems", {}).get("cmdb", {}).get("failures") == 1, \
            f"the breaker must count the fault: {state}"


# ---------------------------------------------------------------------------------------------
# The breaker
# ---------------------------------------------------------------------------------------------

_REPLAY_TABLE = """\
dispositions:
  cmdb:
    get-host: {roles: [gather]}
    health-check: {roles: [gather]}
  identity:
    health-check: {roles: [gather]}
  threat-intel:
    health-check: {roles: [gather]}
"""


def _replay(tmp_path: Path, tenant_root: Path, verbs, calls: list[tuple[str, str, dict]],
            *, lead_system: str):
    """Drive a real run through the replay harness: main dispatches one gather lead, gather
    replays `calls` as `query` tool calls against `verbs`. Returns (run_dir, main, gather,
    run_state) — the run's `RunState` as `drive()` hands it back (#1235)."""
    from defender.tests.e2e._replay_harness import (
        GOLDEN_AB3, ReplayFn, Turn, drive, materialize)

    run_dir = materialize(tmp_path / "replay", GOLDEN_AB3, run_id='t1107b')
    main = ReplayFn([
        Turn(tool_calls=[("gather", {
            "lead_id": "l-001", "system": lead_system, "goal": "measure this lead",
            "what_to_summarize": ["host facts"],
        })]),
        Turn(text="Investigation complete."),
    ])
    gather = ReplayFn(
        [Turn(tool_calls=[("query", {"system": s, "verb": v, "params": p})]) for s, v, p in calls]
        + [Turn(text="Summary: measured the lead.")])
    summary = drive(run_dir, run_id="t1107b", main=main, gather=gather, verbs=verbs,
                    tenant=S.tenant_folder_of(tenant_root))
    return run_dir, main, gather, summary["run_state"]


def _own_rows(run_dir: Path) -> list[dict]:
    from defender._io import read_jsonl_rows
    from defender.runtime.lead_zero import RESERVED_LEAD_IDS

    return [r for r in read_jsonl_rows(run_dir / "executed_queries.jsonl")
            if r.get("lead_id") not in RESERVED_LEAD_IDS]


def _breaker_doc(run_state) -> dict:
    """The run's breaker state, read off the run's `RunState` (#1235: nothing writes
    `circuit_breaker.json` any more); it stays readable here after the driven run."""
    return run_state.breaker_snapshot()


def test_sibling_system_calls_share_one_docker_context_partial_failure(tmp_path, monkeypatch):
    """Two systems sharing one docker context: a transient failure on one system's call is
    attributed to that system alone; the sibling system's own successful call is unaffected."""
    pytest.importorskip("pydantic_ai")
    from defender.tests.e2e._replay_harness import FakeVerbs

    # Each transient failure is a shape the real tooling was observed to produce (AP3,
    # 82-author-probes.md): the daemon's "No such container" and "is not running" (rc=1) and
    # curl's --max-time timeout (rc=28), each with its own diagnostic stderr — never a bare exit.
    transient = {"no-such-container": S.no_such_container("bastion-sib"),
                 "not-running": S.container_not_running(),
                 "timed-out": S.curl_timed_out()}
    for label, failure in transient.items():
        m = "sib"
        shared = f"shared-ctx-{m}"
        where = tmp_path / label
        root, folder = _tenant(where, m, table=_REPLAY_TABLE)
        S.set_key(folder, "cmdb", "CMDB_DOCKER_CONTEXT", shared)
        S.set_key(folder, "identity", "IDENTITY_DOCKER_CONTEXT", shared)
        shim = S.DockerShim(where / "shim", [failure, _OK])
        monkeypatch.setenv("PATH", shim.path_value())
        verbs = FakeVerbs({"cmdb": {"get-host": cmdb_adapter.get_host},
                           "identity": {"health-check": identity_adapter.health_check}})
        run_dir, _, gather, run_state = _replay(where, root, verbs, [
            ("cmdb", "get-host", {"host": "web-1"}), ("identity", "health-check", {})],
            lead_system="cmdb")

        rows = {r["system"]: r for r in _own_rows(run_dir)}
        assert {"cmdb", "identity"} <= set(rows), f"{label}: precondition: both calls were made: {rows}"
        assert rows["identity"]["exit_code"] == 0, f"{label}: the sibling's call was affected: {rows['identity']}"
        assert rows["cmdb"]["exit_code"] == 2, f"{label}: cmdb's transient failure is infra: {rows['cmdb']}"
        systems = _breaker_doc(run_state).get("systems", {})
        assert systems.get("cmdb", {}).get("failures") == 1, \
            f"{label}: the failure must be charged to cmdb alone: {systems}"
        assert "identity" not in systems, f"{label}: the failure must be charged to cmdb alone: {systems}"
        calls = [(S.context_of(a), S.curl_url(a)) for a in _argvs(shim)]
        assert calls == [(shared, f"http://cmdb-{m}:8080/hosts/web-1"),
                         (shared, f"http://identity-{m}:8080/health")], \
            f"{label}: both systems must reach docker on their one shared context: {calls}"




def test_s7_mf8_config_fault_breaker_accounting_unchanged(tmp_path):
    """A ConfigFault counts toward the per-system and the run-wide breaker exactly as a
    TransportFault does (both exit 2): N distinct systems each down for config reach the
    run-wide failure limit at the same count as N connectivity faults (RUN_FAIL_KILL_LIMIT), as
    today. No config-fault exemption is added."""
    limit = circuit_breaker.RUN_FAIL_KILL_LIMIT
    systems = list(_STUB_ADAPTERS)[:limit]
    assert len(systems) == limit, f"precondition: {limit} distinct systems to fail: {systems}"

    # Down for config: each system's config.env removed before resolve.
    root_c, folder_c = _tenant(tmp_path, "mfc", name="config")
    for system in systems:
        S.config_path(folder_c, system).unlink()
    shim_c = S.DockerShim(tmp_path / "config" / "shim", [_OK])
    ctx_c = _ctx(S.resolve(root_c), tmp_path / "config", shim_c)
    config_faults = [_raised(_STUB_ADAPTERS[s].health_check, ctx_c) for s in systems]

    # Down for connectivity: configured, but docker answers G23's unknown-context rc=1.
    root_t, _ = _tenant(tmp_path, "mft", name="transport")
    shim_t = S.DockerShim(tmp_path / "transport" / "shim", [_OK])
    ctx_t = _ctx(S.resolve(root_t), tmp_path / "transport", shim_t)
    transport_faults = []
    for system in systems:
        shim_t.respond(S.context_not_found(S.context_name("mft", system)))  # G23
        transport_faults.append(_raised(_STUB_ADAPTERS[system].health_check, ctx_t))

    assert all(isinstance(f, ConfigFault) for f in config_faults), \
        f"precondition: every config-down system raised ConfigFault: {config_faults}"
    assert all(isinstance(f, TransportFault) for f in transport_faults), \
        f"precondition: every connectivity-down system raised TransportFault: {transport_faults}"
    runs = {}
    for label, faults, run_dir in (("config", config_faults, ctx_c.run_dir),
                                   ("transport", transport_faults, ctx_t.run_dir)):
        runs[label] = _breaker_run(run_dir, [(s, f.exit_code) for s, f in zip(systems, faults, strict=True)])
    for label, (totals, aborted) in runs.items():
        assert aborted is not None, f"{label}: {limit} distinct systems down must raise RunAborted at {limit}: {runs[label]}"
        assert aborted.total_failures == limit, f"{label}: {limit} distinct systems down must raise RunAborted at {limit}: {runs[label]}"
        assert totals == list(range(1, limit)), f"{label}: each fault counted once: {totals}"
    assert runs["config"][1].systems == runs["transport"][1].systems == sorted(systems), \
        f"both runs must abort over the same systems: {runs}"


# ---------------------------------------------------------------------------------------------
# The connect example, the ticket adapter's verbs, the two readers of elastic's file
# ---------------------------------------------------------------------------------------------

class _Recorder(http.server.BaseHTTPRequestHandler):
    """A local HTTP endpoint that records each path it is asked for and answers a JSON record."""

    def do_GET(self):  # noqa: N802 — the stdlib handler's name
        self.server.paths.append(self.path)
        body = json.dumps({"id": "r1"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def test_o8_example_reads_record(tmp_path, monkeypatch):
    """examples/example_adapter.py reads its system's settings from the record on its
    VerbContext. Driven with a record whose systems carry an example entry, and with no
    config.env on disk, it addresses that entry's URL."""
    for var in ("http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("no_proxy", "*")
    example = load_module(S.DEFENDER / "skills" / "connect" / "examples" / "example_adapter.py",
                          name="example_adapter_1107b", register=False)
    assert "get-record" in example.VERBS, "precondition: the example declares get-record"

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Recorder)
    server.paths = []
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        root, folder = _tenant(tmp_path, "oex")
        # The entry carries the example's own key spelling and its prefixed one, and no docker
        # access method: the example calls its system directly, so it must not need one.
        S.write_config(folder, "example", S.render_env({
            "URL_BASE": base, "TIMEOUT_SEC": "5", "EXAMPLE_URL_BASE": base,
            "EXAMPLE_TIMEOUT_SEC": "5"}))
        record = S.resolve(root)
        S.config_path(folder, "example").unlink()
        assert not S.config_path(folder, "example").exists(), "precondition: no config.env on disk"
        shim = S.DockerShim(tmp_path / "shim", [S.answer('{"id": "r1"}')])
        fault = _raised(example.get_record, _ctx(record, tmp_path, shim), id="r1")
        addressed = [base + p for p in server.paths] + [S.curl_url(a) for a in _argvs(shim)]
    finally:
        server.shutdown()
        server.server_close()
    assert fault is None, f"the example's get-record faulted with its entry in the record: {fault!r}"
    assert f"{base}/records/r1" in addressed, \
        f"the example must address its record entry's URL: {addressed}"












def test_s7_mf7c_the_adapter_judges_its_own_required_keys(tmp_path):
    """The read adapter keeps its own required-key check (no record view stands beside it since
    #1222 M1). With ELASTIC_KIBANA_CONTAINER absent the Elasticsearch verbs, whose own required
    keys are present, still answer; with KIBANA_URL absent the adapter faults naming it."""
    m = "mf7"
    root, folder = _tenant(tmp_path, m, name="kc")
    S.drop_key(folder, "elastic", "ELASTIC_KIBANA_CONTAINER")
    record = S.resolve(root)
    shim = S.DockerShim(tmp_path / "kc" / "shim", [_SEARCH])
    envelope = elastic_adapter.query(_ctx(record, tmp_path / "kc", shim), native_query="*")
    [argv] = _argvs(shim)
    assert envelope.get("index") == f"{m}-events-*", f"the ES verb must still answer: {envelope}"
    assert S.exec_target(argv) == S.es_container(m), f"the ES verb's child: {argv}"
    assert S.context_of(argv) == S.context_name(m, "elastic"), f"the ES verb's child: {argv}"

    # A key the adapter requires of every verb (KIBANA_URL).
    root2, folder2 = _tenant(tmp_path, "mf8", name="ku")
    S.drop_key(folder2, "elastic", "KIBANA_URL")
    record2 = S.resolve(root2)
    shim2 = S.DockerShim(tmp_path / "ku" / "shim", [_SEARCH])
    fault = _raised(elastic_adapter.query, _ctx(record2, tmp_path / "ku", shim2), native_query="*")
    assert isinstance(fault, ConfigFault), f"the adapter requires KIBANA_URL itself and must fault naming it: {fault!r}"
    assert "KIBANA_URL" in str(fault), f"the adapter requires KIBANA_URL itself and must fault naming it: {fault!r}"
    assert _argvs(shim2) == [], f"the faulted adapter spawned a child: {_argvs(shim2)}"


def test_o5_missing_system_config_run_completes(tmp_path, monkeypatch):
    """A tenant with cmdb's config.env removed resolves, and its run completes. A cmdb call
    raises ConfigFault (exit 2, counted toward the cmdb breaker), and the other systems still
    answer."""
    pytest.importorskip("pydantic_ai")
    from defender.tests.e2e._replay_harness import FakeVerbs

    m = "o5m"
    root, folder = _tenant(tmp_path, m, table=_REPLAY_TABLE)
    S.config_path(folder, "cmdb").unlink()
    S.resolve(root)  # resolves: a system with no config is down, not a refused run
    shim = S.DockerShim(tmp_path / "shim", [_OK])
    monkeypatch.setenv("PATH", shim.path_value())
    verbs = FakeVerbs({"cmdb": {"get-host": cmdb_adapter.get_host},
                       "threat-intel": {"health-check": threat_intel_adapter.health_check}})
    run_dir, main, gather, run_state = _replay(tmp_path, root, verbs, [
        ("cmdb", "get-host", {"host": "web-1"}), ("threat-intel", "health-check", {})],
        lead_system="cmdb")

    assert main.calls >= 2, f"the run must complete (main {main.calls} turns, gather {gather.calls})"
    assert gather.calls >= 3, f"the run must complete (main {main.calls} turns, gather {gather.calls})"
    rows = {r["system"]: r for r in _own_rows(run_dir)}
    assert {"cmdb", "threat-intel"} <= set(rows), f"precondition: both calls were made: {rows}"
    assert (rows["cmdb"]["exit_code"], rows["cmdb"]["error_class"]) == (2, "infra"), \
        f"cmdb with no config must be an infra fault (exit 2): {rows['cmdb']}"
    assert rows["threat-intel"]["exit_code"] == 0, f"threat-intel must still answer: {rows}"
    assert _breaker_doc(run_state).get("systems", {}).get("cmdb", {}).get("failures") == 1, \
        f"cmdb's fault must count toward its breaker: {_breaker_doc(run_state)}"
    calls = [S.context_of(a) for a in _argvs(shim)]
    assert calls == [S.context_name(m, "threat-intel")], \
        f"only threat-intel reaches docker, on its own context: {calls}"


def test_tenant_copied_from_the_template_keeps_its_placeholders(tmp_path):
    """A tenant copied from knowledge/tenant-template keeps its CHANGE-ME placeholders: the
    access-method keys and the non-pattern Elastic keys are present but name no real method or
    context, so each system is down at call time (its calls fault, TRANSPORT=CHANGE-ME as an
    unimplemented method) and the run goes on. Only CHANGE-ME index patterns are refused ahead
    of that, at branch launch (F23/G49)."""
    root = tmp_path / "tenants"
    # #1120: the copy is the tenant's knowledge folder under a data root — `agent/.tenant-id`
    # naming it, and its row beside it (written by hand, as `_tenants1106.place_tenant` does).
    folder = root / S.PLAYGROUND_ID / "knowledge"
    shutil.copytree(S.TEMPLATE_DIR, folder)
    (folder / "agent" / ".tenant-id").write_text(f"{S.PLAYGROUND_ID}\n", encoding="utf-8")
    (root / S.PLAYGROUND_ID / "tenant.json").write_text(json.dumps(
        {"tenant_id": S.PLAYGROUND_ID, "created_at": "2026-09-28T00:00:00+00:00"}) + "\n",
        encoding="utf-8")
    # The template grants nothing (the run would be refused for that, not for its placeholders).
    (S.settings_of(folder) / "verb-grants.yaml").write_text(T1106.TABLE_A, encoding="utf-8")
    configs = sorted((S.settings_of(folder) / "systems").glob("*/config.env"))
    assert len(configs) >= 7, f"precondition: the copied tenant carries its placeholders: {configs}"
    assert all("CHANGE-ME" in p.read_text(encoding="utf-8") for p in configs), f"precondition: the copied tenant carries its placeholders: {configs}"

    record = S.resolve(root)
    shim = S.DockerShim(tmp_path / "shim", [_OK])
    ctx = _ctx(record, tmp_path, shim)
    calls = [(s, a.health_check, {}) for s, a in _STUB_ADAPTERS.items()] + [
        ("host-state", host_state_adapter.health_check, {}),
        ("host-state", host_state_adapter.proc_tree, {"host": "web-1"}),
        ("elastic", elastic_adapter.query, {"native_query": "*"}),
        ("elastic", elastic_adapter.health_check, {}),
    ]
    for system, fn, kw in calls:
        fault = _raised(fn, ctx, **kw)
        assert isinstance(fault, ConfigFault), f"{system}.{fn.__name__} on a placeholder tenant must be the system down, got {fault!r}"
        assert fault.exit_code == 2, f"{system}.{fn.__name__} on a placeholder tenant must be the system down, got {fault!r}"
        if system in _STUB_ADAPTERS:
            assert "CHANGE-ME" in str(fault), \
                f"{system}: the fault must name the unimplemented method CHANGE-ME: {fault}"
    assert _argvs(shim) == [], f"a placeholder system reached docker: {_argvs(shim)}"
