"""#1347 r6.4.1 A3/A5/D15/O12: the real lab ops that start the frozen copy's side services, through a recorded `run=` seam.

Names bound by this contract (proposals the implementer may rename, with this file): the module
`playground-v2/scripts/lab_ops.py`, class `LabOps(run=subprocess.run, *, context="soc-playground",
tenant_hosts, frozen_endpoint, audit_path, live_audit_path)` with the methods the launcher's fake
`_lab_fakes.LabOps` models: `load_stubs(parts, as_of, mutations=None)`, `start_proxy() -> url`,
`restart_node(clock_offset)`. `run` is called like `subprocess.run` (argv list, keyword options) and
stands in for `docker --context <context> ...`: nothing here runs docker (a local fake docker would
execute the proxy program). Every value is looked for in what `run` was handed (argv, `input=`,
`env=`), so the test fixes the content sent, not the docker flag it rides on.

r6.4.2 (attack batch 1), also bound here: the real `LabOps` takes `es=` (the frozen cluster through the
chaos seam's `es_request(method, path, body=None)`) and answers `content_digest(patterns)` from the
documents it reads there for the freeze's patterns and from the stub stores it loaded;
`ensure_node()` starts the frozen node if it is stopped; `teardown()` leaves no container running
that the other operations started. `live_run_alerts()` and `ticketed_alerts()` read `V2_RUNS_DIR` and
`V2_FROZEN_PARTS_DIR` from the environment and raise when one is unset.

Deferred to the operator (needs the lab): that the shim really shifts Elasticsearch's wall clock, that
the stub containers honour `V2_STUB_AS_OF`, and that the frozen proxy reaches OpenBao and the frozen
engine's frontends.
"""
from __future__ import annotations

import importlib.util
import json
import re
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from _lab_fakes import (ALERTS, ALERTS_PATTERN, AUTH, CMDB_STALE, DATA_DROP, EVENTS, REPO, SCHEMA_DRIFT, SNAP, SYSLOG, T,
                        LabRig, instant)
from _periphery_fakes import FakeDocker

LAB_OPS = Path(__file__).resolve().parents[1] / "lab_ops.py"
HOSTS = ["elastic.lab.example", "kibana.lab.example"]
ENDPOINT = "10.99.0.1:19200"
AUDIT, LIVE_AUDIT = "/audit/frozen-proxy.jsonl", "/audit/proxy.jsonl"


class Recorder:
    def __init__(self):
        self.calls = []

    def __call__(self, argv, **kw):
        self.calls.append((list(argv), kw))
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    def blob(self):
        parts = []
        for argv, kw in self.calls:
            parts += [str(a) for a in argv]
            parts += [str(kw.get("input", "")), json.dumps(kw.get("env") or {}, default=str)]
        return "\n".join(parts)


def _ops(tmp_path, run=None, **extra):
    spec = importlib.util.spec_from_file_location("lab_ops_1347", LAB_OPS)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    rec = Recorder() if run is None else run
    ops = module.LabOps(run=rec, tenant_hosts=HOSTS, frozen_endpoint=ENDPOINT,
                        audit_path=AUDIT, live_audit_path=LIVE_AUDIT, **extra)
    return SimpleNamespace(ops=ops, rec=rec)


def _search_texts(rec):
    """Every argv token and `input=` text the recorder saw."""
    return [str(a) for argv, _ in rec.calls for a in argv] + [str(kw.get("input", "")) for _, kw in rec.calls]


def _stub_as_of_values(rec):
    """`V2_STUB_AS_OF=v` / `V2_STUB_AS_OF: v` in any command text or input, plus env values."""
    values = [m.group(1) for text in _search_texts(rec) + [rec.blob()]
              for m in re.finditer(r"V2_STUB_AS_OF[\"']?\s*[=:]\s*[\"']?([^;\"'\s,}\]]+)", text)]
    values += [str(kw["env"]["V2_STUB_AS_OF"]) for _, kw in rec.calls if "V2_STUB_AS_OF" in (kw.get("env") or {})]
    return values


def test_the_stub_containers_are_loaded_with_the_freeze_moment_and_the_resolved_mutations(tmp_path):
    """A3/A9: `V2_STUB_AS_OF` carries T and the case's resolved mutations reach the stub containers."""
    lab = _ops(tmp_path)
    parts = tmp_path / "parts"
    parts.mkdir()
    (parts / "stubs.tar").write_bytes(b"stub-dump-bytes")
    lab.ops.load_stubs(parts, T, [CMDB_STALE])

    assert lab.rec.calls, "no command was sent"
    values = _stub_as_of_values(lab.rec)
    assert values and all(instant(v) == instant(T) for v in values), values
    for needle in (CMDB_STALE["kind"], CMDB_STALE["host"], CMDB_STALE["new_value"]):
        assert needle in lab.rec.blob(), needle


def test_stubs_loaded_without_mutations_still_carry_the_freeze_moment(tmp_path):
    """A3 control: no overlay, the stubs are still pinned at T and no mutation text is sent."""
    lab = _ops(tmp_path)
    parts = tmp_path / "parts"
    parts.mkdir()
    (parts / "stubs.tar").write_bytes(b"stub-dump-bytes")
    lab.ops.load_stubs(parts, T, None)

    assert "V2_STUB_AS_OF=" in lab.rec.blob() and CMDB_STALE["kind"] not in lab.rec.blob()


def test_the_frozen_proxy_runs_the_products_proxy_program_unmodified_with_its_own_audit_file(tmp_path):
    """O12/A5: `python -m defender.credential_proxy`, an audit path that is not the live proxy's, and
    the url it answers is the frozen proxy's, not the live one."""
    lab = _ops(tmp_path)
    url = lab.ops.start_proxy()
    blob = lab.rec.blob()

    assert url and url != "http://credential-proxy:8443"
    assert "defender.credential_proxy" in blob and "-m" in blob
    assert AUDIT in blob and LIVE_AUDIT not in blob.replace(AUDIT, "")
    assert not any(a.endswith(".py") and "credential_proxy" in a for argv, _ in lab.rec.calls for a in argv), \
        "the proxy program must be started as the product's module, not a lab copy of it"


def test_the_frozen_proxy_resolves_every_declared_host_name_to_the_frozen_endpoint(tmp_path):
    """O12: each of the tenant's declared host names maps to the ssh-forwarded frozen endpoint."""
    lab = _ops(tmp_path)
    lab.ops.start_proxy()
    blob = lab.rec.blob()

    ip = ENDPOINT.split(":")[0]
    for h in HOSTS:
        assert _mapped_ips(lab.rec, h) == {ip}, (h, blob)


def _mapped_ips(rec, host):
    """The IPs written on `host`'s own mapping entry (same argv token or same line), `host:ip` or `ip host`."""
    found = set()
    texts = _search_texts(rec) + [str(v) for _, kw in rec.calls for v in (kw.get("env") or {}).values()]
    q, ip, h = "[\"']?", r"(\d+\.\d+\.\d+\.\d+)", re.escape(host)
    for text in texts:
        for ln in text.splitlines():
            for m in re.finditer(rf"(?<![\w.-]){q}{h}{q}\s*[:=\s]\s*{q}{ip}|{q}{ip}{q}[ \t]+(?:(?!\d+(?:\.\d+){{3}}(?![\w.-]))[\w.-]+[ \t]+)*{q}{h}(?![\w.-])", ln):
                found.add(m.group(1) or m.group(2))
    return found


def test_a_host_mapped_to_another_ip_is_not_read_as_the_frozen_endpoint():
    """O12 control: the shape read above tells the live IP apart from the frozen one."""
    rec = Recorder()
    rec(["docker", "run", "--add-host", f"{HOSTS[0]}:10.0.0.9", "--add-host", f"{HOSTS[1]}:10.99.0.1"])
    assert _mapped_ips(rec, HOSTS[0]) == {"10.0.0.9"} and _mapped_ips(rec, HOSTS[1]) == {"10.99.0.1"}


def test_the_node_restart_hands_the_clock_offset_to_the_frozen_elasticsearch_through_the_preload_shim(tmp_path):
    """D15/O5: the offset reaches the frozen Elasticsearch's environment with `LD_PRELOAD`."""
    lab = _ops(tmp_path)
    lab.ops.restart_node(-1_234_567)
    blob = lab.rec.blob()

    env = [kw.get("env") or {} for _, kw in lab.rec.calls]
    assert "LD_PRELOAD" in blob, blob
    stop = r"[;\"'\s,}\]]"
    assert any(v == "-1234567" for e in env for v in map(str, e.values())) or any(
        re.search(rf"[=:]\s*[\"']?-1234567(?={stop}|$)", t) for t in _search_texts(lab.rec)), blob
    assert any("restart" in a or "elasticsearch" in a for argv, _ in lab.rec.calls for a in argv)


# =====================================================================================================
# r6.4.2 repairs (attack batch 1)
# =====================================================================================================


def _stub_parts(tmp_path, body=b"stub-dump-bytes"):
    parts = tmp_path / "stub-parts"
    parts.mkdir(exist_ok=True)
    (parts / "stubs.tar").write_bytes(body)
    return parts


def test_teardown_leaves_no_container_running_that_the_operations_started(tmp_path):
    """C8/A1: after start_proxy, load_stubs and the node restart, alone and in combination, no container
    they brought up (the proxy, the frontends, the stubs, the node) is still running. What each operation
    starts, if anything, is its own business; across them something must have been started."""
    sets = [("start_proxy",), ("load_stubs",), ("restart_node",), ("load_stubs", "restart_node", "start_proxy")]
    started_any = False
    for n, started in enumerate(sets):
        docker = FakeDocker()
        case = tmp_path / f"case{n}"
        case.mkdir()
        lab = _ops(case, run=docker)
        parts = _stub_parts(case)
        do = {"start_proxy": lab.ops.start_proxy, "load_stubs": lambda: lab.ops.load_stubs(parts, T, [CMDB_STALE]),
              "restart_node": lambda: lab.ops.restart_node(-1_234_567)}
        for name in started:
            do[name]()
        assert not docker.unmodelled, f"the fake docker does not model: {docker.unmodelled}"
        started_any = started_any or bool(docker.started)

        lab.ops.teardown()

        assert not docker.started & docker.running(), (started, sorted(docker.started & docker.running()))
    assert started_any, "no operation started a container: the claim was never exercised"


TOUCHED = [DATA_DROP, SCHEMA_DRIFT]      # the overlays whose indices the digest covers: syslog events, auth events, their alerts


def _digest_lab(tmp_path, *, body=b"stub-dump-bytes", mutations=None):
    """A real LabOps over a restored copy of the world, its stubs loaded with the overlays' resolved
    mutations (`TOUCHED` unless given); returns (lab, rig)."""
    rig = LabRig(tmp_path)
    rig.cluster.es_request("PUT", f"/_snapshot/{REPO}", {"type": "fs", "settings": {"readonly": True}})
    rig.cluster.es_request("POST", f"/_snapshot/{REPO}/{SNAP}/_restore", {})
    lab = _ops(tmp_path, run=FakeDocker(), es=rig.cluster)
    lab.ops.load_stubs(_stub_parts(tmp_path, body), T, TOUCHED if mutations is None else mutations)
    return lab, rig


def test_the_content_digest_follows_every_document_of_a_touched_index_and_every_stub_byte(tmp_path):
    """C8/A1 (design: "a content digest covers the touched indices and every stub store"): the same copy
    and stubs give the same digest; one document of a touched index (a syslog or auth event, an alert)
    altered, added, removed or re-versioned, one stub byte, or the stub mutations, give another. What an
    untouched index (nginx) holds is not pinned either way."""
    patterns = [EVENTS, ALERTS_PATTERN]
    lab, rig = _digest_lab(tmp_path / "base")
    digest = lab.ops.content_digest(patterns)
    assert isinstance(digest, str) and digest
    assert lab.ops.content_digest(patterns) == digest
    assert _digest_lab(tmp_path / "again")[0].ops.content_digest(patterns) == digest

    def edits(r):
        docs = r.cluster.indices
        return {
            "syslog altered": lambda: docs[SYSLOG]["docs"]["syslog-20"]["_source"].__setitem__("message", "changed"),
            "syslog re-versioned": lambda: docs[SYSLOG]["docs"]["syslog-20"].__setitem__("_version", 2),
            "syslog removed": lambda: docs[SYSLOG]["docs"].pop("syslog-20"),
            "syslog added": lambda: r.cluster.put(SYSLOG, "syslog-99", {"@timestamp": "2026-10-20T05:00:00Z", "message": "new"}),
            "auth altered": lambda: docs[AUTH]["docs"]["auth-25"]["_source"].__setitem__("source.port", 1),
            "auth re-versioned": lambda: docs[AUTH]["docs"]["auth-25"].__setitem__("_version", 7),
            "auth removed": lambda: docs[AUTH]["docs"].pop("auth-25"),
            "alert altered": lambda: docs[ALERTS]["docs"]["id-young"]["_source"].__setitem__("host.name", "web-2"),
            "alert re-versioned": lambda: docs[ALERTS]["docs"]["id-young"].__setitem__("_version", 9),
        }

    for name in edits(rig):
        lab2, rig2 = _digest_lab(tmp_path / name.replace(" ", "-"))
        edits(rig2)[name]()
        assert lab2.ops.content_digest(patterns) != digest, name

    assert _digest_lab(tmp_path / "byte", body=b"stub-dump-bytez")[0].ops.content_digest(patterns) != digest
    assert _digest_lab(tmp_path / "flip", mutations=[*TOUCHED, CMDB_STALE])[0].ops.content_digest(patterns) != digest


# -- B2: an exclusion source that is not configured refuses, it never reads as "none excluded" ------------


def test_a_live_run_or_ticket_source_that_is_not_configured_refuses_instead_of_excluding_nothing(tmp_path, monkeypatch):
    """B2/O13: with V2_RUNS_DIR and V2_FROZEN_PARTS_DIR unset the two lookups raise, not return an empty
    set; with both set to existing (empty) directories they return empty sets."""
    lab = _ops(tmp_path, run=FakeDocker())
    runs, parts = tmp_path / "runs", tmp_path / "frozen-parts"
    runs.mkdir()
    parts.mkdir()
    monkeypatch.setenv("V2_RUNS_DIR", str(runs))
    monkeypatch.setenv("V2_FROZEN_PARTS_DIR", str(parts))
    assert lab.ops.live_run_alerts() == set() and lab.ops.ticketed_alerts() == set()

    monkeypatch.delenv("V2_RUNS_DIR")
    monkeypatch.delenv("V2_FROZEN_PARTS_DIR")
    for lookup in (lab.ops.live_run_alerts, lab.ops.ticketed_alerts):
        with pytest.raises(Exception) as caught:
            lookup()
        assert not isinstance(caught.value, (AttributeError, TypeError, NameError)), repr(caught.value)
