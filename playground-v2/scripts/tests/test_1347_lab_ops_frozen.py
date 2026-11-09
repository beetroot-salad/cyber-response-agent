"""#1347 r6.4.1 A3/A5/D15/O12: the real lab ops that start the frozen copy's side services, through a recorded `run=` seam.

Names bound by this contract (proposals the implementer may rename, with this file): the module
`playground-v2/scripts/lab_ops.py`, class `LabOps(run=subprocess.run, *, context="soc-playground",
tenant_hosts, frozen_endpoint, audit_path, live_audit_path)` with the methods the launcher's fake
`_lab_fakes.LabOps` models: `load_stubs(parts, as_of, mutations=None)`, `start_proxy() -> url`,
`restart_node(clock_offset)`. `run` is called like `subprocess.run` (argv list, keyword options) and
stands in for `docker --context <context> ...`: nothing here runs docker (a local fake docker would
execute the proxy program). Every value is looked for in what `run` was handed (argv, `input=`,
`env=`), so the test fixes the content sent, not the docker flag it rides on.

Deferred to the operator (needs the lab): that the shim really shifts Elasticsearch's wall clock, that
the stub containers honour `V2_STUB_AS_OF`, and that the frozen proxy reaches OpenBao and the frozen
engine's frontends.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from _lab_fakes import CMDB_STALE, FROZEN_PROXY_URL, T, instant

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


def _ops(tmp_path):
    spec = importlib.util.spec_from_file_location("lab_ops_1347", LAB_OPS)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    rec = Recorder()
    ops = module.LabOps(run=rec, tenant_hosts=HOSTS, frozen_endpoint=ENDPOINT,
                        audit_path=AUDIT, live_audit_path=LIVE_AUDIT)
    return SimpleNamespace(ops=ops, rec=rec)


def test_the_stub_containers_are_loaded_with_the_freeze_moment_and_the_resolved_mutations(tmp_path):
    """A3/A9: `V2_STUB_AS_OF` carries T and the case's resolved mutations reach the stub containers."""
    lab = _ops(tmp_path)
    parts = tmp_path / "parts"
    parts.mkdir()
    (parts / "stubs.tar").write_bytes(b"stub-dump-bytes")
    lab.ops.load_stubs(parts, T, [CMDB_STALE])

    assert lab.rec.calls, "no command was sent"
    values = [a.split("=", 1)[1] for argv, kw in lab.rec.calls for a in [*argv, *(f"{k}={v}" for k, v in (kw.get("env") or {}).items())]
              if a.startswith("V2_STUB_AS_OF=")]
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
    assert all(h in blob for h in HOSTS) and ip in blob, blob
    for h in HOSTS:
        line = next((ln for ln in blob.splitlines() if h in ln), "")
        assert ip in line or ENDPOINT in blob, (h, line)


def test_the_node_restart_hands_the_clock_offset_to_the_frozen_elasticsearch_through_the_preload_shim(tmp_path):
    """D15/O5: the offset reaches the frozen Elasticsearch's environment with `LD_PRELOAD`."""
    lab = _ops(tmp_path)
    lab.ops.restart_node(-1_234_567)
    blob = lab.rec.blob()

    assert "LD_PRELOAD" in blob and "1234567" in blob, blob
    assert any("restart" in a or "elasticsearch" in a for argv, _ in lab.rec.calls for a in argv)
