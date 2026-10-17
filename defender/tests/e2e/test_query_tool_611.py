"""#611 slice 1 — the executable spec for the `query` tool, the VERBS registry, and
capture-as-a-capability."""
from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import fields
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.exceptions import (  # noqa: E402
    ApprovalRequired,
    CallDeferred,
    ModelRetry,
    SkipToolExecution,
    ToolRetryError,
)

from defender._io import read_jsonl_rows  # noqa: E402
from defender.tests import _system_index_1256 as SI  # noqa: E402
from defender.learning import lead_repository  # noqa: E402
from defender.runtime import permission, tools as runtime_tools  # noqa: E402
from defender.runtime.agent_definition import bind, compile_policy_for  # noqa: E402
from defender.runtime.circuit_breaker import RunAborted, error_class_for_exit  # noqa: E402
from defender.runtime.driver import MAIN_DEF  # noqa: E402
from defender.runtime.permission.grant import Route  # noqa: E402
from defender.tests import _tenants1106  # noqa: E402
from defender.tests.tenant_1107_settings import _spec1107 as S1107  # noqa: E402
from defender.tests.e2e._replay_harness import (  # noqa: E402
    DEFENDER,
    GOLDEN_AB3,
    FakeVerbs,
    ReplayFn,
    Turn,
    VerbRecorder,
    drive,
    materialize,
)

from defender.runtime import query_tool  # noqa: E402
from defender.runtime.verb_grant import DENY_ALL, VerbGrant  # noqa: E402
from defender.runtime.verbs import (  # noqa: E402
    ModuleVerbRegistry,
    VerbContext,
)
from defender.scripts.adapters import _stub_transport  # noqa: E402
from defender.scripts.adapters.faults import (  # noqa: E402
    ConfigFault,
    TransportFault,
    UpstreamFault,
)
from defender.runtime.verbs import read_roster  # noqa: E402

pytestmark = pytest.mark.e2e

SALT = "aabbccddeeff0011"
LEAD = "l-001"
ADAPTERS_DIR = DEFENDER / "scripts" / "adapters"


def _sql_shim_aggregates() -> bool:
    """Can the `defender-sql` shim OF THE TREE UNDER TEST actually aggregate a payload?"""
    try:
        probe = subprocess.run(
            [str(DEFENDER / "bin" / "defender-sql"), "SELECT 1"],
            input=b"[]", capture_output=True, timeout=30,
            env={**os.environ, "DEFENDER_DIR": str(DEFENDER)},
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return probe.returncode == 0

PAYLOAD = [
    {"@timestamp": "2026-01-01T00:00:00Z", "user.name": "dev.dana", "event.action": "ssh_login"},
    {"@timestamp": "2026-01-01T00:05:00Z", "user.name": "dev.dana", "event.action": "sudo"},
]


class _Run:
    """One driven replay: the run dir plus the two replay models and the tables on disk."""

    def __init__(self, run_dir: Path, main: ReplayFn, gather: ReplayFn,
                 summary: dict | None = None):
        self.run_dir, self.main, self.gather = run_dir, main, gather
        self.summary = summary if summary is not None else {}

    @property
    def rows(self) -> list[dict]:
        return read_jsonl_rows(self.run_dir / "executed_queries.jsonl")

    @property
    def own_rows(self) -> list[dict]:
        """`.rows` filtered to exclude #808's harness-authored leads (`l-000`/`l-00c`) —
        the rows produced by THIS test's own dispatched lead, not lead-0's unconditional
        pre-ORIENT resolution against `GOLDEN_AB3`'s alert."""
        from defender.runtime.lead_zero import RESERVED_LEAD_IDS
        return [r for r in self.rows if r.get("lead_id") not in RESERVED_LEAD_IDS]

    def row(self) -> dict:
        rows = self.own_rows
        assert len(rows) == 1, f"expected exactly one queries row, got {rows}"
        return rows[0]

    @property
    def gather_saw(self) -> str:
        """The gather model's last message history — where a tool RESULT (the query return,
        a deny reason bounced back as ModelRetry feedback) shows up."""
        return self.gather.seen[-1]

    def payload(self, seq: int = 0) -> str:
        return (self.run_dir / "gather_raw" / LEAD / f"{seq}.json").read_text(encoding="utf-8")

    @property
    def state(self):
        """The run's one `RunState` (#1235 round 2), as the driver's summary hands it back."""
        return self.summary["run_state"]

    @property
    def breaker(self) -> dict:
        """The run's breaker state, off the run's `RunState` (#1235), read post-run;
        blank (`{"systems": {}, "total_failures": 0}`) when nothing was charged."""
        return self.state.breaker_snapshot()


def run_gather(
    tmp_path: Path, *, verbs, turns: list[Turn], system: str = "elastic", run_id: str = "q611",
) -> _Run:
    """Drive a REAL run: main dispatches one gather lead, the nested gather agent replays
    `turns` (the query calls under test) against the INJECTED verb registry. Everything
    between the two fakes — dispatch, the query tool, its validator, the capture capability."""
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id=run_id)
    main = ReplayFn([
        Turn(tool_calls=[("gather", {
            "lead_id": LEAD, "system": system, "goal": "measure this lead",
            "what_to_summarize": ["auth events"],
        })]),
        Turn(text="Investigation complete."),
    ])
    gather = ReplayFn(turns)
    summary = drive(run_dir, run_id=run_id, main=main, gather=gather, verbs=verbs)
    return _Run(run_dir, main, gather, summary)


def q(system: str, verb: str, params: dict, query_id: str | None = None) -> Turn:
    """One scripted `query` tool call — the model-facing shape of the new tool."""
    args: dict = {"system": system, "verb": verb, "params": params}
    if query_id is not None:
        args["query_id"] = query_id
    return Turn(tool_calls=[("query", args)])


DONE = Turn(text="Summary: measured the lead.")


def elastic_ok(rec: VerbRecorder) -> FakeVerbs:
    """The happy-path registry: one system, one verb, two declared params (`native_query`
    REQUIRED, `limit` optional). The signature IS the param contract the tool validates."""

    def query(ctx: VerbContext, *, native_query: str, limit: int = 10) -> list[dict]:
        rec.record("query", ctx, {"native_query": native_query, "limit": limit})
        return PAYLOAD

    return FakeVerbs({"elastic": {"query": query}})


def raising(rec: VerbRecorder, exc: BaseException, systems: tuple[str, ...] = ("elastic",)) -> FakeVerbs:
    """A registry whose verb RAISES `exc` — a fault injector, nothing more. It does not map
    the fault to an exit code, does not touch the breaker, and does not write a row: every
    one of those is the capture capability's job, and every assertion about them is therefore"""

    def probe(ctx: VerbContext, *, native_query: str = "FROM logs") -> list[dict]:
        rec.record("probe", ctx, {"native_query": native_query})
        raise exc

    return FakeVerbs({s: {"probe": probe} for s in systems})


def test_query_returns_wrapped_truncated_view_and_payload_note(tmp_path):
    """query_returns_wrapped_truncated_view_and_payload_note — the tool returns an exit-code
    line, the SALT-WRAPPED truncated view, and the ABSOLUTE `[record_query] raw payload:`
    note. Not a bare payload_ref."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=elastic_ok(rec), turns=[
        q("elastic", "query", {"native_query": "FROM logs | LIMIT 2"}), DONE,
    ])
    seen = r.gather_saw
    payload_abs = str(r.run_dir / "gather_raw" / LEAD / "0.json")

    assert rec.only().params == {"native_query": "FROM logs | LIMIT 2", "limit": 10}

    assert "exit=0" in seen
    assert re.search(r"<run-[0-9a-f]+-untrusted>", seen), "the return was not framed"
    assert re.search(r"</run-[0-9a-f]+-untrusted>", seen), "the frame never closed"
    assert f"[record_query] raw payload: {payload_abs}" in seen
    assert "dev.dana" in seen, "the truncated view of the payload must reach the model"


def test_query_return_wrap_mints_its_own_salt(tmp_path):
    """query_return_wrap_mints_its_own_salt — the wrap mints a FRESH token per return, never a
    per-run one shared with the party being framed."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=elastic_ok(rec), turns=[
        q("elastic", "query", {"native_query": "FROM logs"}), DONE,
    ])
    tags = re.findall(r"<run-([0-9a-zA-Z]+)-untrusted>", r.gather_saw)
    assert tags, "the query return carried no untrusted wrap at all"
    for tag in set(tags):
        body = r.gather_saw.split(f"<run-{tag}-untrusted>", 1)[1].split(
            f"</run-{tag}-untrusted>", 1)[0]
        assert tag not in body, \
            f"the frame salt {tag!r} occurs inside its own body — gather can close its frame"


def test_query_payload_is_not_double_wrapped_on_read_back(tmp_path):
    """query_payload_is_not_double_wrapped_on_read_back — reading the persisted payload back
    with the REAL read tool (which salt-wraps gather_raw/ via is_untrusted_read) yields exactly
    ONE wrap, not a wrap nested inside the one the query tool already applied."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=elastic_ok(rec), turns=[
        q("elastic", "query", {"native_query": "FROM logs"}), DONE,
    ])
    payload_abs = r.run_dir / "gather_raw" / LEAD / "0.json"

    gdeps = bind(_tenants1106.fixture_gather_def(), r.run_dir, defender_dir=DEFENDER)
    out = runtime_tools._tool_read_file(gdeps, str(payload_abs))

    assert len(re.findall(r"<run-[0-9a-f]+-untrusted>", out)) == 1
    assert len(re.findall(r"</run-[0-9a-f]+-untrusted>", out)) == 1
    assert "dev.dana" in out


@pytest.mark.parametrize(("label", "args"), [
    ("unknown-system", {"system": "nosuch", "verb": "query", "params": {"native_query": "x"}}),
    ("unknown-verb", {"system": "elastic", "verb": "nosuch", "params": {"native_query": "x"}}),
    ("unknown-param", {"system": "elastic", "verb": "query",
                       "params": {"native_query": "x", "nosuch": 1}}),
    ("missing-required", {"system": "elastic", "verb": "query", "params": {"limit": 5}}),
])
def test_unknown_system_verb_param_rejected(tmp_path, label, args):
    """unknown_system_verb_param_rejected — an unknown system / unknown verb / unknown param
    key / missing required param is rejected at the boundary and NEVER reaches a transport."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=elastic_ok(rec), turns=[
        Turn(tool_calls=[("query", args)]), DONE,
    ], run_id=f"q611-{label}")

    assert rec.calls == [], f"{label} reached the verb — validation is not at the boundary"
    assert r.gather.calls >= 2, "the rejection did not bounce the gather agent back into its loop"


def test_registry_validation_failure_writes_its_row_before_raising(tmp_path):
    """registry_validation_failure_writes_its_row_before_raising — a registry validation
    failure writes its queries row (64 / agent-fixable / error) BEFORE raising ModelRetry:
    ModelRetry bypasses on_tool_execute_error AND after_tool_execute, so a write that follows"""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=elastic_ok(rec), turns=[
        q("elastic", "nosuch-verb", {"native_query": "x"}), DONE,
    ])
    row = r.row()
    assert row["exit_code"] == 64
    assert row["error_class"] == "agent-fixable"
    assert row["payload_status"] == "error"
    assert row["system"] == "elastic"
    assert row["verb"] == "nosuch-verb"
    assert rec.calls == []
    assert r.breaker.get("total_failures", 0) == 0


def test_arg_shape_validation_error_still_writes_a_64_row(tmp_path):
    """arg_shape_validation_error_still_writes_a_64_row — a malformed tool CALL (verb as an
    int) fails in pydantic-ai's VALIDATE hook family, which runs BEFORE the EXECUTE family, so
    capture must also install wrap_tool_validate or the row is silently lost."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=elastic_ok(rec), turns=[
        Turn(tool_calls=[("query", {"system": "elastic", "verb": {"not": "a string"},
                                    "params": {"native_query": "x"}})]),
        DONE,
    ])
    assert rec.calls == []
    rows = r.own_rows
    assert len(rows) == 1, "an arg-shape failure wrote no row — half the exit-64 class is gone"
    assert rows[0]["exit_code"] == 64
    assert rows[0]["error_class"] == "agent-fixable"
    assert rows[0]["payload_status"] == "error"


def test_a_recursive_args_body_does_not_take_the_rejection_row_with_it():
    """a_recursive_args_body_does_not_take_the_rejection_row_with_it — `_raw_args` absorbs the
    `RecursionError` a deeply nested arguments body raises, because its one production caller
    is `wrap_tool_validate`'s rejection handler and that frame has no `try` of its own."""
    body = '{"system": "elastic", "verb": "probe", "params": ' + "[" * 2000 + "]" * 2000 + "}"
    with pytest.raises(RecursionError):
        json.loads(body)
    assert query_tool._raw_args(body) == {}, \
        "a recursive arguments body no longer coarsens to `{}` — if it raises here instead, " \
        "the rejection handler writes no row and the companion guard stops counting"


def test_empty_verbs_declaration_fails_closed_at_the_tool(tmp_path):
    """empty_verbs_declaration_fails_closed_at_the_tool — a system whose module declares NO
    verbs is unreachable through query(): an empty declaration must not read as 'no filter'."""
    rec = VerbRecorder()
    verbs = FakeVerbs({"ghost": {}})
    r = run_gather(tmp_path, verbs=verbs, system="ghost", turns=[
        q("ghost", "anything", {"native_query": "x"}), DONE,
    ])
    assert rec.calls == []
    assert r.gather.calls >= 2, "the empty-VERBS system was not rejected back to the model"
    assert all(row["exit_code"] != 0 for row in r.rows), \
        "a system with an empty VERBS declaration answered a query"


_ADAPTER_NO_VERBS = "VERBS = {}\n"

_ADAPTER_WITH_VERBS = (
    "def look(ctx, *, name: str) -> dict:\n"
    '    return {"name": name}\n'
    "\n"
    'VERBS = {"look": look}\n'
)

_TREE_PROBE = (
    "from pathlib import Path\n"
    "\n"
    "TREE = Path(__file__).resolve().parents[2]\n"
    "\n"
    "def whoami(ctx, *, unused: str = '') -> dict:\n"
    '    return {"tree": str(TREE)}\n'
    "\n"
    'VERBS = {"whoami": whoami}\n'
)


def _make_tree(root: Path, adapters: dict[str, str], described: tuple[str, ...] = ()) -> Path:
    """A minimal defender tree: `scripts/adapters/{system}_adapter.py` + a described SKILL.md per
    system, so descriptor_catalog has a roster to glob AND a description to read."""
    (root / "scripts" / "adapters").mkdir(parents=True)
    for system, src in adapters.items():
        (root / "scripts" / "adapters" / f"{system}_adapter.py").write_text(src, encoding="utf-8")
    for system in described:
        d = root / "skills" / system
        d.mkdir(parents=True)
        (d / "SKILL.md").write_text(
            f"---\nname: {system}\ndescription: the {system} system of record\n---\n\nbody\n",
            encoding="utf-8",
        )
    return root


def test_descriptor_catalog_advertises_only_declared_systems(tmp_path):
    """descriptor_catalog_advertises_only_declared_systems — fail-closed holds at the PROMPT as
    well as at the tool: a `*_adapter.py` on disk that declares NO verbs is ABSENT from the injected
    catalog (which today derives its roster by globbing filenames and never imports the module)."""
    tree = _make_tree(
        tmp_path / "tree",
        {"hollow": _ADAPTER_NO_VERBS, "solid": _ADAPTER_WITH_VERBS},
        described=("hollow", "solid"),
    )
    grant = VerbGrant(role="gather", entries=(("solid", "look", "r"),))
    catalog = SI.index_text(SI.index_module(), tree / "skills",
                            read_roster(tree / "scripts" / "adapters"), grant)
    assert SI.listing(catalog)
    assert "`solid`" in catalog
    assert "hollow" not in catalog, "a system with no declared verbs was advertised to gather"


def test_descriptor_catalog_does_not_freeze_the_tree(tmp_path):
    """descriptor_catalog_does_not_freeze_the_tree — two catalogs built for two trees in ONE
    process (the learning loop's worktree-drain shape) each resolve their OWN tree: building
    the catalog for tree A must not make a later verb call under tree B run A's module."""
    a = _make_tree(tmp_path / "a", {"probe": _TREE_PROBE}, described=("probe",))
    b = _make_tree(tmp_path / "b", {"probe": _TREE_PROBE}, described=("probe",))

    grant = VerbGrant(role="gather", entries=(("probe", "whoami", "r"),))
    module = SI.index_module()
    assert SI.listing(SI.index_text(module, a / "skills", read_roster(a / "scripts" / "adapters"),
                                    grant))
    assert SI.listing(SI.index_text(module, b / "skills", read_roster(b / "scripts" / "adapters"),
                                    grant))

    ctx_a = _tenants1106.verb_context(a, tmp_path / "run", {})
    ctx_b = _tenants1106.verb_context(b, tmp_path / "run", {})
    fn_a = ModuleVerbRegistry(read_roster(a / "scripts" / "adapters"), DENY_ALL).verbs("probe")["whoami"]
    fn_b = ModuleVerbRegistry(read_roster(b / "scripts" / "adapters"), DENY_ALL).verbs("probe")["whoami"]

    assert fn_a(ctx_a) == {"tree": str(a)}
    assert fn_b(ctx_b) == {"tree": str(b)}, \
        "tree B's verb ran tree A's module — the roster/registry froze the first tree it saw"


_PROGRAM_ISH = {"program", "command", "cmd", "argv", "exec", "shell", "script", "binary", "path"}
_PATH_EXCEPTION = ("host-state", "fim-checksum", "path")


def test_query_id_fallback_chain(tmp_path):
    """query_id_fallback_chain — model-supplied → {system}.{verb} → {system}.ad-hoc, and
    deps.query_id (never assigned anywhere) is DELETED, not preserved."""
    rec = VerbRecorder()

    r1 = run_gather(tmp_path / "a", verbs=elastic_ok(rec), turns=[
        q("elastic", "query", {"native_query": "x"}, query_id="elastic.sshd-auth-history"), DONE,
    ], run_id="qid-model")
    assert r1.row()["query_id"] == "elastic.sshd-auth-history"

    r2 = run_gather(tmp_path / "b", verbs=elastic_ok(rec), turns=[
        q("elastic", "query", {"native_query": "x"}), DONE,
    ], run_id="qid-derived")
    assert r2.row()["query_id"] == "elastic.query"

    assert query_tool.resolve_query_id("elastic", "", None) == "elastic.ad-hoc"

    assert "query_id" not in {f.name for f in fields(runtime_tools.GatherDeps)}


@pytest.mark.parametrize("bad_qid", [
    "elastic.../../../../tmp/PWNED",
    "elastic.sub/dir",
    "elastic.up..down",
    "elastic.bad\\seg",
    "elastic.nul\x00byte",
])
def test_query_id_traversal_guard_survives(tmp_path, bad_qid):
    """query_id_traversal_guard_survives — a query_id carrying '/', '\\', '..' or NUL is
    rejected: it becomes a {system}/_draft/{verb}.md path segment in the offline lead-author,
    and it is now model-authored input arriving at a NEW boundary."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=elastic_ok(rec), turns=[
        q("elastic", "query", {"native_query": "x"}, query_id=bad_qid), DONE,
    ], run_id="qid-traversal")

    assert rec.calls == [], "a traversal query_id reached the transport"
    assert all(row.get("query_id") != bad_qid for row in r.rows), \
        "a traversal query_id was recorded into the queries table"
    assert r.gather.calls >= 2, "the traversal rejection did not bounce back to the model"


def test_failing_verb_still_writes_its_row(tmp_path):
    """failing_verb_still_writes_its_row — a verb that RAISES still writes its queries row
    (error status, the mapped exit code + error class) and still records the breaker outcome."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=raising(rec, TransportFault("connection refused")), turns=[
        q("elastic", "probe", {}), DONE,
    ])
    row = r.row()
    assert len(rec.calls) == 1, "the verb never ran"
    assert row["exit_code"] == 2
    assert row["error_class"] == "infra"
    assert row["payload_status"] == "error"
    assert "connection refused" in row["payload_digest"]
    assert r.breaker["systems"]["elastic"]["failures"] == 1


def test_unmapped_fault_still_writes_a_row(tmp_path):
    """unmapped_fault_still_writes_a_row — a fault with NO mapping (a bare RuntimeError) still
    writes a row under a default exit code: the catch-all is what stops an unmapped fault from
    DELETING the record the taxonomy exists for."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=raising(rec, RuntimeError("kaboom in the adapter")), turns=[
        q("elastic", "probe", {}), DONE,
    ])
    row = r.row()
    assert row["exit_code"] != 0, "an unmapped fault was recorded as a SUCCESS"
    assert row["payload_status"] == "error"
    assert row["error_class"] == error_class_for_exit(row["exit_code"])
    assert "kaboom in the adapter" in row["payload_digest"]


def test_systemexit_does_not_unwind_the_run(tmp_path):
    """systemexit_does_not_unwind_the_run — SystemExit is a BaseException, so pydantic-ai's
    `except Exception` does not catch it and asyncio.to_thread re-raises it to the awaiter. The
    capture seam catches it, writes a row, and the run CONTINUES."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=raising(rec, SystemExit(2)), turns=[
        q("elastic", "probe", {}), DONE,
    ])
    assert r.gather.calls == 2
    assert r.main.calls == 2
    row = r.row()
    assert row["exit_code"] != 0
    assert row["payload_status"] == "error"


def test_capture_catch_all_re_raises_the_control_flow_exceptions(tmp_path):
    """capture_catch_all_re_raises_the_control_flow_exceptions — the catch-all must NOT swallow
    RunAborted (the run-wide kill switch), ModelRetry, or pydantic-ai's control-flow exceptions.
    Every one of them is a plain Exception subclass, so a broad `except Exception` silently"""
    declared = set(query_tool.CONTROL_FLOW_EXCEPTIONS)
    for exc in (RunAborted, ModelRetry, SkipToolExecution, CallDeferred, ApprovalRequired,
                ToolRetryError):
        assert exc in declared, f"{exc.__name__} is not carved out of the capture catch-all"

    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=raising(rec, ModelRetry("narrow the window and retry")),
                   turns=[q("elastic", "probe", {}), DONE])
    assert "narrow the window and retry" in r.gather_saw


def test_breaker_pre_call_trip_returns_without_executing(tmp_path):
    """breaker_pre_call_trip_returns_without_executing — once a system is tripped, query()
    returns the down-message as the TOOL RESULT without invoking the verb and without raising
    ModelRetry (a tripped system never recovers, so a retry would burn the budget into an"""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=raising(rec, TransportFault("down")), turns=[
        q("elastic", "probe", {}),
        q("elastic", "probe", {}),
        q("elastic", "probe", {}),
        DONE,
    ])
    assert len(rec.calls) == 2, "the tripped system was queried again"
    assert len(r.own_rows) == 2, "the pre-call trip recorded a query that never executed"
    assert "[circuit-breaker]" in r.gather_saw
    assert "is DOWN" in r.gather_saw
    assert r.gather.calls == 4


def test_capture_fires_only_for_the_query_tool(tmp_path):
    """capture_fires_only_for_the_query_tool — a gather run that calls bash / read_file /
    template_search writes NO queries row and has no result swapped: an AbstractCapability hook
    method otherwise fires for EVERY tool (the tools=[…] filter exists only on the Hooks"""
    rec = VerbRecorder()
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id='q611-other')
    main = ReplayFn([
        Turn(tool_calls=[("gather", {
            "lead_id": LEAD, "system": "elastic", "goal": "g", "what_to_summarize": ["e"]})]),
        Turn(text="done"),
    ])
    gather = ReplayFn([
        Turn(tool_calls=[("read_file", {"path": str(run_dir / "alert.json")})]),
        Turn(tool_calls=[("bash", {"command": f"cat {run_dir / 'alert.json'} | wc -l"})]),
        Turn(tool_calls=[("template_search", {"pattern": "sshd"})]),
        DONE,
    ])
    drive(run_dir, run_id="q611-other", main=main, gather=gather,
          verbs=elastic_ok(rec))

    assert gather.calls == 4, "one of the three non-query tools was intercepted and derailed"
    from defender.runtime.lead_zero import RESERVED_LEAD_IDS
    own_rows = [
        row for row in read_jsonl_rows(run_dir / "executed_queries.jsonl")
        if row.get("lead_id") not in RESERVED_LEAD_IDS
    ]
    assert own_rows == [], "a non-query tool call wrote a queries row"
    assert not (run_dir / "gather_raw" / LEAD).exists(), "a non-query tool wrote a payload"


def _echo_registry(rec: VerbRecorder) -> FakeVerbs:
    """A verb whose payload ECHOES its params — so two concurrent payloads are distinguishable
    on disk, and an overwrite is visible rather than silently benign."""

    def probe(ctx: VerbContext, *, tag: str) -> list[dict]:
        rec.record("probe", ctx, {"tag": tag})
        return [{"tag": tag}]

    return FakeVerbs({"elastic": {"probe": probe}})


def _two_in_one_turn() -> Turn:
    return Turn(tool_calls=[
        ("query", {"system": "elastic", "verb": "probe", "params": {"tag": "alpha"}}),
        ("query", {"system": "elastic", "verb": "probe", "params": {"tag": "beta"}}),
    ])


def test_concurrent_queries_do_not_collide_on_seq(tmp_path):
    """concurrent_queries_do_not_collide_on_seq — two query() calls in ONE model turn write
    distinct gather_raw/{lead}/{seq}.json paths and distinct (lead_id, seq) rows; no payload is
    overwritten. pydantic-ai's default parallelism is 'parallel' and sync tool fns are"""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=_echo_registry(rec), turns=[_two_in_one_turn(), DONE])

    assert sorted(c.params["tag"] for c in rec.calls) == ["alpha", "beta"]
    rows = r.own_rows
    assert len(rows) == 2
    assert sorted(row["seq"] for row in rows) == [0, 1]
    assert len({row["payload_path"] for row in rows}) == 2

    got = sorted(json.loads((r.run_dir / row["payload_path"]).read_text())[0]["tag"] for row in rows)
    assert got == ["alpha", "beta"]


def test_seq_collision_would_misdirect_the_judge(tmp_path):
    """seq_collision_would_misdirect_the_judge — (lead_id, seq) is UNIQUE across a concurrent
    run, and every row carries its own payload_path. A duplicate makes judge/compare._payload_paths
    (which falls back to gather_raw/{lead}/0.json when a row carries no payload path) hand the"""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=_echo_registry(rec), turns=[_two_in_one_turn(), DONE])

    rows = r.rows
    keys = [(row["lead_id"], row["seq"]) for row in rows]
    assert len(set(keys)) == len(keys), f"duplicate (lead_id, seq) key: {keys}"

    from defender.runtime.lead_zero import RESERVED_LEAD_IDS
    leads = lead_repository.joined(r.run_dir)
    queries = [
        qr for lead in leads for qr in lead.queries
        if lead.lead_id not in RESERVED_LEAD_IDS
    ]
    assert len(queries) == 2
    refs = [qr.raw_ref for qr in queries]
    assert all(ref is not None for ref in refs), \
        "a row carries no payload path — the judge falls back to 0.json and reads another query"
    assert len(set(map(str, refs))) == 2


def test_hung_verb_records_infra_not_a_synthesized_timeout(tmp_path):
    """hung_verb_records_infra_not_a_synthesized_timeout — a hung verb surfaces through the
    TRANSPORT's own inner timeout as exit 2 / infra, and the breaker advances. 124 is never
    synthesized again: asyncio.wait_for cancels the await, not the thread, so a row claiming a"""
    rec = VerbRecorder()
    r = run_gather(
        tmp_path,
        verbs=raising(rec, TransportFault("docker exec timed out after 40s")),
        turns=[q("elastic", "probe", {}), DONE],
    )
    row = r.row()
    assert row["exit_code"] == 2
    assert row["error_class"] == "infra"
    assert row["exit_code"] != 124, "the seam synthesized a timeout it did not enforce"
    assert "timed out" in row["payload_digest"]
    assert r.breaker["systems"]["elastic"]["failures"] == 1


def test_failure_digest_carries_the_vendor_diagnosis(tmp_path):
    """failure_digest_carries_the_vendor_diagnosis — on failure payload_digest is
    `exit=N; <the upstream error body>`: an HTTP 4xx still carries Elasticsearch's own `detail`
    text, not a generic str(e). The pitfalls curator SKIPS any failure whose digest names no"""
    detail = "[verification_exception] Unknown column [user.nmae], did you mean [user.name]?"
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=raising(rec, UpstreamFault(detail)), turns=[
        q("elastic", "probe", {}), DONE,
    ])
    row = r.row()
    assert row["exit_code"] != 0
    assert row["payload_digest"].startswith(f"exit={row['exit_code']}; ")
    assert detail[:80] in row["payload_digest"]


def test_missing_config_is_infra_not_agent_fixable(tmp_path, caplog):
    """missing_config_is_infra_not_agent_fixable — a missing config is never an agent-fixable
    query error (#611: the transport's bare exit 1 used to file a definitionally-down system as
    the agent's mistake).

    #1256 replaces the rest. The fixture tenant configures elastic, so elastic passes its start
    check and this `ConfigFault` reaches the run at CALL time — an adapter whose settings check
    missed a key (O-5b, DP3), not the startup refusal the design text names for this test: the
    call runs. It no longer ADVANCES the breaker: elastic is marked down as not configured on
    the spot, nothing is charged (per-system or run-wide), the lead's same call retried is
    refused naming "not configured" and the fault's reason without running the verb, and the
    escape is logged as an adapter defect at ERROR or above naming elastic. The escaped call's
    own row is not pinned (the design is silent), beyond never being agent-fixable."""
    import logging

    caplog.set_level(logging.INFO)
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=raising(rec, ConfigFault("config file not found")), turns=[
        q("elastic", "probe", {}), q("elastic", "probe", {}), DONE,
    ])
    assert [row for row in r.own_rows if row.get("error_class") == "agent-fixable"] == [], \
        f"a missing config is misfiled as an agent-fixable error: {r.own_rows}"
    assert rec.verbs == ["probe"], \
        f"after a call-time ConfigFault elastic must be down: the retry ran the verb: {rec.verbs}"
    assert r.state.breaker_failures("elastic") == 0, \
        f"a call-time ConfigFault was charged to elastic (#1256 O-5b): {r.breaker}"
    assert r.state.breaker_snapshot()["total_failures"] == 0, \
        f"a call-time ConfigFault was charged to the run (#1256 O-5b): {r.breaker}"
    assert len(r.gather.seen) >= 3, f"precondition: the retry was answered ({len(r.gather.seen)} requests)"
    assert r.gather.seen[2].startswith(r.gather.seen[1]), \
        "precondition: a gather request's text extends the one before it (harness shape)"
    retried = r.gather.seen[2][len(r.gather.seen[1]):]
    assert "not configured" in retried.lower(), \
        f"the retry's refusal must say elastic is not configured: {retried!r}"
    assert "config file not found" in retried, f"the refusal must carry the fault's reason: {retried!r}"
    assert "tripped" not in retried.lower(), f"a not-configured refusal reads as a trip: {retried!r}"
    defects = [rec_ for rec_ in caplog.records
               if rec_.levelno >= logging.ERROR and "elastic" in rec_.getMessage()]
    assert defects, "the escaped ConfigFault was not logged as an adapter defect naming elastic"


@pytest.mark.parametrize("empty", [{}, []])
def test_empty_verb_return_is_payload_status_empty(tmp_path, empty):
    """empty_verb_return_is_payload_status_empty — a verb returning {} or [] yields
    payload_status='empty': the seam tests the RETURNED OBJECT for emptiness BEFORE serializing,
    because json.dumps({}) == '{}' is non-blank and would read as 'ok' — silently killing the"""
    rec = VerbRecorder()

    def probe(ctx: VerbContext, *, native_query: str = "x"):
        rec.record("probe", ctx, {"native_query": native_query})
        return empty

    r = run_gather(tmp_path, verbs=FakeVerbs({"elastic": {"probe": probe}}), turns=[
        q("elastic", "probe", {}), DONE,
    ], run_id=f"empty-{type(empty).__name__}")
    row = r.row()
    assert row["exit_code"] == 0
    assert row["payload_status"] == "empty"
    assert row["error_class"] is None


def _provider_key_vars() -> set[str]:
    from defender.runtime import providers
    return providers.api_key_vars()


def test_provider_key_absent_from_transport_children(tmp_path, monkeypatch):
    """provider_key_absent_from_transport_children — no subprocess a transport forks carries a
    provider API key in its environment. The scrub rides on _bash_env today; in-process the
    transports pass no env= and would inherit the driver's os.environ."""
    keys = _provider_key_vars()
    assert keys, "no provider key vars declared — the scrub would be vacuous"
    for var in keys:
        monkeypatch.setenv(var, "sk-secret-do-not-leak")

    rec = VerbRecorder()
    run_gather(tmp_path, verbs=elastic_ok(rec), turns=[
        q("elastic", "query", {"native_query": "x"}), DONE,
    ])
    env = rec.only().ctx.env
    leaked = sorted(k for k in keys if k in env)
    assert leaked == [], f"the verb was handed a provider key: {leaked}"
    assert "sk-secret-do-not-leak" not in "".join(env.values())


def test_verb_resolves_config_from_deps_tree(tmp_path):
    """verb_resolves_config_from_deps_tree — a verb resolves its config from the RUN's
    record (the ctx), not an import-time module constant: a run handed tenant A's record reads
    `<A settings>/systems/{system}/config.env` as it was when the run began (#1107: the record"""
    def _ctx_over(root: Path, tenant_id: str, url: str | None) -> VerbContext:
        configs = {} if url is None else {"elastic": (
            f"ELASTIC_URL_BASE={url}\nELASTIC_BASTION_HOST=bastion\nELASTIC_TIMEOUT_SEC=30\n"
            "ELASTIC_TRANSPORT=docker-exec\nELASTIC_DOCKER_CONTEXT=ctx-elastic\n")}
        S1107.plant(root, tenant_id, configs=configs)
        return _tenants1106.verb_context(
            DEFENDER, tmp_path / "run", {}, tenant=S1107.resolve(root, tenant_id))

    cfg_a = _stub_transport.load_config(
        _ctx_over(tmp_path / "a", "t", "http://tree-a:9200"), "elastic", "ELASTIC")
    cfg_b = _stub_transport.load_config(
        _ctx_over(tmp_path / "b", "t", "http://tree-b:9200"), "elastic", "ELASTIC")

    assert cfg_a["URL_BASE"] == "http://tree-a:9200"
    assert cfg_b["URL_BASE"] == "http://tree-b:9200", \
        "the second tree's verb read the first tree's config (an import-time DEFENDER_DIR)"

    with pytest.raises(ConfigFault):
        _stub_transport.load_config(
            _ctx_over(tmp_path / "nowhere", "t", None), "elastic", "ELASTIC")


ROW_KEYS = {
    "lead_id", "seq", "system", "verb", "query_id", "params", "raw_command",
    "payload_path", "exit_code", "error_class", "payload_status", "payload_digest",
    # #877 F-9: the payload's CONTENT identity, beside the display digest rather than inside
    # it — `repeat_note` asserts byte identity from this, the digest stays prose a curator
    # reads. Derived by the writer from the text it persists, so no caller can disagree with
    # the sidecar it just wrote.
    "payload_sha256",
    # #871: the identity of a call whose `system` column deliberately does NOT carry the name
    # the model used. A HASH, never the string — this table is in the gather agent's read
    # scope and `_build_pitfalls_handoffs` spends `system` verbatim as a corpus path — and
    # `""` on every row that kept its dispatched system, which is all of them but the
    # above-guard rejections #855 coarsened.
    "system_key",
    # #1234 A12: the call's host-written id (`record_query.next_call_id`), the one key its
    # served-ledger rows share.
    "call_id",
}


def test_row_contract_frozen(tmp_path):
    """row_contract_frozen — the fourteen-key queries row: params keyed by the REGISTRY's real param
    names (not arg0/arg1), verb holding the tool's REAL verb (the column has zero production
    readers today and finally becomes honest), raw_command a derived audit string."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=elastic_ok(rec), turns=[
        q("elastic", "query", {"native_query": "FROM logs | LIMIT 2", "limit": 2},
          query_id="elastic.sshd-auth-history"),
        DONE,
    ])
    row = r.row()
    assert set(row) == ROW_KEYS

    assert row["lead_id"] == LEAD
    assert row["seq"] == 0
    assert row["system"] == "elastic"
    assert row["verb"] == "query", "verb must hold the tool's real verb, not the query_id suffix"
    assert row["query_id"] == "elastic.sshd-auth-history"
    assert row["params"] == {"native_query": "FROM logs | LIMIT 2", "limit": 2}
    assert "arg0" not in row["params"]
    assert row["exit_code"] == 0
    assert row["error_class"] is None
    assert row["payload_status"] == "ok"
    assert row["payload_digest"]
    # #871: pinned by VALUE here like every other column, not left to `set(row) == ROW_KEYS`.
    # An executed row's `system` is the dispatched name, so it identifies its own call and the
    # fingerprint column is empty — and today nothing else asserts that directly: a non-`""`
    # here is caught only indirectly, by `repeat_trip`'s live call passing `""` and the row
    # then matching nothing.
    assert row["system_key"] == "", \
        "an executed row was fingerprinted, which splits its own system's repeat count"

    assert isinstance(row["raw_command"], str)
    assert "elastic" in row["raw_command"]
    assert "query" in row["raw_command"]
    assert "FROM logs | LIMIT 2" in row["raw_command"]


def test_payload_lands_by_ref(tmp_path):
    """payload_lands_by_ref — the verb's return value is serialized to
    gather_raw/{lead_id}/{seq}.json and payload_path is the RUN-DIR-RELATIVE path to it."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=elastic_ok(rec), turns=[
        q("elastic", "query", {"native_query": "x"}), DONE,
    ])
    row = r.row()
    assert row["payload_path"] == f"gather_raw/{LEAD}/0.json"
    assert not Path(row["payload_path"]).is_absolute()
    assert json.loads((r.run_dir / row["payload_path"]).read_text(encoding="utf-8")) == PAYLOAD


def test_stage_tables_still_round_trips(tmp_path):
    """stage_tables_still_round_trips — lead_repository.stage_tables (copy2 + copytree), the
    SECOND writer of both sinks (driven by core/persist), still round-trips a
    run dir under the new row shape: the replay contract is over the FILES, not the writer."""
    rec = VerbRecorder()
    r = run_gather(tmp_path / "src", verbs=_echo_registry(rec), turns=[
        q("elastic", "probe", {"tag": "alpha"}),
        q("elastic", "probe", {"tag": "beta"}),
        DONE,
    ])
    dst = tmp_path / "staged"
    lead_repository.stage_tables(r.run_dir, dst)

    assert read_jsonl_rows(dst / "executed_queries.jsonl") == r.rows
    for row in r.rows:
        assert (dst / row["payload_path"]).read_text() == (r.run_dir / row["payload_path"]).read_text()
    from defender.runtime.lead_zero import RESERVED_LEAD_IDS
    staged = lead_repository.joined(dst)
    own_staged = [lead for lead in staged if lead.lead_id not in RESERVED_LEAD_IDS]
    assert [lead.lead_id for lead in own_staged] == [LEAD]
    assert len(own_staged[0].queries) == 2


def _policies(tmp_path):
    run_dir = tmp_path / "run"
    (run_dir / "gather_raw" / LEAD).mkdir(parents=True)
    (run_dir / "gather_raw" / LEAD / "0.json").write_text("[]", encoding="utf-8")
    gather = compile_policy_for(
        _tenants1106.fixture_gather_def(), run_dir=run_dir, defender_dir=DEFENDER)
    main = compile_policy_for(MAIN_DEF, run_dir=run_dir, defender_dir=DEFENDER)
    return run_dir, gather, main


def _decide(cmd: str, policy, run_dir):
    return permission.decide_bash(cmd, policy=policy, run_dir=run_dir, defender_dir=DEFENDER)


@pytest.mark.parametrize("cmd", [
    "defender-elastic query foo",
    "defender-elastic esql 'FROM x' | defender-sql 'SELECT 1'",
    "python3 defender/scripts/adapters/elastic_adapter.py query foo",
])
def test_adapters_unreachable_from_gather_bash(tmp_path, cmd):
    """adapters_unreachable_from_gather_bash — no adapter shim or *_adapter.py path is runnable from
    gather's bash lane: the CAPTURE_ADAPTER / CAPTURE_ADAPTER_SQL grants are gone and the adapter
    classifier denies unconditionally."""
    run_dir, gather, _ = _policies(tmp_path)
    decision = _decide(cmd, gather, run_dir)
    assert not decision.allow, f"gather can still run an adapter from bash: {cmd}"
    assert all(g.route is Route.PLAIN for g in gather.bash_allow)
    assert not hasattr(decision, "adapter_argv")
    assert not hasattr(decision, "sql_pipe")


def test_gather_bash_keeps_local_computation(tmp_path):
    """gather_bash_keeps_local_computation — `cat <gather_raw payload> | defender-sql '<SQL>'`
    is still ALLOW for gather, so the split pipe (tool-then-bash) works."""
    run_dir, gather, _ = _policies(tmp_path)
    payload = run_dir / "gather_raw" / LEAD / "0.json"
    assert _decide(f"cat {payload} | defender-sql 'SELECT count(*) FROM data'",
                   gather, run_dir).allow
    assert _decide(f"cat gather_raw/{LEAD}/0.json | defender-sql 'SELECT 1'",
                   gather, run_dir).allow
    assert not _decide("cat ../../etc/passwd | defender-sql 'SELECT 1'", gather, run_dir).allow


#: The raw ES|QL response the fake `esql` verb hands the adapter's own shaping step.
_ESQL_RAW = {
    "columns": [{"name": "failed", "type": "long"}, {"name": "source.ip", "type": "ip"}],
    "values": [[412, "203.0.113.7"], [9, "198.51.100.22"], [3, "203.0.113.40"]],
}


def test_gather_bash_runs_a_declared_defender_sql_over_the_esql_payload_it_captured(tmp_path):
    """#1138 O7 end to end — the lead queries ES|QL with the `query` tool, then declares the
    captured payload's positional rows from its bash lane:
    `cat <payload> | defender-sql --rows values --names columns '<SQL>'`. The REAL gate must"""
    from defender.scripts.adapters.elastic_adapter import esql_payload

    rec = VerbRecorder()

    def esql(ctx: VerbContext, *, native_query: str) -> dict:
        rec.record("esql", ctx, {"native_query": native_query})
        return esql_payload(native_query, _ESQL_RAW)

    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id='q1138')
    payload_abs = run_dir / "gather_raw" / LEAD / "0.json"
    command = (f"cat {payload_abs} | defender-sql --rows values --names columns "
               "'SELECT count(*) AS n, sum(failed) AS s FROM data'")
    main = ReplayFn([
        Turn(tool_calls=[("gather", {
            "lead_id": LEAD, "system": "elastic", "goal": "g", "what_to_summarize": ["e"]})]),
        Turn(text="done"),
    ])
    gather = ReplayFn([
        q("elastic", "esql", {"native_query": "FROM logs-* | STATS failed = COUNT(*) BY source.ip"}),
        Turn(tool_calls=[("bash", {"command": command})]),
        DONE,
    ])
    drive(run_dir, run_id="q1138", main=main, gather=gather,
          verbs=FakeVerbs({"elastic": {"esql": esql}}))

    assert json.loads(payload_abs.read_text(encoding="utf-8"))["values"] == _ESQL_RAW["values"], (
        "premise: the query tool captured the ES|QL payload the bash call reads")
    assert len(gather.seen) >= 3, "the replay never reached the turn after the bash call"
    before, after = gather.seen[1], gather.seen[2]
    assert after.startswith(before), "the replay's message history is not cumulative"
    bash_result = after[len(before):]
    assert "Blocked" not in bash_result, f"the gate refused the declared pipe: {bash_result!r}"
    if not _sql_shim_aggregates():
        pytest.skip("this tree's defender-sql cannot aggregate (no duckdb in the venv it "
                    "re-execs into) — the gate half of the test ran and held")
    assert re.search(r'"n":\s*3\b', bash_result), bash_result
    assert re.search(r'"s":\s*424\b', bash_result), bash_result


def test_main_cannot_reach_a_payload_by_any_surface(tmp_path):
    """main_cannot_reach_a_payload_by_any_surface — the main loop cannot read a gather_raw payload
    by ANY surface, including a bash command carrying a `# record_query` comment. Main's clamp is
    positive enumeration (it has no gather_raw shape at all)."""
    run_dir, _, main = _policies(tmp_path)
    payload = run_dir / "gather_raw" / LEAD / "0.json"
    assert not _decide(f"cat {payload}", main, run_dir).allow
    assert not _decide(f"cat {payload} # record_query", main, run_dir).allow
    assert not permission.decide_read(
        payload, run_dir=run_dir, defender_dir=DEFENDER, policy=main).allow
