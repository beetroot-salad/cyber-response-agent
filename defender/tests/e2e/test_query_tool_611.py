"""#611 slice 1 — the executable spec for the `query` tool, the VERBS registry, and
capture-as-a-capability.

Every test here is one demand of `defender/tests/spec_graph_611-query-tool.yaml`, named
after it and carrying its id in the docstring. THE CODE DOES NOT EXIST YET: this suite is
RED by construction (the imports below name the surface the implementation must build), and
that is the point — the tests are the spec the code is written against.

The surface this suite pins
---------------------------
`defender/runtime/verbs.py`
    `VerbContext(defender_dir, run_dir, env)` — what the harness hands a verb: the RUN's tree
    (never an import-time constant) and the RUN's scrubbed env (never `os.environ`).
    `declared_params(fn)` — a verb's param surface = the keyword-only params of its annotated
    signature. This is the ONE reader of a verb's signature; the tool's validator uses it.
    `ModuleVerbRegistry(adapters_dir)` — the production registry: `systems()` + `verbs(system)`,
    resolved per TREE, reading each adapter module's `VERBS` mapping.

`defender/runtime/query_tool.py`
    `register_query_tool(agent, registry)` / `QueryCapture` / `CONTROL_FLOW_EXCEPTIONS` /
    `resolve_query_id(system, verb, model_query_id)`.

`defender/scripts/adapters/faults.py`
    `AdapterFault` + `ConfigFault` (infra) / `TransportFault` (infra) / `UpstreamFault` (the
    vendor's own diagnosis). Transports RAISE these; they never `sys.exit`.

`ToolSet(query=…)` + `build_agent_core(..., verbs=…)` + `run_investigation(..., verbs=…)`
    The tool is declared as DATA on the agent definition; the registry is INJECTED down the
    build chain exactly like `make_model`. There is no monkeypatch anywhere in this file.

Fakes inject faults; they never classify. A fake verb records what it was handed and then
returns its payload or raises its fault — every exit code, error class, payload status and
breaker outcome in the assertions below is production code's work.
"""
from __future__ import annotations

import ast
import importlib.util
import inspect
import json
import re
from dataclasses import fields, replace
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.capabilities.abstract import AbstractCapability  # noqa: E402
from pydantic_ai.exceptions import (  # noqa: E402
    ApprovalRequired,
    CallDeferred,
    ModelRetry,
    SkipToolExecution,
    ToolRetryError,
)
from pydantic_ai.models.function import FunctionModel  # noqa: E402

from defender._io import read_jsonl_rows  # noqa: E402
from defender._run_paths import RunPaths  # noqa: E402
from defender.hooks._cmd_segments import NON_ADAPTER_SHIMS  # noqa: E402
from defender.hooks.inject_system_skill_description import descriptor_catalog  # noqa: E402
from defender.learning import lead_repository  # noqa: E402
from defender.runtime import circuit_breaker, observe, permission, tools as runtime_tools  # noqa: E402
from defender.runtime.agent_definition import bind, compile_policy_for  # noqa: E402
from defender.runtime.circuit_breaker import RunAborted, error_class_for_exit  # noqa: E402
from defender.runtime.driver import GATHER_DEF, MAIN_DEF, build_agent_core  # noqa: E402
from defender.runtime.permission.grant import _SHIM_FLAGS, Route  # noqa: E402
from defender.runtime.providers import BuiltModel  # noqa: E402
from defender.scripts.adapters import ticket_adapter  # noqa: E402
from defender.scripts.gather_tools import record_query  # noqa: E402
from defender.tests.e2e import _replay_harness  # noqa: E402
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

# --- the surface under test: none of this exists yet (the suite's RED anchor) ---
from defender.runtime import query_tool  # noqa: E402
from defender.runtime.verbs import (  # noqa: E402
    ModuleVerbRegistry,
    VerbContext,
    declared_params,
)
from defender.scripts.adapters import _stub_transport  # noqa: E402
from defender.scripts.adapters.faults import (  # noqa: E402
    ConfigFault,
    TransportFault,
    UpstreamFault,
)

pytestmark = pytest.mark.e2e

SALT = "aabbccddeeff0011"
LEAD = "l-001"
ADAPTERS_DIR = DEFENDER / "scripts" / "adapters"
_HAS_DUCKDB = importlib.util.find_spec("duckdb") is not None

# The one payload every happy-path fake verb returns. A two-record list: the count is what
# the defender-sql positive control aggregates, and the field shape is what the truncated
# view samples.
PAYLOAD = [
    {"@timestamp": "2026-01-01T00:00:00Z", "user.name": "dev.dana", "event.action": "ssh_login"},
    {"@timestamp": "2026-01-01T00:05:00Z", "user.name": "dev.dana", "event.action": "sudo"},
]


# ── scenario plumbing ────────────────────────────────────────────────────────


class _Run:
    """One driven replay: the run dir plus the two replay models and the tables on disk."""

    def __init__(self, run_dir: Path, main: ReplayFn, gather: ReplayFn):
        self.run_dir, self.main, self.gather = run_dir, main, gather

    @property
    def rows(self) -> list[dict]:
        return read_jsonl_rows(self.run_dir / "executed_queries.jsonl")

    def row(self) -> dict:
        assert len(self.rows) == 1, f"expected exactly one queries row, got {self.rows}"
        return self.rows[0]

    @property
    def gather_saw(self) -> str:
        """The gather model's last message history — where a tool RESULT (the query return,
        a deny reason bounced back as ModelRetry feedback) shows up."""
        return self.gather.seen[-1]

    def payload(self, seq: int = 0) -> str:
        return (self.run_dir / "gather_raw" / LEAD / f"{seq}.json").read_text(encoding="utf-8")

    @property
    def breaker(self) -> dict:
        p = self.run_dir / "circuit_breaker.json"
        return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {}


def run_gather(
    tmp_path: Path, *, verbs, turns: list[Turn], system: str = "elastic", run_id: str = "q611",
) -> _Run:
    """Drive a REAL run: main dispatches one gather lead, the nested gather agent replays
    `turns` (the query calls under test) against the INJECTED verb registry. Everything
    between the two fakes — dispatch, the query tool, its validator, the capture capability,
    the circuit breaker, the two tables — is production code."""
    run_dir = materialize(tmp_path, GOLDEN_AB3)
    main = ReplayFn([
        Turn(tool_calls=[("gather", {
            "lead_id": LEAD, "system": system, "goal": "measure this lead",
            "what_to_summarize": ["auth events"],
        })]),
        Turn(text="Investigation complete."),
    ])
    gather = ReplayFn(turns)
    drive(run_dir, run_id=run_id, salt=SALT, main=main, gather=gather, verbs=verbs)
    return _Run(run_dir, main, gather)


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
    one of those is the capture capability's job, and every assertion about them is therefore
    a real assertion about production code."""

    def probe(ctx: VerbContext, *, native_query: str = "FROM logs") -> list[dict]:
        rec.record("probe", ctx, {"native_query": native_query})
        raise exc

    return FakeVerbs({s: {"probe": probe} for s in systems})


# ═════════════════════════════════════════════════════════════════════════════
# The return contract
# ═════════════════════════════════════════════════════════════════════════════


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

    # The verb ran, and it was handed the params the model bound (not just "a call happened").
    assert rec.only().params == {"native_query": "FROM logs | LIMIT 2", "limit": 10}

    assert "exit=0" in seen
    assert f"<run-{SALT}-untrusted>" in seen
    assert f"</run-{SALT}-untrusted>" in seen
    assert f"[record_query] raw payload: {payload_abs}" in seen
    # The gather SKILL filters on the note line, so the note must carry the path — a bare
    # `payload_ref` return (the issue's literal signature) is the REJECTED alternative.
    assert "dev.dana" in seen, "the truncated view of the payload must reach the model"


def test_query_return_wrap_uses_the_run_salt(tmp_path):
    """query_return_wrap_uses_the_run_salt — the wrap uses deps.salt (the per-run token), never
    a freshly minted one: with a fresh salt the model can forge the closing tag and the
    injection defense fails open."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=elastic_ok(rec), turns=[
        q("elastic", "query", {"native_query": "FROM logs"}), DONE,
    ])
    tags = re.findall(r"<run-([0-9a-zA-Z]+)-untrusted>", r.gather_saw)
    assert tags, "the query return carried no untrusted wrap at all"
    assert set(tags) == {SALT}, f"a wrap used a salt other than the run's: {set(tags)}"


def test_query_payload_is_not_double_wrapped_on_read_back(tmp_path):
    """query_payload_is_not_double_wrapped_on_read_back — reading the persisted payload back
    with the REAL read tool (which salt-wraps gather_raw/ via is_untrusted_read) yields exactly
    ONE wrap, not a wrap nested inside the one the query tool already applied."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=elastic_ok(rec), turns=[
        q("elastic", "query", {"native_query": "FROM logs"}), DONE,
    ])
    payload_abs = r.run_dir / "gather_raw" / LEAD / "0.json"

    gdeps = bind(GATHER_DEF, r.run_dir, salt=SALT, defender_dir=DEFENDER)
    out = runtime_tools._tool_read_file(gdeps, str(payload_abs))

    assert out.count(f"<run-{SALT}-untrusted>") == 1
    assert out.count(f"</run-{SALT}-untrusted>") == 1
    assert "dev.dana" in out


def test_query_return_wrap_positive_control(tmp_path):
    """query_return_wrap_positive_control — the payload's own bytes stay fully recoverable
    through the sanctioned path: the file holds the UNWRAPPED payload and defender-sql over it
    aggregates the real rows."""
    rec = VerbRecorder()
    payload_abs = None

    turns = [q("elastic", "query", {"native_query": "FROM logs"})]
    # The split pipe (tool → bash) is the sanctioned aggregation route; it needs the ABSOLUTE
    # path the payload note carries.
    sql_turn_idx = None
    if _HAS_DUCKDB:
        sql_turn_idx = len(turns)
        turns.append(Turn(tool_calls=[("bash", {"command": "PLACEHOLDER"})]))
    turns.append(DONE)

    # The bash command names the run dir, which only exists once materialize() has run — so
    # drive it in two steps rather than guessing the path.
    run_dir = materialize(tmp_path, GOLDEN_AB3)
    payload_abs = run_dir / "gather_raw" / LEAD / "0.json"
    if sql_turn_idx is not None:
        turns[sql_turn_idx] = Turn(tool_calls=[("bash", {
            "command": f"cat {payload_abs} | defender-sql 'SELECT count(*) AS n FROM data'",
        })])
    main = ReplayFn([
        Turn(tool_calls=[("gather", {
            "lead_id": LEAD, "system": "elastic", "goal": "g", "what_to_summarize": ["e"]})]),
        Turn(text="done"),
    ])
    gather = ReplayFn(turns)
    drive(run_dir, run_id="q611-ctl", salt=SALT, main=main, gather=gather, verbs=elastic_ok(rec))

    on_disk = payload_abs.read_text(encoding="utf-8")
    assert "<run-" not in on_disk, "the persisted payload must be the raw bytes, never wrapped"
    assert json.loads(on_disk) == PAYLOAD

    if _HAS_DUCKDB:
        assert re.search(r'"n":\s*2', gather.seen[-1]), \
            "defender-sql over the persisted payload did not aggregate the real rows"


# ═════════════════════════════════════════════════════════════════════════════
# The registry
# ═════════════════════════════════════════════════════════════════════════════


def test_verbs_registry_declares_surface():
    """verbs_registry_declares_surface — every adapter module exports a VERBS mapping of
    verb → callable whose ANNOTATED signature declares that verb's params, and
    `declared_params` (the one reader the tool's validator uses) reads exactly that."""
    reg = ModuleVerbRegistry(ADAPTERS_DIR)
    on_disk = sorted(
        p.name[: -len("_adapter.py")].replace("_", "-") for p in ADAPTERS_DIR.glob("*_adapter.py")
    )
    assert sorted(reg.systems()) == on_disk, "the registry roster is not the adapter roster"

    for system in reg.systems():
        verbs = reg.verbs(system)
        assert verbs, f"{system} declares no verbs"
        for name, fn in verbs.items():
            assert callable(fn), f"{system}.{name} is not callable"
            sig = inspect.signature(fn)
            params = declared_params(fn)
            # The declared params ARE the keyword-only params: everything else in the
            # signature is harness carriage (the VerbContext), never model-supplied.
            kwonly = {
                p.name for p in sig.parameters.values()
                if p.kind is inspect.Parameter.KEYWORD_ONLY
            }
            assert set(params) == kwonly, f"{system}.{name}: declared params != kw-only params"
            for p in params.values():
                assert p.annotation is not inspect.Parameter.empty, \
                    f"{system}.{name}.{p.name} carries no annotation — the validator has no type"


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
    # The rejection came back to the model as retry feedback, and the model kept going.
    assert r.gather.calls >= 2, "the rejection did not bounce the gather agent back into its loop"


def test_registry_validation_failure_writes_its_row_before_raising(tmp_path):
    """registry_validation_failure_writes_its_row_before_raising — a registry validation
    failure writes its queries row (64 / agent-fixable / error) BEFORE raising ModelRetry:
    ModelRetry bypasses on_tool_execute_error AND after_tool_execute, so a write that follows
    the raise never happens."""
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
    # 64 is not an infra code: a model typo must not trip the breaker and hide a live system.
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
    rows = r.rows
    assert len(rows) == 1, "an arg-shape failure wrote no row — half the exit-64 class is gone"
    assert rows[0]["exit_code"] == 64
    assert rows[0]["error_class"] == "agent-fixable"
    assert rows[0]["payload_status"] == "error"


def test_empty_verbs_declaration_fails_closed_at_the_tool(tmp_path):
    """empty_verbs_declaration_fails_closed_at_the_tool — a system whose module declares NO
    verbs is unreachable through query(): an empty declaration must not read as 'no filter'."""
    rec = VerbRecorder()
    verbs = FakeVerbs({"ghost": {}})   # declared, empty — the fail-open shape
    r = run_gather(tmp_path, verbs=verbs, system="ghost", turns=[
        q("ghost", "anything", {"native_query": "x"}), DONE,
    ])
    assert rec.calls == []
    assert r.gather.calls >= 2, "the empty-VERBS system was not rejected back to the model"
    assert all(row["exit_code"] != 0 for row in r.rows), \
        "a system with an empty VERBS declaration answered a query"


def test_empty_verbs_positive_control(tmp_path):
    """empty_verbs_positive_control — the SAME system with a NON-empty VERBS declaration IS
    reachable and returns its payload. The control proving the fail-closed check above can
    observe a difference."""
    rec = VerbRecorder()

    def ping(ctx: VerbContext, *, native_query: str) -> list[dict]:
        rec.record("ping", ctx, {"native_query": native_query})
        return PAYLOAD

    r = run_gather(tmp_path, verbs=FakeVerbs({"ghost": {"ping": ping}}), system="ghost", turns=[
        q("ghost", "ping", {"native_query": "x"}), DONE,
    ])
    assert rec.only().params == {"native_query": "x"}
    row = r.row()
    assert row["exit_code"] == 0
    assert row["system"] == "ghost"
    assert json.loads(r.payload()) == PAYLOAD


# --- the descriptor catalog: fail-closed at the PROMPT too --------------------

_ADAPTER_NO_VERBS = "VERBS = {}\n"

_ADAPTER_WITH_VERBS = (
    "def look(ctx, *, name: str) -> dict:\n"
    '    return {"name": name}\n'
    "\n"
    'VERBS = {"look": look}\n'
)

# The import-time module constant the freeze demand guards: if two trees' modules collide in
# sys.modules, tree B's verb reports tree A's root.
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
    catalog = descriptor_catalog(tree / "skills", tree / "scripts" / "adapters")
    assert catalog is not None
    assert "`solid`" in catalog
    assert "hollow" not in catalog, "a system with no declared verbs was advertised to gather"


def test_descriptor_catalog_does_not_freeze_the_tree(tmp_path):
    """descriptor_catalog_does_not_freeze_the_tree — two catalogs built for two trees in ONE
    process (the learning loop's worktree-drain shape) each resolve their OWN tree: building
    the catalog for tree A must not make a later verb call under tree B run A's module."""
    a = _make_tree(tmp_path / "a", {"probe": _TREE_PROBE}, described=("probe",))
    b = _make_tree(tmp_path / "b", {"probe": _TREE_PROBE}, described=("probe",))

    # Build A's catalog FIRST — if the roster import (or the @cache memo) keys on anything but
    # the tree, B inherits A's module object below.
    assert descriptor_catalog(a / "skills", a / "scripts" / "adapters") is not None
    assert descriptor_catalog(b / "skills", b / "scripts" / "adapters") is not None

    ctx_a = VerbContext(defender_dir=a, run_dir=tmp_path / "run", env={})
    ctx_b = VerbContext(defender_dir=b, run_dir=tmp_path / "run", env={})
    fn_a = ModuleVerbRegistry(a / "scripts" / "adapters").verbs("probe")["whoami"]
    fn_b = ModuleVerbRegistry(b / "scripts" / "adapters").verbs("probe")["whoami"]

    assert fn_a(ctx_a) == {"tree": str(a)}
    assert fn_b(ctx_b) == {"tree": str(b)}, \
        "tree B's verb ran tree A's module — the roster/registry froze the first tree it saw"


_PROGRAM_ISH = {"program", "command", "cmd", "argv", "exec", "shell", "script", "binary", "path"}
# The ONE declared exception (spec: `no_verb_names_a_program_or_command`): host-state's
# fim-checksum takes a path ON A PLAYGROUND TARGET HOST, reached via docker exec — not a path
# in the driver's namespace.
_PATH_EXCEPTION = ("host-state", "fim-checksum", "path")


def test_no_verb_names_a_program_or_command():
    """no_verb_names_a_program_or_command — no verb signature declares a param that is a
    program, a command, or a path in the DRIVER's namespace. host-state's fim-checksum path
    (a path on a target host, via docker exec) is the declared exception."""
    reg = ModuleVerbRegistry(ADAPTERS_DIR)
    offenders = [
        (system, verb, name)
        for system in reg.systems()
        for verb, fn in reg.verbs(system).items()
        for name in declared_params(fn)
        if name in _PROGRAM_ISH and (system, verb, name) != _PATH_EXCEPTION
    ]
    assert offenders == [], f"verb params name a program/command/path: {offenders}"


# ═════════════════════════════════════════════════════════════════════════════
# query_id
# ═════════════════════════════════════════════════════════════════════════════


def test_query_id_fallback_chain(tmp_path):
    """query_id_fallback_chain — model-supplied → {system}.{verb} → {system}.ad-hoc, and
    deps.query_id (never assigned anywhere) is DELETED, not preserved."""
    rec = VerbRecorder()

    # 1. model-supplied wins.
    r1 = run_gather(tmp_path / "a", verbs=elastic_ok(rec), turns=[
        q("elastic", "query", {"native_query": "x"}, query_id="elastic.sshd-auth-history"), DONE,
    ], run_id="qid-model")
    assert r1.row()["query_id"] == "elastic.sshd-auth-history"

    # 2. omitted → {system}.{verb}.
    r2 = run_gather(tmp_path / "b", verbs=elastic_ok(rec), turns=[
        q("elastic", "query", {"native_query": "x"}), DONE,
    ], run_id="qid-derived")
    assert r2.row()["query_id"] == "elastic.query"

    # 3. the degenerate leg (no verb to derive from) → {system}.ad-hoc.
    assert query_tool.resolve_query_id("elastic", "", None) == "elastic.ad-hoc"

    # 4. the dead deps field is gone (it was never assigned anywhere).
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


def test_query_id_traversal_positive_control(tmp_path):
    """query_id_traversal_positive_control — a normally coined {system}.{kebab} id is ACCEPTED
    and recorded verbatim."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=elastic_ok(rec), turns=[
        q("elastic", "query", {"native_query": "x"}, query_id="elastic.sshd-auth-baseline-7d"),
        DONE,
    ])
    row = r.row()
    assert row["query_id"] == "elastic.sshd-auth-baseline-7d"
    assert row["exit_code"] == 0
    assert len(rec.calls) == 1


# ═════════════════════════════════════════════════════════════════════════════
# Capture as a capability
# ═════════════════════════════════════════════════════════════════════════════


def test_capture_runs_in_wrap_tool_execute():
    """capture_runs_in_wrap_tool_execute — capture is implemented in wrap_tool_execute: the only
    execute-family hook that observes the pre-call, both outcomes AND the exception, and the only
    one that can skip handler() and return a value (the breaker's pre-call trip).

    after_tool_execute is skipped when the tool raises and bypassed entirely by ModelRetry, so a
    capture hung there would write NO row for any failed query and leave the breaker dead code."""
    cap = query_tool.QueryCapture
    assert cap.wrap_tool_execute is not AbstractCapability.wrap_tool_execute, \
        "capture does not override wrap_tool_execute"
    # The VALIDATE family runs first and is where a malformed tool CALL fails (see
    # arg_shape_validation_error_still_writes_a_64_row), so capture must be on both.
    assert cap.wrap_tool_validate is not AbstractCapability.wrap_tool_validate, \
        "capture does not override wrap_tool_validate — an arg-shape failure writes no row"
    assert cap.after_tool_execute is AbstractCapability.after_tool_execute, \
        "capture leans on after_tool_execute, which a raising tool and ModelRetry both skip"


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
    # The class is derived by the ONE taxonomy function, never re-decided at the seam.
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
    # The run survived: the gather agent reached its summary turn and the main loop finished.
    assert r.gather.calls == 2
    assert r.main.calls == 2
    row = r.row()
    assert row["exit_code"] != 0
    assert row["payload_status"] == "error"


def test_capture_catch_all_re_raises_the_control_flow_exceptions(tmp_path):
    """capture_catch_all_re_raises_the_control_flow_exceptions — the catch-all must NOT swallow
    RunAborted (the run-wide kill switch), ModelRetry, or pydantic-ai's control-flow exceptions.
    Every one of them is a plain Exception subclass, so a broad `except Exception` silently
    disables the kill switch."""
    declared = set(query_tool.CONTROL_FLOW_EXCEPTIONS)
    for exc in (RunAborted, ModelRetry, SkipToolExecution, CallDeferred, ApprovalRequired,
                ToolRetryError):
        assert exc in declared, f"{exc.__name__} is not carved out of the capture catch-all"

    # Behavioral half: a verb raising ModelRetry must reach the MODEL as retry feedback, not be
    # buried in a row and swallowed.
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=raising(rec, ModelRetry("narrow the window and retry")),
                   turns=[q("elastic", "probe", {}), DONE])
    assert "narrow the window and retry" in r.gather_saw


def test_run_aborted_still_kills_the_run_positive_control(tmp_path):
    """run_aborted_still_kills_the_run_positive_control — with the carve-out in place, reaching
    RUN_FAIL_KILL_LIMIT still raises RunAborted OUT of the run: the control proving the catch-all
    did not swallow it.

    PER_SYSTEM_FAIL_LIMIT=2 trips a system after two infra failures (a third call to it never
    executes), so the kill limit of 5 is reached across three systems: 2 + 2 + 1."""
    rec = VerbRecorder()
    verbs = raising(rec, TransportFault("down"), systems=("elastic", "cmdb", "identity"))
    r = run_gather(tmp_path, verbs=verbs, turns=[
        q("elastic", "probe", {}), q("elastic", "probe", {}),
        q("cmdb", "probe", {}), q("cmdb", "probe", {}),
        q("identity", "probe", {}),
        DONE,
    ])
    assert circuit_breaker.RUN_FAIL_KILL_LIMIT == 5  # the scenario above is built on this
    assert r.breaker["total_failures"] >= circuit_breaker.RUN_FAIL_KILL_LIMIT
    # RunAborted propagated out of the nested gather, out of the gather tool, out of agent.iter:
    # the driver caught it and wrote the partial trace, so the MAIN loop never got a 2nd turn.
    assert r.main.calls == 1, "RunAborted was swallowed — the run kept going past the kill limit"
    assert len(r.rows) == 5


def test_breaker_pre_call_trip_returns_without_executing(tmp_path):
    """breaker_pre_call_trip_returns_without_executing — once a system is tripped, query()
    returns the down-message as the TOOL RESULT without invoking the verb and without raising
    ModelRetry (a tripped system never recovers, so a retry would burn the budget into an
    UnexpectedModelBehavior crash). Only wrap_tool_execute can express this: before_tool_execute
    may only return args or raise."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=raising(rec, TransportFault("down")), turns=[
        q("elastic", "probe", {}),   # failure 1
        q("elastic", "probe", {}),   # failure 2 → tripped
        q("elastic", "probe", {}),   # pre-call trip → down-message, no verb
        DONE,
    ])
    assert len(rec.calls) == 2, "the tripped system was queried again"
    assert len(r.rows) == 2, "the pre-call trip recorded a query that never executed"
    assert "[circuit-breaker]" in r.gather_saw
    assert "is DOWN" in r.gather_saw
    # No ModelRetry: the gather loop ran its full script (4 turns), it was not aborted.
    assert r.gather.calls == 4


def test_capture_fires_only_for_the_query_tool(tmp_path):
    """capture_fires_only_for_the_query_tool — a gather run that calls bash / read_file /
    template_search writes NO queries row and has no result swapped: an AbstractCapability hook
    method otherwise fires for EVERY tool (the tools=[…] filter exists only on the Hooks
    decorator API)."""
    rec = VerbRecorder()
    run_dir = materialize(tmp_path, GOLDEN_AB3)
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
    drive(run_dir, run_id="q611-other", salt=SALT, main=main, gather=gather,
          verbs=elastic_ok(rec))

    assert gather.calls == 4, "one of the three non-query tools was intercepted and derailed"
    assert read_jsonl_rows(run_dir / "executed_queries.jsonl") == [], \
        "a non-query tool call wrote a queries row"
    assert not (run_dir / "gather_raw" / LEAD).exists(), "a non-query tool wrote a payload"


# --- the toolset seam --------------------------------------------------------


def _built(defn, tmp_path, *, verbs=None):
    """Build one real agent through the single build site, with a model that is never called."""
    def make_model(name, effort):
        return BuiltModel(FunctionModel(lambda messages, info: None), None)

    logger = observe.RequestLogger(tmp_path / "llm_requests.jsonl")
    agent = build_agent_core(
        defn, deps_type=runtime_tools.GatherDeps, instructions="x",
        logger=logger, agent_id="t", make_model=make_model,
        verbs=verbs if verbs is not None else FakeVerbs({}),
    )
    logger.close()
    return agent


def _capabilities(agent) -> list:
    caps: list = []
    agent._root_capability.apply(caps.append)
    return caps


def test_tool_and_capture_are_inseparable(tmp_path):
    """tool_and_capture_are_inseparable — DECLARING the query tool in an agent's ToolSet is what
    constructs the capture capability; an agent cannot be built with the tool and without capture."""
    with_query = _built(GATHER_DEF, tmp_path)
    assert "query" in with_query._function_toolset.tools
    assert any(isinstance(c, query_tool.QueryCapture) for c in _capabilities(with_query)), \
        "the query tool was registered without its capture capability"

    # The negative half: the ToolSet bit is the ONLY switch — drop it and BOTH disappear.
    no_query_def = replace(GATHER_DEF, tools=replace(GATHER_DEF.tools, query=False))
    without = _built(no_query_def, tmp_path)
    assert "query" not in without._function_toolset.tools
    assert not any(isinstance(c, query_tool.QueryCapture) for c in _capabilities(without))


def test_query_tool_lands_in_the_function_toolset(tmp_path):
    """query_tool_lands_in_the_function_toolset — the query tool is a PLAIN agent tool, visible in
    agent._function_toolset.tools. A capability-OWNED toolset lands in _cap_toolsets instead,
    which would leave #538's 'registers NOTHING' tool-freeness assertions green while the
    invariant they encode was false."""
    agent = _built(GATHER_DEF, tmp_path)
    assert "query" in agent._function_toolset.tools
    assert not getattr(agent, "_cap_toolsets", []), \
        "the query tool arrived via a capability-owned toolset, invisible to the #538 assertions"


def test_which_agent_may_query_stays_policy_as_data(tmp_path):
    """which_agent_may_query_stays_policy_as_data — MAIN_DEF registers no query tool and
    GATHER_DEF does: 'which agent may reach a data source' stays in the AgentDefinition, not in a
    call-site capabilities= argument invisible to compile_policy and `defender-policy explain`."""
    assert GATHER_DEF.tools.query is True
    assert MAIN_DEF.tools.query is False
    assert "query" in _built(GATHER_DEF, tmp_path)._function_toolset.tools
    assert "query" not in _built(MAIN_DEF, tmp_path)._function_toolset.tools


# ═════════════════════════════════════════════════════════════════════════════
# Concurrency
# ═════════════════════════════════════════════════════════════════════════════


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
    overwritten. pydantic-ai's default parallelism is 'parallel' and sync tool fns are
    thread-offloaded — today's atomicity is an accident of the bash tool blocking the event loop,
    and that accident is gone."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=_echo_registry(rec), turns=[_two_in_one_turn(), DONE])

    assert sorted(c.params["tag"] for c in rec.calls) == ["alpha", "beta"]
    rows = r.rows
    assert len(rows) == 2
    assert sorted(row["seq"] for row in rows) == [0, 1]
    assert len({row["payload_path"] for row in rows}) == 2

    # Each payload holds ITS OWN result — an overwrite would leave two rows pointing at one
    # answer (or at the same bytes).
    got = sorted(json.loads((r.run_dir / row["payload_path"]).read_text())[0]["tag"] for row in rows)
    assert got == ["alpha", "beta"]


def test_seq_collision_would_misdirect_the_judge(tmp_path):
    """seq_collision_would_misdirect_the_judge — (lead_id, seq) is UNIQUE across a concurrent
    run, and every row carries its own payload_path. A duplicate makes judge/compare._payload_paths
    (which falls back to gather_raw/{lead}/0.json when a row carries no payload path) hand the
    judge ANOTHER query's payload — the harm lands two subsystems away from the writer."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=_echo_registry(rec), turns=[_two_in_one_turn(), DONE])

    rows = r.rows
    keys = [(row["lead_id"], row["seq"]) for row in rows]
    assert len(set(keys)) == len(keys), f"duplicate (lead_id, seq) key: {keys}"

    # Read it back through the REAL join surface the judge uses.
    leads = lead_repository.joined(r.run_dir)
    queries = [qr for lead in leads for qr in lead.queries]
    assert len(queries) == 2
    refs = [qr.raw_ref for qr in queries]
    assert all(ref is not None for ref in refs), \
        "a row carries no payload path — the judge falls back to 0.json and reads another query"
    assert len(set(map(str, refs))) == 2


# ═════════════════════════════════════════════════════════════════════════════
# The process-boundary jobs, re-established in-process
# ═════════════════════════════════════════════════════════════════════════════


def _adapter_sources() -> list[tuple[Path, ast.Module]]:
    return [(p, ast.parse(p.read_text(encoding="utf-8"), filename=str(p)))
            for p in sorted(ADAPTERS_DIR.glob("*.py"))]


def _enclosing_functions(tree: ast.Module) -> dict[ast.AST, str]:
    """node → the name of the function that lexically contains it ("" at module scope)."""
    owner: dict[ast.AST, str] = {}

    def walk(node: ast.AST, fn: str) -> None:
        for child in ast.iter_child_nodes(node):
            name = child.name if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) else fn
            owner[child] = name
            walk(child, name)

    walk(tree, "")
    return owner


def _is_sys_exit(call: ast.Call) -> bool:
    f = call.func
    if isinstance(f, ast.Attribute) and f.attr == "exit":
        return isinstance(f.value, ast.Name) and f.value.id.endswith("sys")
    return isinstance(f, ast.Name) and f.id == "exit"


def test_transports_raise_never_exit():
    """transports_raise_never_exit — no transport calls sys.exit. Fifteen of them do today,
    INSIDE the shared module (_stub_transport), so a per-adapter mapping table structurally
    cannot reach them — and ticket_cli serves both the CLI and the VERBS surface from one
    implementation, so a sys.exit in a command body kills the in-process run.

    The surviving CLI entry point (`main`, and the `__main__` guard) may still exit: that is a
    process, not a transport."""
    offenders: list[str] = []
    for path, tree in _adapter_sources():
        owner = _enclosing_functions(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _is_sys_exit(node):
                fn = owner.get(node, "")
                if fn not in ("main",):
                    offenders.append(f"{path.name}:{node.lineno} (in {fn or '<module>'})")
    assert offenders == [], f"a transport still exits the process instead of raising: {offenders}"


def _subprocess_calls(tree: ast.Module) -> list[ast.Call]:
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr in ("run", "Popen", "check_output"):
            base = node.func.value
            if isinstance(base, ast.Name) and base.id.endswith("subprocess"):
                out.append(node)
    return out


def _kw(call: ast.Call, name: str) -> ast.expr | None:
    return next((k.value for k in call.keywords if k.arg == name), None)


def test_every_transport_decodes_lossily():
    """every_transport_decodes_lossily — a non-UTF-8 byte in ANY transport's output costs one
    replacement character, not the stage. The capture seam's errors='replace' disappears with the
    subprocess, so the guarantee now rests on every transport — and host_state_cli's health-check
    subprocess is a STRICT decode today, where a UnicodeDecodeError is a ValueError that sails
    past every guard."""
    offenders: list[str] = []
    for path, tree in _adapter_sources():
        for call in _subprocess_calls(tree):
            decodes = _kw(call, "text") is not None or _kw(call, "encoding") is not None
            errors = _kw(call, "errors")
            lossy = isinstance(errors, ast.Constant) and errors.value == "replace"
            if decodes and not lossy:
                offenders.append(f"{path.name}:{call.lineno}")
    assert offenders == [], f"a transport subprocess decodes STRICTLY: {offenders}"


def test_hung_verb_records_infra_not_a_synthesized_timeout(tmp_path):
    """hung_verb_records_infra_not_a_synthesized_timeout — a hung verb surfaces through the
    TRANSPORT's own inner timeout as exit 2 / infra, and the breaker advances. 124 is never
    synthesized again: asyncio.wait_for cancels the await, not the thread, so a row claiming a
    timeout we did not enforce would be a lie about a process still running."""
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
    text, not a generic str(e). The pitfalls curator SKIPS any failure whose digest names no
    concrete mistake, so a generic message dries that lane up silently."""
    detail = "[verification_exception] Unknown column [user.nmae], did you mean [user.name]?"
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=raising(rec, UpstreamFault(detail)), turns=[
        q("elastic", "probe", {}), DONE,
    ])
    row = r.row()
    assert row["exit_code"] != 0
    assert row["payload_digest"].startswith(f"exit={row['exit_code']}; ")
    assert detail[:80] in row["payload_digest"]


def test_missing_config_is_infra_not_agent_fixable(tmp_path):
    """missing_config_is_infra_not_agent_fixable — a missing/malformed config.env classifies as
    infra (exit 2) and ADVANCES the breaker. Today the shared transport's bare
    sys.exit('error: config file not found') exits 1, so a definitionally-down system is filed as
    an agent-fixable query error and never trips the breaker."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=raising(rec, ConfigFault("config file not found")), turns=[
        q("elastic", "probe", {}), DONE,
    ])
    row = r.row()
    assert row["exit_code"] == 2
    assert row["error_class"] == "infra"
    assert row["exit_code"] != 1, "a missing config is still misfiled as an agent-fixable error"
    assert r.breaker["systems"]["elastic"]["failures"] == 1


@pytest.mark.parametrize("empty", [{}, []])
def test_empty_verb_return_is_payload_status_empty(tmp_path, empty):
    """empty_verb_return_is_payload_status_empty — a verb returning {} or [] yields
    payload_status='empty': the seam tests the RETURNED OBJECT for emptiness BEFORE serializing,
    because json.dumps({}) == '{}' is non-blank and would read as 'ok' — silently killing the
    zero-results signal the lead-author treats as a strong fold signal."""
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

    # The env a verb is HANDED only matters if the transport actually hands it on: a
    # subprocess forked with no env= inherits the driver's os.environ, keys and all.
    naked = [
        f"{path.name}:{call.lineno}"
        for path, tree in _adapter_sources()
        for call in _subprocess_calls(tree)
        if _kw(call, "env") is None
    ]
    assert naked == [], f"a transport forks a child with the INHERITED environment: {naked}"


def test_provider_key_scrub_positive_control(tmp_path):
    """provider_key_scrub_positive_control — the same transport child DOES receive the non-secret
    env it needs (DEFENDER_DIR, PATH): the control proving the scrub is selective and the
    observation channel sees a populated env."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=elastic_ok(rec), turns=[
        q("elastic", "query", {"native_query": "x"}), DONE,
    ])
    env = rec.only().ctx.env
    assert env.get("DEFENDER_DIR") == str(DEFENDER)
    assert env.get("DEFENDER_RUN_DIR") == str(r.run_dir)
    assert env.get("PATH"), "the transport child got no PATH — the scrub emptied the env"


def test_verb_resolves_config_from_deps_tree(tmp_path):
    """verb_resolves_config_from_deps_tree — a verb resolves its config from the RUN's tree
    (deps), not an import-time module constant: a run against a worktree or an eval tmp tree
    reads THAT tree's knowledge/environment/systems/{system}/config.env."""
    def _tree(root: Path, url: str) -> Path:
        d = root / "knowledge" / "environment" / "systems" / "elastic"
        d.mkdir(parents=True)
        (d / "config.env").write_text(
            f"ELASTIC_URL_BASE={url}\nELASTIC_BASTION_HOST=bastion\nELASTIC_TIMEOUT_SEC=30\n",
            encoding="utf-8",
        )
        return root

    a = _tree(tmp_path / "a", "http://tree-a:9200")
    b = _tree(tmp_path / "b", "http://tree-b:9200")

    cfg_a = _stub_transport.load_config(
        VerbContext(defender_dir=a, run_dir=tmp_path / "run", env={}), "elastic", "ELASTIC")
    cfg_b = _stub_transport.load_config(
        VerbContext(defender_dir=b, run_dir=tmp_path / "run", env={}), "elastic", "ELASTIC")

    assert cfg_a["URL_BASE"] == "http://tree-a:9200"
    assert cfg_b["URL_BASE"] == "http://tree-b:9200", \
        "the second tree's verb read the first tree's config (an import-time DEFENDER_DIR)"

    # And the absent config is a ConfigFault (infra), never a process exit.
    with pytest.raises(ConfigFault):
        _stub_transport.load_config(
            VerbContext(defender_dir=tmp_path / "nowhere", run_dir=tmp_path / "run", env={}),
            "elastic", "ELASTIC",
        )


# ═════════════════════════════════════════════════════════════════════════════
# The frozen row contract
# ═════════════════════════════════════════════════════════════════════════════

ROW_KEYS = {
    "lead_id", "seq", "system", "verb", "query_id", "params", "raw_command",
    "payload_path", "exit_code", "error_class", "payload_status", "payload_digest",
}


def test_row_contract_frozen(tmp_path):
    """row_contract_frozen — the twelve-key queries row: params keyed by the REGISTRY's real param
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

    # raw_command is a DERIVED audit string over the same three facts — never a shell command
    # the agent typed (there is no argv any more).
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
    SECOND writer of both sinks (driven by core/persist and evals/_pipeline), still round-trips a
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
    # The join surface reads the staged copy exactly as it reads the live run dir.
    staged = lead_repository.joined(dst)
    assert [lead.lead_id for lead in staged] == [LEAD]
    assert len(staged[0].queries) == 2


# ═════════════════════════════════════════════════════════════════════════════
# The bash lane loses the adapter route
# ═════════════════════════════════════════════════════════════════════════════


def _policies(tmp_path):
    run_dir = tmp_path / "run"
    (run_dir / "gather_raw" / LEAD).mkdir(parents=True)
    (run_dir / "gather_raw" / LEAD / "0.json").write_text("[]", encoding="utf-8")
    gather = compile_policy_for(GATHER_DEF, run_dir=run_dir, defender_dir=DEFENDER)
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
    # The capability WAS the grant: no grant may carry an adapter route any more.
    assert all(g.route is Route.PLAIN for g in gather.bash_allow)
    # …and the decision no longer carries the routing fields the capture layer read.
    assert not hasattr(decision, "adapter_argv")
    assert not hasattr(decision, "sql_pipe")


def test_deny_reason_names_no_deleted_route(tmp_path):
    """deny_reason_names_no_deleted_route — the deny reason an adapter-shaped command receives
    points at the QUERY TOOL and does not tell gather it 'may only run a data-source adapter
    standalone'. A reason naming a route that no longer exists teaches a dead command, which this
    codebase treats as an enforced invariant, not a cosmetic string."""
    run_dir, gather, _ = _policies(tmp_path)
    for cmd in ("defender-elastic query foo",
                f"cat gather_raw/{LEAD}/0.json | defender-sql 'SELECT 1'"):
        reason = _decide(cmd, gather, run_dir).reason
        assert "standalone" not in reason.lower(), f"the deny reason teaches a dead route: {reason}"
        assert "query" in reason.lower(), f"the deny reason does not name the query tool: {reason}"


def test_gather_bash_keeps_local_computation(tmp_path):
    """gather_bash_keeps_local_computation — `cat <ABSOLUTE gather_raw payload> | defender-sql
    '<SQL>'` is still ALLOW for gather, so the split pipe (tool-then-bash) works. The RELATIVE
    spelling still denies — which is why the payload note must stay ABSOLUTE."""
    run_dir, gather, _ = _policies(tmp_path)
    payload = run_dir / "gather_raw" / LEAD / "0.json"
    assert _decide(f"cat {payload} | defender-sql 'SELECT count(*) FROM data'",
                   gather, run_dir).allow
    assert not _decide(f"cat gather_raw/{LEAD}/0.json | defender-sql 'SELECT 1'",
                       gather, run_dir).allow


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


def test_shim_flags_and_non_adapter_shims_are_removed_together():
    """shim_flags_and_non_adapter_shims_are_removed_together — `defender-record-query` leaves
    NON_ADAPTER_SHIMS *and* grant._SHIM_FLAGS together: a shim left in NON_ADAPTER_SHIMS but
    dropped from _SHIM_FLAGS gets a free-text-only shape from _shim_shape, silently WIDENING what
    it may be handed."""
    assert "defender-record-query" not in NON_ADAPTER_SHIMS
    assert "defender-record-query" not in _SHIM_FLAGS
    # The invariant behind the pairing: every surviving shim declares a flag grammar.
    assert set(NON_ADAPTER_SHIMS) <= set(_SHIM_FLAGS), \
        "a shim carries no _SHIM_FLAGS entry — its shape degrades to free text"


# ═════════════════════════════════════════════════════════════════════════════
# Survival
# ═════════════════════════════════════════════════════════════════════════════


def test_record_query_module_survives_its_cli():
    """record_query_module_survives_its_cli — record_query.py survives the deletion of
    main()/parse_params/_derive_verb: runtime/tools.py imports derive_system AND
    _passthrough_max_bytes from it, and the latter is the character cap for the read_file tool —
    unrelated to adapters, and pinned by test_read_file_bounded."""
    assert callable(record_query.derive_system)
    assert callable(record_query._passthrough_max_bytes)
    # The read tool's char cap IS this function (one source, so an on-disk read can never defeat
    # the passthrough cap).
    assert runtime_tools._read_char_cap is record_query._passthrough_max_bytes

    for dead in ("main", "parse_params", "_derive_verb"):
        assert not hasattr(record_query, dead), f"record_query.{dead} outlived its CLI"


def test_ticket_cli_dual_surface_survives():
    """ticket_cli_dual_surface_survives — ticket_cli keeps its argparse CLI over the SAME
    implementation as its VERBS entry: ticket_seeds and verify_forward/forward (both subprocess
    callers) and the benign judge's pinned `--require-closed` bash grant all still work. A
    params-dict cannot express a MANDATORY flag, and that mandate is the judge's entire answer-key
    defense."""
    # 1. The VERBS surface exists.
    verbs = ModuleVerbRegistry(ADAPTERS_DIR).verbs("ticket")
    assert {"list-tickets", "get-ticket"} <= set(verbs)

    # 2. The CLI surface still parses the argvs its three subprocess callers pin.
    parser = ticket_adapter.build_parser()
    assert parser.parse_args(["list-tickets", "--status", "closed"]).status == "closed"
    assert parser.parse_args(["get-ticket", "SOC-1042"]).key == "SOC-1042"
    # …including the judge's MANDATORY closed-only flag, which cannot be a params-dict entry.
    assert parser.parse_args(["get-ticket", "SOC-1042", "--require-closed"]).require_closed is True
    assert parser.parse_args(["list-tickets", "--require-closed"]).require_closed is True


def test_replay_actor_still_loads_the_staged_tables(tmp_path):
    """replay_actor_still_loads_the_staged_tables — learning/ops/replay_actor (which re-execs
    lead_repository + the actor as a subprocess, relocating the tree anchor onto whatever tree it
    lands in) still loads a staged run dir under the new row shape: it requires gather_raw/ OR
    executed_queries.jsonl, and reads params/query_id THROUGH lead_repository, never by
    re-parsing the tables itself."""
    rec = VerbRecorder()
    r = run_gather(tmp_path / "src", verbs=_echo_registry(rec), turns=[
        q("elastic", "probe", {"tag": "alpha"}, query_id="elastic.probe-alpha"), DONE,
    ], run_id="replay-actor")
    staged = tmp_path / "staged"
    lead_repository.stage_tables(r.run_dir, staged)
    (staged / "alert.json").write_text((r.run_dir / "alert.json").read_text(), encoding="utf-8")

    # 1. The precondition replay_actor.main checks before it does anything else.
    paths = RunPaths(staged)
    assert paths.alert.is_file()
    assert paths.gather_raw.is_dir() or paths.executed_queries.is_file()

    # 2. The projection it actually loads — params/query_id under the NEW row shape, read through
    #    lead_repository (the function replay_actor calls by name).
    view = lead_repository.actor_view(staged)
    assert view["leads"] == [{
        "lead_id": LEAD,
        "queries": [{"query_id": "elastic.probe-alpha", "params": {"tag": "alpha"}}],
    }]

    # 3. It reaches the tables ONLY through that surface: a second parser in replay_actor would
    #    have to be migrated in lock-step with the row shape, which is the coupling the single
    #    read/join surface exists to prevent.
    src = (DEFENDER / "learning" / "ops" / "replay_actor.py").read_text(encoding="utf-8")
    assert "executed_queries" not in src.split("def main", 1)[1].replace(
        "staging_paths.executed_queries", ""), "replay_actor re-parses the queries table itself"
    assert "actor_view" in src


def test_e2e_replay_harness_has_an_injected_verb_seam(tmp_path):
    """e2e_replay_harness_has_an_injected_verb_seam — the harness fakes the registry/transport
    through an INJECTED seam (like its make_model seam), not by monkeypatching: its old seam
    stubbed record_query's `subprocess` module attribute, which a registry does not have. The
    exit-2 circuit-breaker fixture still reproduces."""
    assert "verbs" in inspect.signature(drive).parameters
    for gone in ("FakeAdapterSubprocess", "FailingAdapterSubprocess"):
        assert not hasattr(_replay_harness, gone), \
            f"{gone} (the record_query.subprocess monkeypatch seam) is still the harness's fake"

    # The fixture it replaces: an exit-2 (infra) failure trips the per-system breaker.
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=raising(rec, TransportFault("connection refused")), turns=[
        q("elastic", "probe", {}), q("elastic", "probe", {}), DONE,
    ])
    assert [row["exit_code"] for row in r.rows] == [2, 2]
    assert circuit_breaker.is_tripped(r.run_dir, "elastic")
