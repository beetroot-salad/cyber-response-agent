"""#631 — S1/S2: the run's integrity surface, and the two authoring paths that reach `investigation.md` without the gate the constraint lives inside."""
from __future__ import annotations

from dataclasses import replace as _with_live_run_1165
from defender.tests.support.shared.contracts._spec1077 import fixture_run as _live_run_1165

import asyncio
import json
import math
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.models import override_allow_model_requests  # noqa: E402
from pydantic_ai.models.function import FunctionModel  # noqa: E402
from pydantic_ai.usage import UsageLimits  # noqa: E402

from defender._io import read_jsonl_rows  # noqa: E402
from defender.hooks.budget_enforcer import DEFAULT_LIMITS  # noqa: E402
from defender.runtime import driver, observe, permission  # noqa: E402
from defender.runtime.agent_definition import bind, compile_policy_for  # noqa: E402
from defender.runtime.verb_grant import VerbGrant  # noqa: E402
from defender.runtime.verbs import VerbRegistry  # noqa: E402
from defender.runtime.driver import MAIN_DEF  # noqa: E402
from defender.runtime.providers import BuiltModel  # noqa: E402
from defender.skills.invlang.validate import validate_companion  # noqa: E402
from defender.tests.runtime.engine.test_budget_seams_631 import ScriptedModel, drive_agent  # noqa: E402
from defender.tests.support.tenancy import _tenants1106 as T1106

REPO_ROOT = Path(__file__).resolve().parents[4]
DEFENDER = REPO_ROOT / "defender"
GOLDEN = DEFENDER / "tests" / "fixtures" / "e2e" / "golden-v2sshd"
FLAG = "DEFENDER_BUDGET_ENFORCE"

BAD_INVLANG = "```yaml\nfoo: bar\n```\n"

INTEGRITY_SURFACE = (
    "budget.json",
    "circuit_breaker.json",
    "wire_logs/llm_requests.jsonl",
    "tool_trace.jsonl",
    "executed_queries.jsonl",
    "gather_raw/l-001.lead.json",
    "gather_summaries/l-001.md",
    "alert.json",
    "lessons_loaded.jsonl",
)


def _run_dir(tmp_path: Path, name: str = "run") -> Path:
    rd = tmp_path / name
    (rd / "gather_raw").mkdir(parents=True)
    (rd / "gather_summaries").mkdir(parents=True)
    (rd / "alert.json").write_text(json.dumps({"rule": {"name": "probe"}}))
    return rd


def _main_policy(run_dir: Path):
    return compile_policy_for(MAIN_DEF, run_dir, defender_dir=DEFENDER)


def _report_text() -> str:
    return "---\ncase_id: c-1\ndisposition: benign\nconfidence: low\n---\n\nDone.\n"


def test_model_cannot_disable_enforcement(tmp_path):
    """A model that writes to files or runs bash cannot turn the enforcement FLAG off mid-run: the flag is read..."""
    run_dir = _run_dir(tmp_path)
    policy = _main_policy(run_dir)

    benign = permission.decide_bash(f"cat {run_dir / 'alert.json'}", run_dir=run_dir,
                                     defender_dir=DEFENDER, policy=policy)
    assert benign.allow, "the bash gate denies even a benign read — no positive control"

    for command in ("export DEFENDER_BUDGET_ENFORCE=0",
                    "env DEFENDER_BUDGET_ENFORCE=0 true",
                    "DEFENDER_BUDGET_ENFORCE=0 true",
                    "unset DEFENDER_BUDGET_ENFORCE",
                    "bash -c 'export DEFENDER_BUDGET_ENFORCE=0'",
                    "sh -c 'unset DEFENDER_BUDGET_ENFORCE'",
                    "echo DEFENDER_BUDGET_ENFORCE=0 >> ~/.bashrc"):
        decision = permission.decide_bash(command, run_dir=run_dir,
                                          defender_dir=DEFENDER, policy=policy)
        assert not decision.allow, f"the bash lane admitted {command!r}"

    for target in ("../.env", ".env", "/proc/self/environ",
                   str(DEFENDER / "runtime" / "driver.py"),
                   str(DEFENDER / "_env.py")):
        decision = permission.decide_write(Path(run_dir / target), "x", run_dir=run_dir,
                                           defender_dir=DEFENDER, policy=policy)
        assert not decision.allow, f"the api lane admitted a write to {target!r}"

    before = os.environ.get(FLAG)
    subprocess.run(
        [sys.executable, "-c",
         f"import os; os.environ[{FLAG!r}] = '0'"],
        env={**os.environ, FLAG: "1"}, check=True,
    )
    assert os.environ.get(FLAG) == before, "a child process mutated the parent's flag"


def test_model_cannot_author_its_own_budget_state(tmp_path):
    """MAIN cannot author or edit the record its own enforcement decision reads: a write_file or edit_file call..."""
    run_dir = _run_dir(tmp_path)
    policy = _main_policy(run_dir)

    for rel in INTEGRITY_SURFACE:
        target = run_dir / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        decision = permission.decide_write(target, '{"tool_calls": 0}',
                                           run_dir=run_dir, defender_dir=DEFENDER,
                                           policy=policy)
        assert not decision.allow, f"MAIN may still author {rel}"
        assert decision.reason, f"{rel} was refused with no reason the model can read"

    for command in ("cat /dev/null > budget.json", "echo '{}' > budget.json",
                    "jq -n '{}' > budget.json"):
        assert not permission.decide_bash(command, run_dir=run_dir,
                                          defender_dir=DEFENDER, policy=policy).allow

    assert MAIN_DEF.tools.write is False, (
        "MAIN holds a path-taking writer again — budget.json is nameable from the model"
    )
    assert MAIN_DEF.tools.append is True


def test_report_write_is_refused_and_investigation_write_still_succeeds(tmp_path):
    """#774/R1 UPDATE. `report.md` left MAIN's write allow-list entirely (the close tool is now its only writer),..."""
    run_dir = _run_dir(tmp_path)
    policy = _main_policy(run_dir)

    inv_text = (GOLDEN / "investigation.md").read_text()
    decision = permission.decide_write(run_dir / "investigation.md", inv_text, run_dir=run_dir,
                                       defender_dir=DEFENDER, policy=policy)
    assert decision.allow, f"investigation.md was refused: {decision.reason}"
    decision = permission.decide_write(run_dir / "report.md", _report_text(), run_dir=run_dir,
                                       defender_dir=DEFENDER, policy=policy)
    assert not decision.allow, "report.md is no longer model-writable after R1"

    from defender.runtime.run_state import RunState

    drive_agent(MAIN_DEF, run_dir,
                [[("append_block", {"text": inv_text})]],
                limits=DEFAULT_LIMITS, enforce=True, state=RunState(run_dir, "r"))
    assert (run_dir / "investigation.md").read_text() == inv_text
    assert not (run_dir / "report.md").exists(), "report.md must not commit from the main loop"


def test_main_write_scope_is_an_explicit_allow_list(tmp_path):
    """MAIN's compiled write scope is a POSITIVE ALLOW-LIST of exactly investigation.md (#774/R1 narrowed this..."""
    run_dir = _run_dir(tmp_path)
    policy = _main_policy(run_dir)
    admitted = set()
    for rel in ("investigation.md", "report.md",
                *INTEGRITY_SURFACE,
                "gather_raw/evil.md", "notes.md", "a/b/c/deep.md",
                "anything/at/all/x.bin", "report.md.bak",
                "sub/report.md", "gather_raw/investigation.md"):
        target = run_dir / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if rel.endswith("investigation.md"):
            text = (GOLDEN / "investigation.md").read_text()
        elif rel.endswith("report.md"):
            text = "---\ndisposition: benign\n---\nok\n"
        else:
            text = "x\n"
        if permission.decide_write(target, text, run_dir=run_dir,
                                   defender_dir=DEFENDER, policy=policy).allow:
            admitted.add(rel)
    assert admitted == {"investigation.md"}, (
        f"the write scope is not the positive allow-list: {sorted(admitted)}"
    )


def test_a_write_through_an_alias_to_investigation_md_is_still_validated(tmp_path):
    """The invlang validator is selected on the RESOLVED path, so a write through an alias that resolves to..."""
    run_dir = _run_dir(tmp_path)
    policy = _main_policy(run_dir)
    real = run_dir / "investigation.md"
    real.write_text("")
    alias = run_dir / "alias.md"
    alias.symlink_to(real)

    direct = permission.decide_write(real, BAD_INVLANG, run_dir=run_dir,
                                     defender_dir=DEFENDER, policy=policy)
    through_alias = permission.decide_write(alias, BAD_INVLANG, run_dir=run_dir,
                                            defender_dir=DEFENDER, policy=policy)
    assert not direct.allow
    assert "invlang validation" in direct.reason
    assert not through_alias.allow, "the alias bypassed the invlang validator"
    assert "invlang validation" in through_alias.reason

    good = (GOLDEN / "investigation.md").read_text()
    assert validate_companion(good, None) == []
    valid_alias = permission.decide_write(alias, good, run_dir=run_dir,
                                          defender_dir=DEFENDER, policy=policy)
    assert valid_alias.allow, (
        "valid invlang through an alias was refused — the gate denies all aliases rather "
        "than validating on the resolved path"
    )


def _drive_one_query(run_dir: Path, params: dict) -> list[dict]:
    """Drive ONE real `query` call on a real GATHER agent against an injected verb registry — the tool boundary..."""
    class Verbs(VerbRegistry):
        def __init__(self):
            super().__init__(VerbGrant(role="gather", entries=(("elastic", "esql", "r"),)))

        def systems(self):
            return ("elastic",)

        def verbs(self, system):
            def esql(ctx, **kwargs) -> dict:
                return {"rows": [], "echo": kwargs}
            return {"esql": esql}

    model = ScriptedModel([[("query", {"system": "elastic", "verb": "esql",
                                       "params": params,
                                       "query_id": "elastic.probe"})]])
    logger = observe.RequestLogger(run_dir / "llm_requests.jsonl")
    gather_def = T1106.fixture_gather_def()
    agent = driver.build_agent_core(
        gather_def, deps_type=gather_def.deps_cls, instructions="probe",
        logger=logger, agent_id="gather:l-001",
        make_model=lambda n, e: BuiltModel(FunctionModel(model), None),
        verbs=Verbs(), limits=DEFAULT_LIMITS,
    )
    # #1235 round 2: the query tool's writer and guards read the run's `RunState` its deps
    # carry; this agent is driven outside a run, so it carries the state a started run would.
    from defender.runtime.run_state import RunState

    deps = replace(_with_live_run_1165(bind(gather_def, run_dir, defender_dir=DEFENDER), run=_live_run_1165(run_dir)),
                   lead_id="l-001", run_state=RunState(run_dir, "r"))

    async def _go():
        with override_allow_model_requests(False):
            return await agent.run("go", deps=deps,
                                   usage_limits=UsageLimits(request_limit=3))
    try:
        asyncio.run(_go())
    finally:
        logger.close()
    return list(read_jsonl_rows(run_dir / "executed_queries.jsonl"))


def test_a_query_row_carrying_a_non_finite_param_is_still_strict_json(tmp_path):
    """A query call whose params carry a non-finite value appends a row every line of which parses under a STRICT..."""
    run_dir = _run_dir(tmp_path)
    _drive_one_query(run_dir, {"threshold": 1e400, "count": 42.5, "index": "logs"})

    table = run_dir / "executed_queries.jsonl"
    lines = [ln for ln in table.read_text().splitlines() if ln.strip()]
    assert lines, "the query wrote no row at all"

    def _reject(token):
        raise AssertionError(f"non-standard JSON token {token!r} reached the queries table")

    for line in lines:
        json.loads(line, parse_constant=_reject)

    row = json.loads(lines[0])
    for value in row["params"].values():
        assert not (isinstance(value, float) and not math.isfinite(value))
    assert row["params"].get("count") == 42.5, (
        "a legitimate finite float was mangled — the non-finite fix is a blanket sanitizer"
    )
    assert row["params"].get("index") == "logs", "an ordinary string param was lost"


def test_hostile_string_params_still_produce_exactly_one_row(tmp_path):
    """Ordinary params round-trip byte-identical, and the sharp string cases — an embedded newline and U+2028 —..."""
    hostile = {
        "index": "logs-*",
        "newline": 'a\nb',
        "crlf": 'a\r\nb',
        "line_sep": "a\u2028b",
        "para_sep": "a\u2029b",
        "nel": "a\u0085b",
        "forged": '{"lead_id": "l-999", "seq": 0}',
        "quotes": 'he said \\"hi\\" \\\\ done',
    }
    run_dir = _run_dir(tmp_path)
    rows = _drive_one_query(run_dir, hostile)

    raw = (run_dir / "executed_queries.jsonl").read_text()
    assert raw.count("\n") == 1, f"one call produced {raw.count(chr(10))} physical lines"
    assert len(raw.splitlines()) == 1
    assert len(rows) == 1
    assert rows[0]["params"] == hostile, "a legitimate param was mangled by a sanitizer"
    assert rows[0]["lead_id"] == "l-001", "the forged row displaced the genuine one"
