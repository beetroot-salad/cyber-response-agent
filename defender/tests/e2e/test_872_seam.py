"""#872 — O7/M6's seam, the gate's reach, and provenance
(`d19`, `d20`, `d21`, `d22`, `d23`, `d35`, `d40`, `d44`, `d59`, `d74`, `d75`)."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

# `toons` ships in the `runtime` EXTRA, so an install without it is a supported one —
# and a bare module-scope import there is a COLLECTION error, which pytest answers by
# interrupting the whole session. Guarded like `pydantic_ai` above it.
toons = pytest.importorskip("toons")  # noqa: E402


from defender.tests.e2e._replay_harness import (  # noqa: E402
    GOLDEN_AB3,
    Turn,
    VerbRecorder,
    drive,
    materialize,
)
from defender.tests.e2e._toon872 import (  # noqa: E402
    REPO_ROOT,
    RUN_ID,
    PartRecorder,
    agent_run,
    corpus,
    foreign_toolset,
    framed_content,
    owned_toolset,
    run_isolated,
    toon_rows,
    wire_text,
)
from defender.tests.e2e.test_query_tool_611 import DONE, elastic_ok, q  # noqa: E402

pytestmark = pytest.mark.e2e


def _payload() -> dict:
    return toon_rows(corpus()["fx-33"])


def _desalt(text: str) -> str:
    """One frame's salt replaced by a fixed marker, so two RUNS' texts can be compared."""
    return re.sub(r"run-[0-9a-f]{16}-", "run-<salt>-", text)


def _gather_turn(lead: str = "l-001") -> Turn:
    return Turn(tool_calls=[("gather", {
        "lead_id": lead, "system": "elastic", "goal": "measure this lead",
        "what_to_summarize": ["auth events"],
    })])


def test_a_foreign_toolset_injected_at_the_entry_point_reaches_the_model_through_the_gate(
    tmp_path: Path,
) -> None:
    """A foreign dict-returning toolset installed through the declared seam at
    `run_investigation` is offered to the model, called, and its result reaches the model as
    the framed TOON view."""
    value = _payload()
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id=RUN_ID)
    main = PartRecorder([Turn(tool_calls=[("fetch_rows", {})]), Turn(text="Complete.")])
    drive(run_dir, run_id=RUN_ID, main=main, toolset=foreign_toolset(value))

    view = main.dispatched.text("fetch_rows")
    assert framed_content(view) == toons.dumps(value), (
        "the foreign result did not reach the model as the framed TOON view"
    )


def test_the_query_tool_path_is_byte_identical_with_the_gate_installed(
    tmp_path: Path,
) -> None:
    """With the gate installed the model still sees `QueryCapture`'s rendered salt-wrapped
    string for `query`, the executed-queries row is still appended — and a foreign dict in the
    SAME run is substituted."""
    from defender._io import read_jsonl_rows
    from defender.run_repository import RunPaths

    def _run(root: Path, toolset):
        run_dir = materialize(root, GOLDEN_AB3, run_id=RUN_ID)
        rec = VerbRecorder()
        main = PartRecorder([
            _gather_turn(),
            *([Turn(tool_calls=[("fetch_rows", {})])] if toolset is not None else []),
            Turn(text="Complete."),
        ])
        gather = PartRecorder([q("elastic", "query", {"native_query": "FROM logs"}), DONE])
        drive(run_dir, run_id=RUN_ID, main=main, gather=gather,
              verbs=elastic_ok(rec), toolset=toolset)
        return run_dir, main, gather

    idle_dir, _, idle_gather = _run(tmp_path / "idle", None)
    live_dir, live_main, live_gather = _run(tmp_path / "live", foreign_toolset(_payload()))

    assert read_jsonl_rows(RunPaths(live_dir).executed_queries), (
        "no executed-queries row was written, so the query path did not run"
    )
    # COMPARED WITH THE SALT NORMALIZED, because #875 mints a fresh one per frame: `query`
    # renders its own payload through `wrap_fresh`, so the two runs' delimiters differ by
    # construction and a raw text comparison asserts only that two CSPRNG draws collided. Every
    # other byte — the payload, the frame's shape, its position in the surrounding tool text —
    # is still compared, and the frame's presence is asserted separately below.
    def _comparable(text: str, run_dir: Path) -> str:
        # ...and the run dir normalized with it, for the same reason: the two arms are two
        # RUNS, so `query` echoes each one's own `gather_raw` path back in its tool text.
        return _desalt(text).replace(str(run_dir), "<run-dir>")

    assert _comparable(live_gather.dispatched.text("query"), live_dir) == _comparable(
        idle_gather.dispatched.text("query"), idle_dir), (
        "the query tool's model-visible text changed in the run where the gate was active"
    )
    assert re.search(r"<run-[0-9a-f]+-untrusted>", live_gather.dispatched.text("query")), (
        "query's own rendering lost its frame, so the comparison above is over empty text"
    )
    assert read_jsonl_rows(RunPaths(live_dir).executed_queries) == read_jsonl_rows(
        RunPaths(idle_dir).executed_queries), "the queries table diverged between the two runs"
    assert framed_content(live_main.dispatched.text("fetch_rows")) == toons.dumps(
        _payload()), "no foreign substitution happened, so the inertness above proves nothing"


def test_an_owned_agent_tool_result_is_untouched_while_a_foreign_one_is_gated() -> None:
    """An owned `@agent.tool` result and a foreign toolset's tool OF THE SAME NAME are driven
    in ONE run, and only the foreign one is gated."""
    value = _payload()

    # THE SAME-NAME DISCRIMINATOR, at the finest grain the library allows.
    foreign = agent_run(toolset=foreign_toolset(value, name="fetch_rows"))
    owned = agent_run(toolset=owned_toolset(value, name="fetch_rows"))
    assert framed_content(foreign.dispatched.text("fetch_rows")) == toons.dumps(value), (
        "the foreign `fetch_rows` was not gated"
    )
    assert owned.dispatched.text("fetch_rows") == wire_text(value), (
        "the OWNED `fetch_rows` — same name, same payload — was gated too, so the verdict is a "
        "function of the tool's name and a same-named foreign tool would walk through a name list"
    )

    # THE ONE-RUN ARM, at the two names one agent can carry.
    def own_rows() -> dict:
        return value

    out = agent_run(
        toolset=foreign_toolset(value, name="fetch_rows"),
        own_tool=own_rows,
        calls=[("fetch_rows", {}), ("own_rows", {})],
    )
    foreign_text = out.dispatched.text("fetch_rows")
    owned_text = out.dispatched.text("own_rows")

    assert framed_content(foreign_text) == toons.dumps(value), (
        "the foreign result was not gated"
    )
    assert owned_text == wire_text(value), (
        "an owned tool's model-visible text was changed by the gate — exactly what O2 forbids"
    )


def test_an_unlabelled_toolset_is_treated_as_foreign_and_only_the_composition_root_marks_owned() -> None:
    """An UNLABELLED toolset is treated as foreign — gated and framed — and a toolset carrying
    defender's owned label is not."""
    value = _payload()
    unlabelled = agent_run(toolset=foreign_toolset(value, name="fetch_rows"))
    assert framed_content(unlabelled.dispatched.text()) == toons.dumps(value), (
        "an unlabelled toolset defaulted to owned — the unsafe direction"
    )

    labelled = agent_run(toolset=owned_toolset(value, name="fetch_rows"))
    assert labelled.encoder.dumps_calls == 0, "an owned-labelled toolset reached the encoder"
    assert labelled.dispatched.text() == wire_text(value), (
        "an owned-labelled result was gated or framed"
    )


def test_the_golden_case_generators_subprocess_child_carries_the_gate() -> None:
    """A re-executed `run.py` child reaches `build_agent_core`, so the gate is on that path
    unconditionally."""
    child = '''
import json, os, sys

# `run.py:39-40`'s own move, reproduced: the re-executed child puts the real repo root on
# sys.path ITSELF, which is why the reach does not depend on the ambient environment. The
# inherited PYTHONPATH is deleted first, so anything that resolves below resolves the way the
# re-executed child resolves it and not the way this test process was launched.
os.environ.pop("PYTHONPATH", None)
for name in [m for m in sys.modules if m == "defender" or m.startswith("defender.")]:
    del sys.modules[name]
sys.path.insert(0, RUN_PY_ROOT)

from defender.tests.e2e import _toon872 as T
import toons

value = T.toon_rows(T.corpus()["fx-33"])
out = T.agent_run(toolset=T.foreign_toolset(value))
print(json.dumps({
    "gated": T.framed_content(out.dispatched.text()) == toons.dumps(value),
    "encoded": out.encoder.dumps_calls,
}))
'''
    outcome = run_isolated(child.replace("RUN_PY_ROOT", repr(str(REPO_ROOT))),
                           timeout=120.0, pythonpath=False)
    assert outcome.returncode == 0, (
        f"the re-executed child did not reach the gate's install site: {outcome.stderr[-800:]}"
    )
    result = json.loads(outcome.stdout.strip().splitlines()[-1])
    not_on_path = ("a re-executed run.py child builds an agent the gate is not on, so any "
                   "behavior change this gate makes would not land in its runs")
    assert result["encoded"] == 1, not_on_path
    assert result["gated"] is True, not_on_path
