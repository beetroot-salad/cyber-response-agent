"""#872 — the return contract at the seam: what each branch hands the model.

#872 — the ruler and the bar: delivered UTF-8 bytes, measured with the wire serializer.

#872 — the gate's seam, its reach (whole runs, the query path, a re-executed `run.py`
child), and provenance: owned tools are not gated, foreign ones are.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

pytest.importorskip('pydantic_ai')
from pydantic_ai.messages import ToolReturn  # noqa: E402
from pydantic_ai.toolsets import FunctionToolset  # noqa: E402

from defender.investigation.toon_gate import GATE_METADATA_KEY  # noqa: E402
from defender.tests.e2e._toon872 import (  # noqa: E402
    agent_run,
    corpus,
    delivered_percent,
    foreign_toolset,
    framed_content,
    toon_rows,
    wire_roundtrip_equal,
    wire_text,
)
from defender.tests.e2e._toon872 import (  # noqa: E402
    agent_run,
    corpus,
    delivered_percent,
    foreign_toolset,
    frame_overhead,
    framed_content,
    toon_bytes,
    toon_rows,
    wire_bytes,
    wire_text,
)
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
from defender.tests.e2e.test_query_tool import DONE, elastic_ok, q  # noqa: E402


toons = pytest.importorskip("toons")  # noqa: E402


pytestmark = pytest.mark.e2e


FIXTURE = "fx-33"


def _under_bar() -> dict:
    value = toon_rows(corpus()[FIXTURE])
    assert delivered_percent(value) < 80.0, (
        "the substitution fixture no longer clears the delivered-bytes bar"
    )
    return value


def test_substitute_branch_return_shape() -> None:
    """The substitute branch returns `ToolReturn(return_value=<framed TOON>,
    metadata={"json": <the tool's own return>})`."""
    value = _under_bar()
    out = agent_run(toolset=foreign_toolset(value))
    part = out.dispatched.part("fetch_rows")

    assert GATE_METADATA_KEY == "json", "the gate's metadata key is no longer `json`"
    assert framed_content(part.content) == toons.dumps(value), (
        "the model was handed something other than the framed TOON view"
    )
    assert isinstance(part.metadata, dict)
    assert GATE_METADATA_KEY in part.metadata
    assert part.metadata[GATE_METADATA_KEY] == value


def test_the_byte_gate_and_the_stringify_step_measure_the_bytes_the_model_receives() -> None:
    for value in ({"x": float("nan")}, {"x": b"ab"}, [], {"x": float("-inf")}):
        out = agent_run(toolset=foreign_toolset(value))
        assert framed_content(out.dispatched.text()) == wire_text(value), (
            f"the gate measured {value!r} with the wrong serializer"
        )

    oracle = {"rows": [{"a": float("nan"), "b": i} for i in range(40)]}
    assert wire_roundtrip_equal(oracle), (
        "the wire serializer no longer renders both sides of this round trip identically"
    )
    assert delivered_percent(oracle) <= 85, (
        "the oracle fixture no longer clears the delivered-bytes bar"
    )
    out = agent_run(toolset=foreign_toolset(oracle))
    assert framed_content(out.dispatched.text()) == toons.dumps(oracle), (
        "a payload the round-trip oracle accepts under the wire serializer passed through"
    )


def test_a_tool_body_that_returns_its_own_toolreturn_is_unwrapped_framed_and_loses_nothing() -> None:
    value = {"rows": [{"a": i, "b": f"row-{i}"} for i in range(40)]}
    ts = FunctionToolset()

    def fetch_rows() -> ToolReturn:
        return ToolReturn(return_value=value, metadata={"body_private": "kept"})

    ts.tool_plain(fetch_rows)
    part = agent_run(toolset=ts).dispatched.part("fetch_rows")

    assert isinstance(part.content, str), "the ToolReturn dataclass reached the model"
    assert "body_private" not in part.content, "the tool body's private metadata leaked to the model"
    assert "tool-return" not in part.content
    assert "return_value" not in part.content
    assert framed_content(part.content) == toons.dumps(value), (
        "a pre-wrapped ToolReturn opted out of the gate"
    )
    assert part.metadata["body_private"] == "kept", "the gate destroyed application data"
    assert part.metadata[GATE_METADATA_KEY] == value

    collide = FunctionToolset()

    def fetch_rows_collide() -> ToolReturn:
        return ToolReturn(return_value=value, metadata={GATE_METADATA_KEY: "the body's own"})

    fetch_rows_collide.__name__ = "fetch_rows"
    collide.tool_plain(fetch_rows_collide)
    hit = agent_run(toolset=collide).dispatched.part("fetch_rows")
    reachable = _flatten(hit.metadata)
    assert "the body's own" in reachable, "the gate overwrote the body's value on the reserved key"
    assert value in reachable, "the body overwrote the gate's original JSON on the reserved key"


def _flatten(meta: dict) -> list:
    """Every value reachable in a metadata mapping, so the test fixes no merge order."""
    out: list = []
    for v in meta.values():
        out.append(v)
        if isinstance(v, dict):
            out.extend(_flatten(v))
    return out


MAX_PERCENT_ENV = "DEFENDER_TOON_GATE_MAX_PERCENT"


def _pick(bar: int, *, clearing: bool):
    """A committed fixture arm on the requested side of a CONFIGURED bar."""
    for name, columnar in sorted(corpus().items()):
        for arm, value in (("dict-rows", toon_rows(columnar)), ("columnar", columnar)):
            if (delivered_percent(value) <= bar) is clearing:
                return f"{name}/{arm}", value
    raise AssertionError(f"no committed fixture is {'under' if clearing else 'over'} bar {bar}")


def test_a_fixture_whose_verdict_differs_between_rulers_takes_the_wire_rulers_verdict() -> None:
    overhead = frame_overhead()

    def _verdict(value, denominator: int, bar: int) -> bool:
        """The gate's comparison, delivered bytes on both sides, so only the serializer of the
        JSON side varies between the two rulers."""
        return 100 * (toon_bytes(value) + overhead) <= bar * (denominator + overhead)

    for bar in (85, 90):
        discriminators = [
            (f"{name}/{arm}", value)
            for name, columnar in sorted(corpus().items())
            for arm, value in (("dict-rows", toon_rows(columnar)), ("columnar", columnar))
            if _verdict(value, len(json.dumps(value).encode()), bar)
            != _verdict(value, wire_bytes(value), bar)
        ]
        assert discriminators, f"no committed arm discriminates the two rulers at bar {bar}"
        label, value = discriminators[0]
        out = agent_run(toolset=foreign_toolset(value), env={MAX_PERCENT_ENV: str(bar)})
        substituted = framed_content(out.dispatched.text()) != wire_text(value)
        assert substituted == _verdict(value, wire_bytes(value), bar), (
            f"{label} took the json.dumps ruler's verdict at bar {bar}"
        )


def test_a_cjk_payload_is_measured_in_bytes_not_characters() -> None:
    bar = 85
    overhead = frame_overhead()

    def _straddles(value) -> tuple[bool, bool]:
        view, wire = toons.dumps(value), wire_text(value)
        by_bytes = 100 * (len(view.encode()) + overhead) <= bar * (len(wire.encode()) + overhead)
        by_chars = 100 * (len(view) + overhead) <= bar * (len(wire) + overhead)
        return by_bytes, by_chars

    candidates = [
        {"rows": [{"件": "あ" * width, "詳": "説明", "備": "補"} for _ in range(rows)]}
        for rows in range(1, 13)
        for width in range(1, 40)
    ]
    straddling = [v for v in candidates if _straddles(v)[0] != _straddles(v)[1]]
    assert straddling, (
        "no CJK payload in the searched family straddles the bar on the DELIVERED ratio any "
        "more, so a len(str) implementation would pass this test"
    )
    value = straddling[len(straddling) // 2]
    by_bytes, by_chars = _straddles(value)

    out = agent_run(toolset=foreign_toolset(value), env={MAX_PERCENT_ENV: str(bar)})
    substituted = framed_content(out.dispatched.text()) != wire_text(value)
    assert substituted == by_bytes, (
        f"the CJK payload was measured in characters (verdict {by_chars}), not in UTF-8 bytes"
    )


def test_a_payload_just_under_the_configured_bar_substitutes_and_one_just_over_it_passes_through() -> None:
    """Checked at two configured bars and on both sides of one fixture's ratio, so no constant
    is asserted; a substituted view decodes back to the payload."""
    for bar in (85, 90):
        env = {MAX_PERCENT_ENV: str(bar)}
        under_label, under = _pick(bar, clearing=True)
        over_label, over = _pick(bar, clearing=False)

        subbed = agent_run(toolset=foreign_toolset(under), env=env)
        view = framed_content(subbed.dispatched.text())
        assert view == toons.dumps(under), f"{under_label} did not substitute at bar {bar}"
        assert toons.loads(view) == under

        passed = agent_run(toolset=foreign_toolset(over), env=env)
        assert framed_content(passed.dispatched.text()) == wire_text(over), (
            f"{over_label} substituted at bar {bar}"
        )

    import math
    _, value = _pick(85, clearing=True)
    ratio = delivered_percent(value)
    low, high = math.floor(ratio), math.ceil(ratio)
    assert low != high, "the boundary fixture's ratio is exactly integral; pick another arm"
    passed = agent_run(toolset=foreign_toolset(value), env={MAX_PERCENT_ENV: str(low)})
    assert framed_content(passed.dispatched.text()) == wire_text(value), (
        f"a payload at {ratio:.2f}% substituted at a configured bar of {low}"
    )
    subbed = agent_run(toolset=foreign_toolset(value), env={MAX_PERCENT_ENV: str(high)})
    assert framed_content(subbed.dispatched.text()) == toons.dumps(value), (
        f"a payload at {ratio:.2f}% passed through at a configured bar of {high}"
    )


def _payload() -> dict:
    return toon_rows(corpus()["fx-33"])


def _desalt(text: str) -> str:
    """One frame's salt replaced by a fixed marker, so two RUNS' texts can be compared."""
    return re.sub(r"run-[0-9a-f]{16}-", "run-<salt>-", text)


def _gather_turn() -> Turn:
    return Turn(tool_calls=[("gather", {
        "lead_id": "l-001", "system": "elastic", "goal": "measure this lead",
        "what_to_summarize": ["auth events"],
    })])


def test_a_foreign_toolset_injected_at_the_entry_point_reaches_the_model_through_the_gate(
    tmp_path: Path,
) -> None:
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
    from defender._io import read_jsonl_rows
    from defender.records import RunPaths

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
    def _comparable(text: str, run_dir: Path) -> str:
        # Salt and run dir both differ between the two runs (`query` echoes its `gather_raw`
        # path back in its tool text).
        # The arrival-stamp line is the platform's own clock (#1385 A6): it differs too.
        return re.sub(r"^\[reply received [^\]\n]*\]\n?", "", _desalt(text).replace(
            str(run_dir), "<run-dir>"), flags=re.M)

    assert _comparable(live_gather.dispatched.text("query"), live_dir) == _comparable(
        idle_gather.dispatched.text("query"), idle_dir), (
        "the query tool's model-visible text changed in the run where the gate was active"
    )
    assert re.search(r"<run-[0-9a-f]+-untrusted>", live_gather.dispatched.text("query")), (
        "query's own rendering lost its frame, so the comparison above is over empty text"
    )
    def _sans_arrival(run_dir: Path) -> list[dict]:
        return [{k: v for k, v in row.items() if k != "received_at"}
                for row in read_jsonl_rows(RunPaths(run_dir).executed_queries)]

    assert _sans_arrival(live_dir) == _sans_arrival(idle_dir), (
        "the queries table diverged between the two runs")
    assert framed_content(live_main.dispatched.text("fetch_rows")) == toons.dumps(
        _payload()), "no foreign substitution happened, so the inertness above proves nothing"


def test_an_owned_agent_tool_result_is_untouched_while_a_foreign_one_is_gated() -> None:
    """An unlabelled (hence foreign) toolset is gated; an owned-labelled one of the same name
    and an owned `@agent.tool` in the same run are not."""
    value = _payload()

    # THE SAME-NAME DISCRIMINATOR, at the finest grain the library allows.
    foreign = agent_run(toolset=foreign_toolset(value, name="fetch_rows"))
    owned = agent_run(toolset=owned_toolset(value, name="fetch_rows"))
    assert framed_content(foreign.dispatched.text("fetch_rows")) == toons.dumps(value), (
        "the unlabelled `fetch_rows` was not gated: an unlabelled toolset defaulted to owned"
    )
    assert owned.encoder.dumps_calls == 0, "an owned-labelled toolset reached the encoder"
    assert owned.dispatched.text("fetch_rows") == wire_text(value), (
        "the owned `fetch_rows` was gated too, so the verdict depends on the tool's name"
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
        "the gate changed an owned tool's model-visible text"
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
