"""Drive model-path rendering, evidence preservation, operand refusal, and corpus isolation."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import json
import re
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender._io import read_jsonl_rows  # noqa: E402
from defender.records import RUN_LAYOUT  # noqa: E402
from defender import box as box_mod  # noqa: E402
from defender.box import BoxSpec  # noqa: E402
from defender.tests.support.runtime.state import _1255_view as V
from defender.tests.support.shared.contracts._fold_936 import (  # noqa: E402
    CLASS_LESSON,
    CLASS_SELECTOR,
    CLOSED_LOOP,
    OPEN_CLASS_BLOCK,
    WRITE_RETURN_HEADER,
)
from defender.tests.support.learning.retrieval._lessons_corpus import _write_lesson  # noqa: E402
from defender.tests.e2e._replay_harness import (  # noqa: E402
    GOLDEN_AB3,
    FakeVerbs,
    Turn,
    drive,
)

pytestmark = pytest.mark.e2e

ALERT = (GOLDEN_AB3 / "alert.json").read_bytes()
RULE_ID = "v2-cross-tier-ssh-pivot"
SPEC = BoxSpec(runtime="runc", rootfs=V.STATIC_ROOTFS)
_SALT = re.compile(r"run-[0-9a-f]{16}-")
LEAD = "l-001"
MODEL_PAYLOAD = f"{V.MODEL_RUN}/{RUN_LAYOUT.gather_raw.name}/{LEAD}/0.json"
FOREIGN_HOST_PATH = "/srv/acme-prod/defender-data/acme/runs/20250101t000000z-old/investigation.md"


def _unboxed(layout: V.Layout, run_dir: Path, monkeypatch) -> object:
    """Start production's explicitly permitted fallback without a Docker daemon."""
    monkeypatch.setenv("DEFENDER_ALLOW_UNSANDBOXED", "1")
    agent, token = layout.staged()
    return box_mod.start_box(run_dir, layout.checkout, spec=SPEC, docker=V.FakeDocker(),
                             tenant_agent=agent, tenant_id=layout.tenant.id, staged_token=token)


def _drive(layout: V.Layout, run_dir: Path, main, monkeypatch, **kw) -> dict:
    return drive(run_dir, run_id=run_dir.name, main=main, tenant=layout.tenant,
                 defender_dir=layout.checkout, box=_unboxed(layout, run_dir, monkeypatch), **kw)


def _value(text: str, label: str) -> str:
    """Extract a coordinate or dispatch field, failing if its label is absent."""
    m = re.search(rf"^{re.escape(label)}: (.*)$", text, re.MULTILINE)
    assert m, f"no `{label}:` line in:\n{text[:2000]}"
    return m.group(1)


def _map_root(text: str, name: str) -> str:
    """The workspace map's `- NAME: `value`` line."""
    m = re.search(rf"^- {re.escape(name)}: `([^`]*)`$", text, re.MULTILINE)
    assert m, f"the workspace map has no {name} root line:\n{text[:3000]}"
    return m.group(1)


def test_b3_message_zero_is_the_same_under_two_host_layouts(tmp_path, monkeypatch):
    a = V.make_layout(tmp_path / "a", V.TENANT_A)
    b = V.make_layout(tmp_path / "b" / "x" / "y", V.TENANT_B,
                      checkout=V.mirror_checkout(tmp_path / "b" / "src" / "co"))
    run_id = "20261015t120000z-view-two"
    seen = []
    for layout in (a, b):
        main = V.Recorder([Turn(text="done")])
        _drive(layout, V.natural_run(layout, ALERT, run_id), main, monkeypatch)
        m0 = main.first_user_text()
        assert RULE_ID in m0, "control: message 0 carries the alert"
        assert _value(m0, "run_dir") == V.MODEL_RUN
        assert _value(m0, "alert") == V.MODEL_ALERT
        assert _map_root(m0, "RUN_DIR") == V.MODEL_RUN
        assert _map_root(m0, "DEFENDER_DIR") == V.MODEL_DEFENDER
        assert f"## Run dir — `{V.MODEL_RUN}`" in m0, "the run-dir listing is not headed by its model path"
        hits = V.scan(m0, V.host_tokens(layout))
        assert not hits, "message 0 shows host layout:\n" + "\n".join(hits)
        seen.append(_SALT.sub("run-<SALT>-", m0))
    ma, mb = seen
    if ma != mb:
        diff = [(x, y) for x, y in zip(ma.splitlines(), mb.splitlines(), strict=False) if x != y]
        raise AssertionError("message 0 depends on the host layout:\n"
                             + "\n".join(f"  A: {x}\n  B: {y}" for x, y in diff[:12]))


HITS_HEADER = "### Hits for that signature"


def test_b6_o3_message_zero_lessons_section_shows_no_host_layout(tmp_path, monkeypatch):
    from defender.investigation import orient

    layout = V.make_layout(tmp_path / "a", V.TENANT_A)
    # #1108 P4 (O1, O4): the corpus the signature lookup reads is the run TENANT's
    # (`agent/lessons/`), never the checkout's; the fixture tenant carries no lesson for this
    # alert's signature, so the scene plants one there (made up; the default signature of
    # `_write_lesson` is this alert's rule id).
    _write_lesson(layout.agent / "lessons", "view-b6-signature-lesson")
    run_dir = V.natural_run(layout, ALERT, "20261015t120000z-view-lessons0")
    main = V.Recorder([Turn(text="done")])
    _drive(layout, run_dir, main, monkeypatch, orient_shim=orient._shim)

    m0 = main.first_user_text()
    assert "## Lessons" in m0, ("control: the signature lookup's hits are not in message 0 — the shims did not run, or "
        "the corpus no longer holds a lesson for this signature")
    assert HITS_HEADER in m0, ("control: the signature lookup's hits are not in message 0 — the shims did not run, or "
        "the corpus no longer holds a lesson for this signature")
    hits = V.scan(m0, V.host_tokens(layout))
    assert not hits, "message 0's lessons section shows host layout:\n" + "\n".join(hits)


def test_b4_an_alert_carrying_a_host_path_is_shown_byte_for_byte(tmp_path, monkeypatch):
    layout = V.make_layout(tmp_path / "a", V.TENANT_A)
    evidence = f"{location_path(layout.data_root)}/{layout.tenant_id}/runs/20250101t000000z-old/investigation.md"
    doc = json.loads(ALERT)
    doc["process_args_evidence"] = f"cat {evidence}"
    run_dir = V.natural_run(layout, json.dumps(doc, indent=2).encode("utf-8"),
                            "20261015t120000z-view-evid")
    main = V.Recorder([
        Turn(tool_calls=[("read_file", {"path": V.MODEL_ALERT})]),
        Turn(text="done"),
    ])
    _drive(layout, run_dir, main, monkeypatch)

    m0 = main.first_user_text()
    assert f"cat {evidence}" in m0, "the alert's own bytes were rewritten in message 0"
    assert V.scan(m0, [str(location_path(layout.data_root))]), "control: the scanner sees the planted path"
    assert _value(m0, "run_dir") == V.MODEL_RUN
    assert not V.scan(m0.replace(evidence, "<EVIDENCE>"), V.host_tokens(layout)), (
        "message 0 shows host layout outside the evidence")
    kind, text = main.answer_to(1)
    assert kind == "return", f"the alert was not read through its model path: {text}"
    assert f"cat {evidence}" in text, "the alert read back with its bytes rewritten"


def _own_tree_evidence(layout: V.Layout, run_dir: Path | str) -> dict[str, str]:
    """Plant evidence paths inside all three host trees to detect accidental rewriting."""
    return {"run folder": f"{run_dir}/{RUN_LAYOUT.investigation}",
            "checkout": f"{layout.checkout}/skills/invlang/SKILL.md",
            "agent half": f"{layout.agent}/examples/{PROBE_NAME}"}


def _outside(text: str, evidence: list[str]) -> str:
    """Mask only exact planted evidence before scanning surrounding host-composed text."""
    for item in sorted(evidence, key=len, reverse=True):
        text = text.replace(item, "<EVIDENCE>")
    return text


def test_b4_evidence_naming_this_runs_own_trees_is_shown_byte_for_byte(tmp_path, monkeypatch):
    layout = V.make_layout(tmp_path / "a", V.TENANT_A)
    # #1279 A3: setup mints the run id, so the evidence naming this run's folder is planted into
    # the alert after the run exists, at the place the view reads the alert from.
    run_dir = V.natural_run(layout, ALERT, "view-evid-own")
    old = f"{location_path(layout.data_root)}/{layout.tenant_id}/runs/20250101t000000z-old/investigation.md"
    own = _own_tree_evidence(layout, run_dir)
    planted = [f"cat {p}" for p in (old, *own.values())]
    doc = json.loads(ALERT)
    for i, line in enumerate(planted):
        doc[f"process_args_evidence_{i}"] = line
    # The run's input is write-once and digest-checked, so the doc is re-admitted through run
    # start's own front door and both files are replaced together (host-side fixture surgery).
    from defender import run_common

    staged = location_path(layout.data_root).parent / "alert-view-evid-own-planted.json"
    staged.write_bytes(json.dumps(doc, indent=2).encode("utf-8"))
    from defender.tenancy import _tenant

    door = run_common._admit_input(staged, settings=_tenant.clone_halves(layout.tenant)[1],
                                   world=None)
    for sealed in (run_dir / RUN_LAYOUT.alert, run_dir / RUN_LAYOUT.alert_record):
        sealed.chmod(0o644)  # setup seals the input read-only; a non-root runner cannot rewrite it
    (run_dir / RUN_LAYOUT.alert).write_bytes(door.raw)
    (run_dir / RUN_LAYOUT.alert_record).write_text(door.record, encoding="utf-8")
    assert run_dir.parent == Path(location_path(layout.tenant.runs)), (
        f"fixture: the run folder is not in the tenant's runs ({run_dir})")
    main = V.Recorder([
        Turn(tool_calls=[("read_file", {"path": V.MODEL_ALERT})]),
        Turn(text="done"),
    ])
    _drive(layout, run_dir, main, monkeypatch)
    tokens = V.host_tokens(layout, extra=[run_dir])

    m0 = main.first_user_text()
    assert RULE_ID in m0, "control: message 0 carries the alert"
    for (name, path), line in zip(own.items(), planted[1:], strict=True):
        assert line in m0, (
            f"the alert's own bytes naming this run's {name} ({path}) were rewritten in "
            "message 0")
    assert planted[0] in m0, "the alert's own bytes naming an older run were rewritten"
    assert _value(m0, "run_dir") == V.MODEL_RUN
    assert _value(m0, "alert") == V.MODEL_ALERT
    assert _map_root(m0, "RUN_DIR") == V.MODEL_RUN
    assert _map_root(m0, "DEFENDER_DIR") == V.MODEL_DEFENDER
    hits = V.scan(_outside(m0, planted), tokens)
    assert not hits, "message 0 shows host layout outside the evidence:\n" + "\n".join(hits)
    kind, text = main.answer_to(1)
    assert kind == "return", f"the alert was not read through its model path: {text[:400]}"
    missing = [line for line in planted if line not in text]
    assert not missing, f"the alert read back with its evidence rewritten: {missing}"
    hits = V.scan(_outside(text, planted), tokens)
    assert not hits, "the alert's read-back shows host layout outside the evidence:\n" + "\n".join(hits)


PROBE_NAME = "view-probe-1255.md"
PROBE_TEXT = "agent-half probe body 1255\n"


def test_b2_file_tools_and_bash_reach_each_tree_by_model_path_and_refuse_host_paths(
    tmp_path, monkeypatch,
):
    layout = V.make_layout(tmp_path / "a", V.TENANT_A)
    probe = layout.agent / "examples" / PROBE_NAME
    probe.parent.mkdir(parents=True)
    probe.write_text(PROBE_TEXT, encoding="utf-8")
    run_dir = V.natural_run(layout, ALERT, "20261015t120000z-view-in")
    host_alert = str(run_dir / RUN_LAYOUT.alert_input_dir / "alert.json")
    skill_rel = "skills/invlang/SKILL.md"
    steps = [
        ("read_file", {"path": V.MODEL_ALERT}, "return", RULE_ID),
        ("read_file", {"path": host_alert}, "retry", None),
        ("bash", {"command": f"cat {V.MODEL_ALERT}"}, "return", RULE_ID),
        ("bash", {"command": f"cat {host_alert}"}, "retry", None),
        ("read_file", {"path": f"{V.MODEL_DEFENDER}/{skill_rel}"}, "return", "invlang"),
        ("read_file", {"path": str(layout.checkout / skill_rel)}, "retry", None),
        ("read_file", {"path": f"{V.MODEL_AGENT}/examples/{PROBE_NAME}"}, "return", PROBE_TEXT.strip()),
        ("read_file", {"path": str(probe)}, "retry", None),
    ]
    main = V.Recorder([Turn(tool_calls=[(tool, args)]) for tool, args, _, _ in steps]
                      + [Turn(text="done")])
    _drive(layout, run_dir, main, monkeypatch)

    assert main.calls == len(steps) + 1, f"the loop stopped early ({main.calls} requests)"
    for i, (tool, args, want, marker) in enumerate(steps, start=1):
        kind, text = main.answer_to(i)
        assert kind == want, f"{tool} {args}: expected a {want}, got a {kind}: {text[:400]}"
        if marker is not None:
            assert marker in text, f"{tool} {args} came back without its content: {text[:400]}"


def test_b3_refusals_and_errors_name_the_model_path_never_the_host(tmp_path, monkeypatch):
    layout = V.make_layout(tmp_path / "a", V.TENANT_A)
    older = V.natural_run(layout, ALERT, "20261015t110000z-view-older")
    (older / "investigation.md").write_text("older run\n", encoding="utf-8")
    run_dir = V.natural_run(layout, ALERT, "20261015t120000z-view-err")
    climb = f"../{older.name}/investigation.md"
    missing = f"{V.MODEL_RUN}/no-such-notes.md"
    main = V.Recorder([
        Turn(tool_calls=[("read_file", {"path": climb})]),
        Turn(tool_calls=[("read_file", {"path": missing})]),
        Turn(text="done"),
    ])
    _drive(layout, run_dir, main, monkeypatch)
    tokens = V.host_tokens(layout, extra=[run_dir, older])
    climb_kind, climb = main.answer_to(1)
    miss_kind, miss = main.answer_to(2)

    assert climb_kind == "retry", f"a climb out of the run folder was not refused: {climb[:400]}"
    assert older.name in climb, f"control: the refusal names the operand the model typed: {climb}"
    assert miss_kind == "retry", miss
    assert missing in miss, f"the error does not name the path the model typed: {miss}"
    hits = V.scan(climb, tokens)
    assert not hits, "the refusal shows host layout:\n" + "\n".join(hits)
    assert "not found" in miss, f"a missing file in the run folder is not reported as missing: {miss}"
    assert not V.scan(miss, tokens), miss


UNPROCESSABLE = (
    f"{V.MODEL_RUN}/inv\x00.md",
    f"{V.MODEL_RUN}/\ud800.md",
    f"{V.MODEL_DEFENDER}/skills/\x00/SKILL.md",
    f"{V.MODEL_AGENT}/examples/\ud800.md",
)


class _ReportsUsage:
    """A replay double that reports its own token usage, as every real provider does."""

    __name__ = "_ReportsUsage"

    def __init__(self, inner: V.Recorder) -> None:
        self.inner = inner

    def __call__(self, messages, info):
        from pydantic_ai.usage import RequestUsage

        response = self.inner(messages, info)
        response.usage = RequestUsage(input_tokens=1, output_tokens=1)
        return response


def _answers_to_unprocessable_paths(tmp_path, monkeypatch) -> tuple[list[tuple], list[str]]:
    """Exercise both read lanes on hostile paths, with the readable alert as control."""
    layout = V.make_layout(tmp_path / "a", V.TENANT_A)
    run_dir = V.natural_run(layout, ALERT, "20261015t120000z-view-nul")
    steps = [*(("read_file", {"path": p}) for p in UNPROCESSABLE),
             *(("bash", {"command": f"cat {p}"}) for p in UNPROCESSABLE),
             ("read_file", {"path": f"{RUN_LAYOUT.alert_input_dir}/alert.json"})]
    main = V.Recorder([Turn(tool_calls=[call]) for call in steps] + [Turn(text="done")])
    try:
        _drive(layout, run_dir, _ReportsUsage(main), monkeypatch)
    except Exception as e:  # noqa: BLE001 — the failure the b2 test exists to name
        pytest.fail(f"an unprocessable model path escaped the tool as {type(e).__name__}: {e!r} "
                    f"(after {main.calls} model requests)")

    assert main.calls == len(steps) + 1, f"the loop stopped early ({main.calls} requests)"
    kind, text = main.answer_to(len(steps))
    assert (kind, RULE_ID in text) == ("return", True), (
        f"positive control: the alert by its run-relative path did not read back: {kind} {text[:300]}")
    answers = [(tool, args, *main.answer_to(i)) for i, (tool, args) in enumerate(steps[:-1], 1)]
    return answers, V.host_tokens(layout, extra=[run_dir])


def test_b2_an_unprocessable_model_path_is_refused_at_the_tool_never_raised(
    tmp_path, monkeypatch,
):
    answers, _tokens = _answers_to_unprocessable_paths(tmp_path, monkeypatch)

    for tool, args, kind, text in answers:
        assert kind == "retry", f"{tool} {args!r} was not refused: {kind}: {text[:400]!r}"


def test_b3_the_refusal_of_an_unprocessable_model_path_names_no_host_layout(
    tmp_path, monkeypatch,
):
    answers, tokens = _answers_to_unprocessable_paths(tmp_path, monkeypatch)

    for tool, args, _kind, text in answers:
        hits = V.scan(text, tokens)
        assert not hits, f"the answer to {tool} {args!r} shows host layout:\n" + "\n".join(hits)


def test_b2_g10_proc_stays_outside_read_scope(tmp_path, monkeypatch):
    layout = V.make_layout(tmp_path / "a", V.TENANT_A)
    run_dir = V.natural_run(layout, ALERT, "20261015t120000z-view-proc")
    main = V.Recorder([
        Turn(tool_calls=[("read_file", {"path": "/proc/self/mountinfo"})]),
        Turn(tool_calls=[("bash", {"command": "cat /proc/self/mountinfo"})]),
        Turn(tool_calls=[("read_file", {"path": f"{RUN_LAYOUT.alert_input_dir}/alert.json"})]),
        Turn(text="done"),
    ])
    _drive(layout, run_dir, main, monkeypatch)

    for i in (1, 2):
        kind, text = main.answer_to(i)
        assert kind == "retry", f"/proc/self/mountinfo was readable: {text[:400]}"
        assert " - " not in text, "a mount table reached the model"
        assert "rw," not in text, "a mount table reached the model"
    kind, text = main.answer_to(3)
    assert (kind, RULE_ID in text) == ("return", True), (kind, text[:300])


def _elastic(payload: list[dict]) -> FakeVerbs:
    def query(ctx, *, native_query: str, limit: int = 10) -> list[dict]:
        return payload

    return FakeVerbs({"elastic": {"query": query}})


def test_b3_gather_is_dispatched_and_answered_in_the_model_view(tmp_path, monkeypatch):
    layout = V.make_layout(tmp_path / "a", V.TENANT_A)
    run_dir = V.natural_run(layout, ALERT, "20261015t120000z-view-gather")
    own = _own_tree_evidence(layout, run_dir)
    planted = [f"cat {p}" for p in (FOREIGN_HOST_PATH, *own.values())]
    payload = [{"@timestamp": "2026-05-25T13:50:00Z", "user.name": "dev.dana",
                "process.command_line": planted[0],
                **{f"process.parent{i}.command_line": line
                   for i, line in enumerate(planted[1:], start=1)}}]
    main = V.Recorder([
        Turn(tool_calls=[("gather", {"lead_id": LEAD, "system": "elastic",
                                     "goal": "measure this lead",
                                     "what_to_summarize": ["auth events"]})]),
        Turn(text="done"),
    ])
    gather = V.Recorder([
        Turn(tool_calls=[("query", {"system": "elastic", "verb": "query",
                                    "params": {"native_query": "FROM logs | LIMIT 1"}})]),
        Turn(tool_calls=[("read_file", {"path": MODEL_PAYLOAD})]),
        Turn(text="Summary: one auth event."),
    ])
    _drive(layout, run_dir, main, monkeypatch, gather=gather, verbs=_elastic(payload))

    assert gather.requests, "control: the lead was dispatched"
    dispatch = gather.first_user_text()
    assert _value(dispatch, "lead_id") == LEAD, "control: this is l-001's dispatch"
    q_kind, answer = gather.answer_to(1)
    assert q_kind == "return", answer[:400]
    assert "dev.dana" in answer, "control: the query's answer carries the payload view"
    assert FOREIGN_HOST_PATH in answer, "the payload's own bytes were rewritten in the view"
    for (name, path), line in zip(own.items(), planted[1:], strict=True):
        assert line in answer, (
            f"the payload's own bytes naming this run's {name} ({path}) were rewritten in the "
            f"view:\n{answer[:1200]}")
    rows = [r for r in read_jsonl_rows(run_dir / RUN_LAYOUT.executed_queries)
            if r.get("lead_id") == LEAD]
    assert [r.get("payload_path") for r in rows] == [f"{RUN_LAYOUT.gather_raw.name}/{LEAD}/0.json"], rows
    assert _value(dispatch, "defender_dir") == V.MODEL_DEFENDER
    assert _value(dispatch, "run_dir") == V.MODEL_RUN
    named = re.findall(r"`(/[^`\s]+)`", dispatch)
    assert named, f"the dispatch names no absolute path at all:\n{dispatch[:2000]}"
    assert all(V.under_model_root(p) for p in named), (
        f"the dispatch names paths outside the model view: {[p for p in named if not V.under_model_root(p)]}")

    assert f"[record_query] raw payload: {MODEL_PAYLOAD}" in answer, answer[-600:]

    kind, raw = gather.answer_to(2)
    assert kind == "return", f"the payload is not readable at the path the line gave: {raw[:400]}"
    assert FOREIGN_HOST_PATH in raw, raw[:400]
    assert "dev.dana" in raw, raw[:400]
    missing = [line for line in planted if line not in raw]
    assert not missing, f"the payload read back with its evidence rewritten: {missing}"

    hits = V.scan(_outside(gather.all_text(), planted), V.host_tokens(layout))
    assert not hits, "gather was shown host layout outside the evidence:\n" + "\n".join(hits)


def test_b3_the_lessons_block_names_lessons_by_model_path(tmp_path, monkeypatch):
    # #1108 P4 (O1, O4): the lessons a run's writes are matched against are its TENANT's
    # (`agent/lessons/`, at the model root `MODEL_AGENT`), never the checkout's — so the
    # lesson is planted in the tenant's agent half and named back by its `/agent` path. The
    # checkout is a mirror elsewhere, so a block that leaked either host tree is caught.
    tree = V.mirror_checkout(tmp_path / "co" / "src")
    layout = V.make_layout(tmp_path / "a", V.TENANT_A, checkout=tree)
    _write_lesson(layout.agent / "lessons", CLASS_LESSON, nodes=CLASS_SELECTOR)
    run_dir = V.natural_run(layout, ALERT, "20261015t120000z-view-lesson")
    (run_dir / RUN_LAYOUT.investigation).write_text(CLOSED_LOOP, encoding="utf-8")
    model_lesson = f"{V.MODEL_AGENT}/lessons/{CLASS_LESSON}.md"
    main = V.Recorder([
        Turn(tool_calls=[("append_block", {"text": OPEN_CLASS_BLOCK})]),
        Turn(tool_calls=[("read_file", {"path": model_lesson})]),
        Turn(text="done"),
    ])
    _drive(layout, run_dir, main, monkeypatch)

    kind, block = main.answer_to(1)
    assert kind == "return", block[:400]
    assert WRITE_RETURN_HEADER in block, f"control: the write returned no lessons block naming the lesson:\n{block}"
    assert CLASS_LESSON in block, f"control: the write returned no lessons block naming the lesson:\n{block}"
    assert f"- {model_lesson} — matched" in block, f"the block does not name the model path:\n{block}"
    hits = V.scan(block, V.host_tokens(layout))
    assert not hits, "the lessons block shows host layout:\n" + "\n".join(hits)
    kind, body = main.answer_to(2)
    assert (kind, "lesson body" in body) == ("return", True), (kind, body[:300])


_LOADED = re.compile(r"loaded (\d+)/(\d+) cases")


def test_b5_unboxed_invlang_scans_only_this_run_as_the_box_would(tmp_path, monkeypatch):
    layout = V.make_layout(tmp_path / "a", V.TENANT_A)
    golden_doc = (GOLDEN_AB3 / "investigation.md").read_text(encoding="utf-8")
    for other in ("20261015t100000z-view-sib1", "20261015t110000z-view-sib2"):
        (V.natural_run(layout, ALERT, other) / RUN_LAYOUT.investigation).write_text(
            golden_doc, encoding="utf-8")
    run_dir = V.natural_run(layout, ALERT, "20261015t120000z-view-invlang")
    main = V.Recorder([
        Turn(tool_calls=[("append_block", {"text": golden_doc})]),
        Turn(tool_calls=[("bash", {"command": "defender-invlang sequence"})]),
        Turn(text="done"),
    ])
    _drive(layout, run_dir, main, monkeypatch)

    kind, text = main.answer_to(1)
    assert kind == "return", f"control: the model's append did not land: {text[:400]}"
    assert (run_dir / RUN_LAYOUT.investigation).read_text(encoding="utf-8").strip(), (
        "control: the host run folder holds the document the model wrote")
    kind, text = main.answer_to(2)
    assert kind == "return", f"the shim did not run: {text[:400]}"
    m = _LOADED.search(text)
    assert m, f"control: the shim printed its load report: {text[:800]}"
    assert m.group(2) == "1", (
        f"invlang scanned {m.group(2)} case folders; the model view holds exactly this run:\n"
        f"{text[:800]}")
    assert m.group(1) == "1", (
        f"invlang loaded {m.group(1)} of this run's documents; the one the model wrote mid-run "
        f"is not in the staged tree:\n{text[:800]}")
    assert "view-sib" not in text, f"a sibling run reached the model: {text[:800]}"


SQL_ROWS = 3


def test_b5_unboxed_sql_reduces_a_payload_gathered_mid_run_by_its_model_path(tmp_path, monkeypatch):
    from defender.tests.e2e.test_query_tool_611 import _sql_shim_aggregates

    layout = V.make_layout(tmp_path / "a", V.TENANT_A)
    run_dir = V.natural_run(layout, ALERT, "20261015t120000z-view-sql")
    payload = [{"@timestamp": f"2026-05-25T13:5{i}:00Z", "user.name": "dev.dana"}
               for i in range(SQL_ROWS)]
    main = V.Recorder([
        Turn(tool_calls=[("gather", {"lead_id": LEAD, "system": "elastic",
                                     "goal": "count the auth events",
                                     "what_to_summarize": ["auth events"]})]),
        Turn(text="done"),
    ])
    gather = V.Recorder([
        Turn(tool_calls=[("query", {"system": "elastic", "verb": "query",
                                    "params": {"native_query": "FROM logs | LIMIT 3"}})]),
        Turn(tool_calls=[("bash", {
            "command": f"cat {MODEL_PAYLOAD} | defender-sql 'SELECT count(*) AS n FROM data'"})]),
        Turn(text="Summary: three auth events."),
    ])
    _drive(layout, run_dir, main, monkeypatch, gather=gather, verbs=_elastic(payload))

    q_kind, answer = gather.answer_to(1)
    assert q_kind == "return", f"control: the query answered: {answer[:400]}"
    assert "dev.dana" in answer, f"control: the query answered: {answer[:400]}"
    on_disk = run_dir / RUN_LAYOUT.gather_raw / LEAD / "0.json"
    assert json.loads(on_disk.read_text(encoding="utf-8")) == payload, (
        "control: the query wrote its payload to the host's run folder")
    kind, reduced = gather.answer_to(2)
    assert kind == "return", f"the reduce over the model path was refused: {reduced[:400]}"
    if not _sql_shim_aggregates():
        pytest.skip("this tree's defender-sql cannot aggregate (no duckdb in the venv it "
                    "re-execs into) — the gate half of the test ran and held")
    assert re.search(rf'"n":\s*{SQL_ROWS}\b', reduced), (
        f"defender-sql over the mid-run payload did not aggregate its rows:\n{reduced[:800]}")
    assert not V.scan(reduced, V.host_tokens(layout)), reduced


def test_c5_the_bash_overflow_hint_names_the_payload_by_its_model_path(tmp_path, monkeypatch):
    layout = V.make_layout(tmp_path / "a", V.TENANT_A)
    run_dir = V.natural_run(layout, ALERT, "20261015t120000z-view-overflow")
    payload = [{"@timestamp": "2026-05-25T13:50:00Z", "user.name": "dev.dana",
                "message": f"auth event {i:04d} " + "x" * 120} for i in range(200)]
    relative = f"{RUN_LAYOUT.gather_raw.name}/{LEAD}/0.json"
    main = V.Recorder([
        Turn(tool_calls=[("gather", {"lead_id": LEAD, "system": "elastic",
                                     "goal": "measure this lead",
                                     "what_to_summarize": ["auth events"]})]),
        Turn(text="done"),
    ])
    gather = V.Recorder([
        Turn(tool_calls=[("query", {"system": "elastic", "verb": "query",
                                    "params": {"native_query": "FROM logs"}})]),
        Turn(tool_calls=[("bash", {"command": f"cat {relative}"})]),
        Turn(text="Summary: many auth events."),
    ])
    _drive(layout, run_dir, main, monkeypatch, gather=gather, verbs=_elastic(payload))

    kind, out = gather.answer_to(2)
    assert kind == "return", f"control: the cat ran: {out[:400]}"
    assert "too large to read whole" in out, f"control: the return overflowed and carries the reduce hint:\n{out[-800:]}"
    assert "DESCRIBE data" in out, f"control: the return overflowed and carries the reduce hint:\n{out[-800:]}"
    hint = out[out.index("too large to read whole"):]
    m = re.search(r"\bcat\s+(\S+)\s+\|", hint)
    assert m, f"control: the reduce hint names the file its `cat` reads:\n{hint}"
    named = m.group(1).strip("'\"")
    assert named == relative or named.startswith(V.MODEL_RUN + "/"), (
        f"the hint names {named!r}: neither the operand the model typed ({relative!r}) nor a "
        f"path under {V.MODEL_RUN}:\n{hint}")
    hits = V.scan(hint, V.host_tokens(layout, extra=[run_dir]))
    assert not hits, "the overflow hint shows host layout:\n" + "\n".join(hits)


DIGEST_REFUSAL = "does not match the digest its record carries"


def test_c5_the_alert_digest_refusal_names_no_run_folder(tmp_path, monkeypatch):
    layout = V.make_layout(tmp_path / "a", V.TENANT_A)
    run_dir = V.natural_run(layout, ALERT, "20261015t120000z-view-digest")
    alert = run_dir / RUN_LAYOUT.alert_input_dir / "alert.json"
    original = alert.read_bytes()

    def tamper() -> None:
        alert.chmod(0o644)
        alert.write_bytes(original + b"\n")

    def restore() -> None:
        alert.write_bytes(original)

    main = V.Recorder([
        Turn(tool_calls=[("read_file", {"path": f"{RUN_LAYOUT.alert_input_dir}/alert.json"})]),
        Turn(text="done"),
    ], before={0: tamper, 1: restore})
    _drive(layout, run_dir, main, monkeypatch)

    kind, text = main.answer_to(1)
    assert kind == "retry", f"control: a replaced alert was served: {text[:400]}"
    assert DIGEST_REFUSAL in text, f"control: the refusal is the digest reason: {text}"
    assert run_dir.name not in text, f"the digest refusal names the run folder: {text}"
    assert not V.scan(text, V.host_tokens(layout, extra=[run_dir])), text
