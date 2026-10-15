"""#1255 slice B — what the model RECEIVES names the model view (outbound), and what it hands
back is read through the model view (inbound). Driven through the real driver.

Design rev 4, "Model view (P1)":
  * Outbound — "Model-bound text is built from typed paths rendered through the mapping where the
    text is constructed: the opening prompt, the workspace map, the gather dispatch and its skill
    paths, "raw payload:" lines, the lessons block …, refusals and error text."
  * Inbound — "Every path the model hands back is mapped model → host at one point on the host,
    before the permission gate checks it or a file tool opens it. That covers file tool paths and
    bash operands. The gate decides on the model path. A path outside the three trees is refused."
  * Evidence — "Evidence bytes (payloads, alert content) are never rewritten, even when they
    contain a host-like path."
  * Every mode — unboxed mode runs shims against a per-run staging tree; P-U6 (dossier): symlink
    staging makes invlang's corpus walk skip the run, so the assertion is the OUTCOME: invlang sees
    this run's own case, and only it.

Entry surface: `_replay_harness.drive` (the real `run_investigation`), with the run folder made by
`run_common.materialize_run` under a real set-up tenant in a chosen data root, and the bash lane's
executor built by the production `start_box` fallback (`DEFENDER_ALLOW_UNSANDBOXED=1` over a daemon
double that refuses the create) — never the harness's own host-env executor, which would be a
test-built env. Observations are the model doubles' received messages (`_1255_view.Recorder`).

Each negative ("no host path") is paired with a positive on the same message: the surface carries
its content (the alert, the payload view, the lesson) AND the model path form.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender._io import read_jsonl_rows  # noqa: E402
from defender.run_repository import RUN_LAYOUT  # noqa: E402
from defender.runtime import box as box_mod  # noqa: E402
from defender.runtime.box import BoxSpec  # noqa: E402
from defender.tests import _1255_view as V  # noqa: E402
from defender.tests._fold_936 import (  # noqa: E402
    CLASS_LESSON,
    CLASS_SELECTOR,
    CLOSED_LOOP,
    OPEN_CLASS_BLOCK,
    WRITE_RETURN_HEADER,
)
from defender.tests._lessons_corpus import _write_lesson  # noqa: E402
from defender.tests.e2e._replay_harness import (  # noqa: E402
    GOLDEN_AB3,
    FakeVerbs,
    Turn,
    drive,
)

pytestmark = pytest.mark.e2e

ALERT = (GOLDEN_AB3 / "alert.json").read_bytes()
#: A string the AB3 alert carries — the positive control that message 0 shows the alert.
RULE_ID = "v2-cross-tier-ssh-pivot"
SPEC = BoxSpec(runtime="runc", rootfs=V.STATIC_ROOTFS)
_SALT = re.compile(r"run-[0-9a-f]{16}-")
LEAD = "l-001"
MODEL_PAYLOAD = f"{V.MODEL_RUN}/{RUN_LAYOUT.gather_raw.name}/{LEAD}/0.json"
#: Evidence that LOOKS like a host path but is no path of this host — the payload must reach the
#: model byte for byte (design: evidence is never rewritten).
FOREIGN_HOST_PATH = "/srv/acme-prod/defender-data/acme/runs/20250101t000000z-old/investigation.md"


def _unboxed(layout: V.Layout, run_dir: Path, monkeypatch) -> object:
    """The run's executor as production builds it when the box cannot start and the operator
    opted into the unsandboxed fallback."""
    monkeypatch.setenv("DEFENDER_ALLOW_UNSANDBOXED", "1")
    return box_mod.start_box(run_dir, layout.checkout, spec=SPEC, docker=V.FakeDocker(),
                             tenant_agent=layout.agent, tenant_id=layout.tenant.id)


def _drive(layout: V.Layout, run_dir: Path, main, monkeypatch, **kw) -> dict:
    return drive(run_dir, run_id=run_dir.name, main=main, tenant=layout.tenant,
                 defender_dir=layout.checkout, box=_unboxed(layout, run_dir, monkeypatch), **kw)


def _value(text: str, label: str) -> str:
    """The value a `label: value` line carries (the opening prompt's coordinates, the dispatch's
    yaml), or AssertionError naming the missing label."""
    m = re.search(rf"^{re.escape(label)}: (.*)$", text, re.MULTILINE)
    assert m, f"no `{label}:` line in:\n{text[:2000]}"
    return m.group(1)


def _map_root(text: str, name: str) -> str:
    """The workspace map's `- NAME: `value`` line."""
    m = re.search(rf"^- {re.escape(name)}: `([^`]*)`$", text, re.MULTILINE)
    assert m, f"the workspace map has no {name} root line:\n{text[:3000]}"
    return m.group(1)


# ---------------------------------------------------------------------------------------------
# B3 — message 0
# ---------------------------------------------------------------------------------------------
def test_b3_message_zero_names_the_run_and_its_alert_by_model_path(tmp_path, monkeypatch):
    """P1 outbound (the opening prompt and the workspace map) / O3: message 0 shows the alert
    (positive control: the rule id is in it) and names the run as `run_dir: /runs/current`, the
    alert as `alert: /runs/current/alert_input/alert.json`, and the workspace map's roots as
    `RUN_DIR: /runs/current`, `DEFENDER_DIR: /defender`. No data root, tenant name, checkout path
    or home appears anywhere in it. Today each is the host path (G2/G3)."""
    layout = V.make_layout(tmp_path / "a", V.TENANT_A)
    run_dir = V.natural_run(layout, ALERT, "20261015t120000z-view-m0")
    main = V.Recorder([Turn(text="done")])
    _drive(layout, run_dir, main, monkeypatch)

    m0 = main.first_user_text()
    assert RULE_ID in m0, "control: message 0 carries the alert"
    assert _value(m0, "run_dir") == V.MODEL_RUN
    assert _value(m0, "alert") == V.MODEL_ALERT
    assert _map_root(m0, "RUN_DIR") == V.MODEL_RUN
    assert _map_root(m0, "DEFENDER_DIR") == V.MODEL_DEFENDER
    assert f"## Run dir — `{V.MODEL_RUN}`" in m0, "the run-dir listing is not headed by its model path"
    hits = V.scan(m0, V.host_tokens(layout))
    assert not hits, "message 0 shows host layout:\n" + "\n".join(hits)


def test_b3_message_zero_is_the_same_under_two_host_layouts(tmp_path, monkeypatch):
    """P1 / O3 ("host layout is identical for two runs on one host, so equality alone cannot
    catch it"): two hosts that differ in data root, tenant name and checkout path (B's checkout
    is a mirror at another path) give the SAME message 0, frame salts aside. Positive control:
    each is a full opening prompt (the alert is in it). Today the coordinates, the map's roots
    and its run-dir heading differ by host."""
    a = V.make_layout(tmp_path / "a", V.TENANT_A)
    b = V.make_layout(tmp_path / "b" / "x" / "y", V.TENANT_B,
                      checkout=V.mirror_checkout(tmp_path / "b" / "src" / "co"))
    run_id = "20261015t120000z-view-two"
    seen = []
    for layout in (a, b):
        main = V.Recorder([Turn(text="done")])
        _drive(layout, V.natural_run(layout, ALERT, run_id), main, monkeypatch)
        seen.append(_SALT.sub("run-<SALT>-", main.first_user_text()))
    ma, mb = seen
    assert RULE_ID in ma and RULE_ID in mb, "control: both are opening prompts"
    if ma != mb:
        diff = [(x, y) for x, y in zip(ma.splitlines(), mb.splitlines()) if x != y]
        raise AssertionError("message 0 depends on the host layout:\n"
                             + "\n".join(f"  A: {x}\n  B: {y}" for x, y in diff[:12]))


#: The Lessons section's hits subsection — present only when the signature lookup matched.
HITS_HEADER = "### Hits for that signature"


def test_b6_o3_message_zero_lessons_section_shows_no_host_layout(tmp_path, monkeypatch):
    """O3 on message 0's Lessons section, with ORIENT's real shims (`orient._shim`, the
    `drive` docstring's own seam for this section): the signature lookup's hits reach the model
    (control: the hits subsection is in message 0 — the checked-in corpus holds lessons keyed
    on the AB3 alert's signature `v2-cross-tier-ssh-pivot`; `defender-lessons` reads only the
    checkout's REAL `lessons/`, so no planted lesson can stand in) and no data root, tenant
    name, checkout path or home appears in the message. Today `defender-lessons` runs on the
    host and prints each hit's resolved host path (`lessons_fm._emit_match`). The design's
    outbound list does not name this section; O3 ("no host layout … on any run") does — see the
    slice report's finding on host-run ORIENT shims."""
    from defender.runtime import orient

    layout = V.make_layout(tmp_path / "a", V.TENANT_A)
    run_dir = V.natural_run(layout, ALERT, "20261015t120000z-view-lessons0")
    main = V.Recorder([Turn(text="done")])
    _drive(layout, run_dir, main, monkeypatch, orient_shim=orient._shim)

    m0 = main.first_user_text()
    assert "## Lessons" in m0 and HITS_HEADER in m0, (
        "control: the signature lookup's hits are not in message 0 — the shims did not run, or "
        "the corpus no longer holds a lesson for this signature")
    hits = V.scan(m0, V.host_tokens(layout))
    assert not hits, "message 0's lessons section shows host layout:\n" + "\n".join(hits)


# ---------------------------------------------------------------------------------------------
# B4 — evidence bytes are never rewritten
# ---------------------------------------------------------------------------------------------
def test_b4_an_alert_carrying_a_host_path_is_shown_byte_for_byte(tmp_path, monkeypatch):
    """P1 evidence rule: an alert whose content names a real host path of THIS host (the data
    root's runs folder) is inlined into message 0 with that path untouched, and read back
    through the model path with it untouched — while the coordinate line in the same message is
    the model path. This is also the scanner's positive control on message 0: the scan finds the
    data root, and only inside the evidence. A renderer that rewrote host prefixes in outbound
    text would rewrite the evidence; one that left the coordinates alone fails the coordinate
    line (today)."""
    layout = V.make_layout(tmp_path / "a", V.TENANT_A)
    evidence = f"{layout.data_root}/{layout.tenant_id}/runs/20250101t000000z-old/investigation.md"
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
    # Controls (hold today): the evidence is in message 0 verbatim, and the scanner sees it.
    assert f"cat {evidence}" in m0, "the alert's own bytes were rewritten in message 0"
    assert V.scan(m0, [str(layout.data_root)]), "control: the scanner sees the planted path"
    # The model view (red today): the coordinate is the model path and nothing OUTSIDE the
    # evidence names the host; the alert reads back by its model path, bytes intact.
    assert _value(m0, "run_dir") == V.MODEL_RUN
    assert not V.scan(m0.replace(evidence, "<EVIDENCE>"), V.host_tokens(layout)), (
        "message 0 shows host layout outside the evidence")
    kind, text = main.answer_to(1)
    assert kind == "return", f"the alert was not read through its model path: {text}"
    assert f"cat {evidence}" in text, "the alert read back with its bytes rewritten"


# ---------------------------------------------------------------------------------------------
# B2 — inbound: every tree by its model path, never by a host path
# ---------------------------------------------------------------------------------------------
PROBE_NAME = "view-probe-1255.md"
PROBE_TEXT = "agent-half probe body 1255\n"


def test_b2_file_tools_and_bash_reach_each_tree_by_model_path_and_refuse_host_paths(
    tmp_path, monkeypatch,
):
    """P1 inbound: MAIN reads the run's alert (`read_file` and `cat`), a checkout skill and a
    tenant agent-half page by their MODEL paths — each comes back with its content — and the SAME
    files named by their HOST paths are refused (a host path the model guesses is outside the
    three trees: the gate decides on the model path). Today the model paths do not exist on the
    host and the host paths are the gate's roots, so every pair is inverted."""
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


# ---------------------------------------------------------------------------------------------
# B3 — refusals and error text
# ---------------------------------------------------------------------------------------------
def test_b3_refusals_and_errors_name_the_model_path_never_the_host(tmp_path, monkeypatch):
    """P1 outbound (refusals and error text, G17): a relative path that climbs out of the run
    folder is refused naming no host path (today the refusal spells the operand anchored on the
    HOST run folder); a missing file inside the run folder is "not found" under the path the model
    typed (today the gate refuses `/runs/current/…` as outside its roots). Positive controls: each
    answer is a refusal carrying the operand the model typed. The tenant's runs folder holds a
    second, older run the relative path names — the sibling a natural run must not see."""
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

    # Controls (hold today): both are refusals carrying the operand the model typed.
    assert climb_kind == "retry", f"a climb out of the run folder was not refused: {climb[:400]}"
    assert older.name in climb, f"control: the refusal names the operand the model typed: {climb}"
    assert miss_kind == "retry", miss
    assert missing in miss, f"the error does not name the path the model typed: {miss}"
    # The model view (red today).
    hits = V.scan(climb, tokens)
    assert not hits, "the refusal shows host layout:\n" + "\n".join(hits)
    assert "not found" in miss, f"a missing file in the run folder is not reported as missing: {miss}"
    assert not V.scan(miss, tokens), miss


def test_b2_g10_proc_stays_outside_read_scope(tmp_path, monkeypatch):
    """Holding control for the `/proc/self/mountinfo` residual (U1, G10): whatever the box's
    mount table shows, MAIN cannot read it — `read_file` and `cat` of `/proc/self/mountinfo` are
    both refused. Passes today; it must keep passing once the gate decides on model paths (a
    path outside the three trees is refused, as today)."""
    layout = V.make_layout(tmp_path / "a", V.TENANT_A)
    run_dir = V.natural_run(layout, ALERT, "20261015t120000z-view-proc")
    main = V.Recorder([
        Turn(tool_calls=[("read_file", {"path": "/proc/self/mountinfo"})]),
        Turn(tool_calls=[("bash", {"command": "cat /proc/self/mountinfo"})]),
        # Relative to the run folder, so the control reads the same file before and after the
        # change (the anchor is the host run folder today, `/runs/current` after).
        Turn(tool_calls=[("read_file", {"path": f"{RUN_LAYOUT.alert_input_dir}/alert.json"})]),
        Turn(text="done"),
    ])
    _drive(layout, run_dir, main, monkeypatch)

    for i in (1, 2):
        kind, text = main.answer_to(i)
        assert kind == "retry", f"/proc/self/mountinfo was readable: {text[:400]}"
        assert " - " not in text and "rw," not in text, "a mount table reached the model"
    # Positive control on the same channel: a read the gate admits comes back as content.
    kind, text = main.answer_to(3)
    assert (kind, RULE_ID in text) == ("return", True), (kind, text[:300])


# ---------------------------------------------------------------------------------------------
# B3/B4 — the gather dispatch, the "raw payload:" line, the payload bytes
# ---------------------------------------------------------------------------------------------
def _elastic(payload: list[dict]) -> FakeVerbs:
    def query(ctx, *, native_query: str, limit: int = 10) -> list[dict]:
        return payload

    return FakeVerbs({"elastic": {"query": query}})


def test_b3_gather_is_dispatched_and_answered_in_the_model_view(tmp_path, monkeypatch):
    """P1 outbound (the gather dispatch and its skill paths, the "raw payload:" line) + inbound
    (gather reads its payload by the model path the line gave it) + evidence (the payload's own
    host-like text is served byte for byte). The dispatch's `defender_dir:`/`run_dir:` are
    `/defender` and `/runs/current` and every absolute path it names is under a model root; the
    query's answer carries the payload view (control) and `raw payload:
    /runs/current/gather_raw/l-001/0.json`; reading that path returns the payload. No host layout
    in anything gather received. H1 control: the queries table still records the payload
    run-relative (`gather_raw/l-001/0.json`), as today."""
    layout = V.make_layout(tmp_path / "a", V.TENANT_A)
    run_dir = V.natural_run(layout, ALERT, "20261015t120000z-view-gather")
    payload = [{"@timestamp": "2026-05-25T13:50:00Z", "user.name": "dev.dana",
                "process.command_line": f"cat {FOREIGN_HOST_PATH}"}]
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
    # Controls (hold today): the query's answer carries the payload view with its evidence bytes
    # intact, and the host's record keeps the payload run-relative (H1).
    q_kind, answer = gather.answer_to(1)
    assert q_kind == "return", answer[:400]
    assert "dev.dana" in answer, "control: the query's answer carries the payload view"
    assert FOREIGN_HOST_PATH in answer, "the payload's own bytes were rewritten in the view"
    rows = [r for r in read_jsonl_rows(run_dir / RUN_LAYOUT.executed_queries)
            if r.get("lead_id") == LEAD]
    assert [r.get("payload_path") for r in rows] == [f"{RUN_LAYOUT.gather_raw.name}/{LEAD}/0.json"], rows
    # The model view (red today).
    assert _value(dispatch, "defender_dir") == V.MODEL_DEFENDER
    assert _value(dispatch, "run_dir") == V.MODEL_RUN
    named = re.findall(r"`(/[^`\s]+)`", dispatch)
    assert named, f"the dispatch names no absolute path at all:\n{dispatch[:2000]}"
    assert all(V.under_model_root(p) for p in named), (
        f"the dispatch names paths outside the model view: {[p for p in named if not V.under_model_root(p)]}")

    assert f"[record_query] raw payload: {MODEL_PAYLOAD}" in answer, answer[-600:]

    kind, raw = gather.answer_to(2)
    assert kind == "return", f"the payload is not readable at the path the line gave: {raw[:400]}"
    assert FOREIGN_HOST_PATH in raw and "dev.dana" in raw, raw[:400]

    hits = V.scan(gather.all_text(), V.host_tokens(layout))
    assert not hits, "gather was shown host layout:\n" + "\n".join(hits)


# ---------------------------------------------------------------------------------------------
# B3 — the lessons block a write returns
# ---------------------------------------------------------------------------------------------
def test_b3_the_lessons_block_names_lessons_by_model_path(tmp_path, monkeypatch):
    """P1 outbound (the lessons block; today an absolute realpath, G19): an append that opens a
    slot a corpus lesson keys on returns the write-return block naming that lesson (control: the
    header and the lesson's name are there) at `/defender/lessons/<name>.md`, and MAIN reads the
    lesson back by exactly that path. The checkout is a mirror at another host path with its own
    `lessons/` folder, so a host realpath would name the mirror — scanned for, with the rest of
    the layout."""
    tree = V.mirror_checkout(tmp_path / "co" / "src", own_lessons=True)
    layout = V.make_layout(tmp_path / "a", V.TENANT_A, checkout=tree)
    _write_lesson(tree / "lessons", CLASS_LESSON, nodes=CLASS_SELECTOR)
    run_dir = V.natural_run(layout, ALERT, "20261015t120000z-view-lesson")
    (run_dir / RUN_LAYOUT.investigation).write_text(CLOSED_LOOP, encoding="utf-8")
    model_lesson = f"{V.MODEL_DEFENDER}/lessons/{CLASS_LESSON}.md"
    main = V.Recorder([
        Turn(tool_calls=[("append_block", {"text": OPEN_CLASS_BLOCK})]),
        Turn(tool_calls=[("read_file", {"path": model_lesson})]),
        Turn(text="done"),
    ])
    _drive(layout, run_dir, main, monkeypatch)

    kind, block = main.answer_to(1)
    assert kind == "return", block[:400]
    assert WRITE_RETURN_HEADER in block and CLASS_LESSON in block, (
        f"control: the write returned no lessons block naming the lesson:\n{block}")
    assert f"- {model_lesson} — matched" in block, f"the block does not name the model path:\n{block}"
    hits = V.scan(block, V.host_tokens(layout))
    assert not hits, "the lessons block shows host layout:\n" + "\n".join(hits)
    kind, body = main.answer_to(2)
    assert (kind, "lesson body" in body) == ("return", True), (kind, body[:300])


# ---------------------------------------------------------------------------------------------
# B5 — unboxed: invlang's corpus is this run, through the staged tree
# ---------------------------------------------------------------------------------------------
_LOADED = re.compile(r"loaded (\d+)/(\d+) cases")


def test_b5_unboxed_invlang_scans_only_this_run_as_the_box_would(tmp_path, monkeypatch):
    """P1 "Every mode" + P-U6 + C6 (rev 5: "the staging tree reflects host writes made during the
    run, so shims see payloads and document edits written mid-run"): in unboxed mode MAIN writes
    its work log with `append_block`, then runs `defender-invlang sequence`, which walks the staged
    runs folder — exactly ONE case folder (`current`, this run), as inside a box where `/runs`
    holds only the mounted run — and LOADS it, so the document the model wrote mid-run is the one
    the shim read. The tenant's real runs folder holds two other runs (the siblings an arm's
    folder would hold), and none of them is scanned. Positive controls: the append landed and the
    shim ran and printed its load report. Today the unboxed executor hands the shim the real runs
    folder (it scans all three); symlink staging would scan none (P-U6: 0/0); a staging tree
    copied once at run start would scan the run's folder and load nothing (0/0 — the document did
    not exist yet)."""
    layout = V.make_layout(tmp_path / "a", V.TENANT_A)
    golden_doc = (GOLDEN_AB3 / "investigation.md").read_text(encoding="utf-8")
    for other in ("20261015t100000z-view-sib1", "20261015t110000z-view-sib2"):
        (V.natural_run(layout, ALERT, other) / RUN_LAYOUT.investigation).write_text(
            golden_doc, encoding="utf-8")
    run_dir = V.natural_run(layout, ALERT, "20261015t120000z-view-invlang")
    main = V.Recorder([
        # Onto an empty run folder the append IS the create (`test_replay_skeleton`).
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


# ---------------------------------------------------------------------------------------------
# B5/C6 — unboxed: a payload written mid-run is reduced by the model path the line gave
# ---------------------------------------------------------------------------------------------
SQL_ROWS = 3


def test_b5_unboxed_sql_reduces_a_payload_gathered_mid_run_by_its_model_path(tmp_path, monkeypatch):
    """P1 "Every mode" + C6 + inbound (bash operands): gather queries, then reduces the payload
    the query just wrote with `cat /runs/current/gather_raw/l-001/0.json | defender-sql …`, the
    path its "raw payload:" line names — through production's unboxed mode. The reduce aggregates
    the real rows (n = 3): the operand mapped inbound, and the staged tree holds the payload
    written during the run. Controls: the query answered and the payload is on the host's disk.
    Today the gate refuses `/runs/current/…` as outside its roots."""
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
    assert q_kind == "return" and "dev.dana" in answer, f"control: the query answered: {answer[:400]}"
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


# ---------------------------------------------------------------------------------------------
# C5 — the bash overflow hint and the alert-digest refusal
# ---------------------------------------------------------------------------------------------
def test_c5_the_bash_overflow_hint_names_the_payload_by_its_model_path(tmp_path, monkeypatch):
    """C5 (rev 5): the bash overflow hint (`cat <payload> | defender-sql …`) names no host path.
    Gather `cat`s its payload (relative, admitted today) when the payload is larger than the
    captured-payload ceiling; the return is cut and carries the reduce hint (control: the
    "too large" note and `DESCRIBE data`). The path the hint's `cat` names is either the
    relative operand exactly as the model typed it or a path under `/runs/current` (C5's promise
    is that the hint names no host path, not that it uses the absolute form), and no host layout
    appears in the hint. Today the hint spells the operand's HOST path."""
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
    assert "too large to read whole" in out and "DESCRIBE data" in out, (
        f"control: the return overflowed and carries the reduce hint:\n{out[-800:]}")
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
    """C5 (rev 5): the alert-digest refusal names no run folder name. Between two of MAIN's
    turns the stored alert's bytes change on disk (the hook runs as request 1 arrives, before
    the read it answers with); the read of `alert_input/alert.json` is refused with the digest
    reason (control), and the refusal names neither the run folder's name nor any host layout.
    The bytes are put back as the next request arrives, so the run's own post-steps read the
    alert it started with. Today the reason is "the alert stored for run <run folder name> …"."""
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
