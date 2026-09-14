"""Shared machinery for #1025's episode page spec (`learning.html`) — NO test scripts.

The change: a page rendered from an episode directory alone —
`scripts/visualize/visualize_episode.py::render_episode(episode_dir) -> Path`, written beside
`judge.yaml` through `_io.write_guarded`'s replace lane, called by the launcher after the JUDGE
clock frame closes (inside `_cluster_released`'s body, under its own non-fatal boundary) and by
the standalone CLI `main([episode_dir])`. NONE of it exists at base `e8d22ac0`; every import goes
through `mod()` PER TEST (the `_triplet_947` / `_judge_921` idiom) so the missing target is one
failure per test, never a collection error hiding the other assertions.

THE ARCHIVES ARE NOT VISIBLE TO CI (F27: `/workspace/.defender-episodes/` is gitignored and
outside the checkout), so every "sample" number the design doc quotes off
`fresh-authkeys-20260909-n124` (13 findings, 4 withheld, 5 world-author rows, $1.6386) is
carried here by a SUITE-BUILT episode that reproduces the archive's SHAPE with its own numbers:
`sample_episode()` — three worlds (the control `a`, `no_remote_session` withheld, `prior_fake_key_precedent` graded), one draw each plus a family draw, three questioner traces, three
judge traces with their framed twins, three sibling run dirs each ending in a result event, the
review / samples / staged / provenance records — and no `timing.json`, because both archives
predate prep 1 (c25). Every fixture number is a module constant (`SAMPLE`), so a test asserts
against the fixture's declared figure, never against a value its own body computed from the
records.

EVERY RECORD IS WRITTEN IN THE SHAPE ITS PRODUCTION WRITER LEAVES AND READ BACK THROUGH ITS
PRODUCTION READER before a test sees it — `write_judge` round-trips through `judge.read_grade`,
`draw_document` through `enqueue.draws_on_disk`, `staged.yaml` is written by
`staging.record_staged` itself, the manifest by `_triplet_947.write_family`, the served
ledgers by `_judge_921.write_ledger`, the run dirs by `_triplet_947.sibling_run_dir`. A fixture
the real reader refuses is a fixture bug, and it fails HERE, loudly, rather than turning up as a
page that rendered "unreadable" for a record the test believed intact. Where a scenario WANTS an
unreadable record it writes raw bytes (`plant_raw`) and says so.

Fault content cites the ledger claim that observed it on the real dependency
(`spec-flow/specs/spec_graph_1025.yaml`, `claims:`): the trace row shape is c2, the result event
c4, the framed row c8, the refusal classes F25/p6/x16, the replace lane's refusal p1, the NUL /
lone-surrogate encode behaviour p4, the unscreened world leaves p2. Nothing here induces a fault
by imagination; the only fakes are the launcher harness's own (`_judge_921.FakeSibling` /
`FakeJudge`), reached through `cli.main`'s seams (never `monkeypatch.setattr`).

Underscore-prefixed so pytest does not collect it; it defines no tests.
"""
from __future__ import annotations

import contextlib
import html
import json
import os
import shutil
import signal
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import yaml

from defender._io import write_guarded
from defender.tests import _judge_921 as J
from defender.tests import _triplet_947 as T

mod = T.mod
sym = T.sym

#: The page module and its two entry points — the design's names (20-demands.md §2, Q1).
PAGE_MODULE = "scripts.visualize.visualize_episode"
PAGE_NAME = "learning.html"

#: The episode identity every fixture here carries — the harness's, so `episode_dir_for`,
#: `world_token` and the served-ledger names all agree with the launcher's own.
EPISODE_ID = T.EPISODE_ID
EPISODE_TOKEN = T.EPISODE_TOKEN

#: The sample's three worlds, in manifest order. Underscored labels ON PURPOSE (g2): the judge
#: trace stem `judge_no_remote_session_0_trace` is ambiguous to a filename parser, which is what
#: `s_judge_trace_stems_with_underscored_labels_and_two_digit_draws` is about.
CONTROL = "a"
WITHHELD_WORLD = "no_remote_session"
GRADED_WORLD = "prior_fake_key_precedent"
FAMILY = "family"
WORLDS = (CONTROL, WITHHELD_WORLD, GRADED_WORLD)

AXIS_WITHHELD = "There is no accepted SSH login from the external address around the write."
AXIS_GRADED = "Falco history holds two earlier fake-key writes shaped like this one."
BASE_STORY = "Host soc-playground fired the authorized_keys rule after a root one-liner."
ALERT_RULE = "v2 Falco: authorized_keys modification"
ALERT_ID = "99c120d90c1b134ffa0368cdb9f29e766aa0a275e8cd9471ff63ff98fd99a250"
LESSONS_COMMIT = "68f0c7da909108e75ebe76980b8ad6a103eebb4a"
MODEL = "accounts/fireworks/models/kimi-k3"   # prices through the table (c3): $3/M in, $15/M out
ENQUEUED_TO = "/workspace/.claude/worktrees/episode-authkeys/defender/learning/_pending/findings.jsonl"
WORLD_ENQUEUED_TO = ("/workspace/.claude/worktrees/episode-authkeys/defender/learning/_pending/"
                     "questioner_findings.jsonl")
ENVELOPE_FAILED = "ES|QL query failed (HTTP 400): Found 3 problems\nline 2:9: Unknown column"


@dataclass(frozen=True)
class _Sample:
    """The fixture's declared figures — the expected side of every count assertion."""

    findings: int = 13            # 5 + 5 + 3
    defender_enqueued: int = 4    # prior_fake_key_precedent's four subject: defender rows
    defender_withheld: int = 4    # no_remote_session's four, withheld reachability_unmeasured
    world_author: int = 5         # one per world draw + the family draw's three
    queued: int = 9               # 4 + 5
    withheld_reason: str = "reachability_unmeasured"
    graded: int = 2
    measuring: int = 1
    contrasting: int = 0
    # trace usage → cost through the pricing table (kimi-k3: $3/M in, $15/M out — exact sums)
    questioner_usage: tuple[tuple[int, int], ...] = ((100_000, 10_000), (50_000, 10_000),
                                                     (50_000, 10_000))
    questioner_cost: str = "$1.0500"        # 0.45 + 0.30 + 0.30
    questioner_ms: tuple[int, ...] = (60_000, 30_000, 30_000)
    questioner_wall: str = "2m00s"
    judge_usage: tuple[tuple[int, int], ...] = ((100_000, 20_000), (50_000, 20_000),
                                                (50_000, 20_000))
    judge_cost: str = "$1.5000"             # 0.60 + 0.45 + 0.45
    judge_ms: tuple[int, ...] = (120_000, 60_000, 60_000)
    judge_wall: str = "4m00s"
    run_cost: dict[str, float] = field(default_factory=lambda: {
        CONTROL: 0.40, WITHHELD_WORLD: 0.25, GRADED_WORLD: 0.35})
    run_ms: dict[str, int] = field(default_factory=lambda: {
        CONTROL: 600_000, WITHHELD_WORLD: 180_000, GRADED_WORLD: 300_000})
    worlds_cost: str = "$1.0000"
    total_cost: str = "$3.5500"             # 1.05 + 1.50 + 1.00
    longest_world: str = "10m00s"
    shortest_world: str = "3m00s"
    lower_bound: str = "16m00s"             # 2m00s + 4m00s + 10m00s


SAMPLE = _Sample()


# --------------------------------------------------------------------------------------
# Record writers — each in its production writer's shape, each read back through its reader.
# --------------------------------------------------------------------------------------


def write_judge(episode_dir: Path, doc: dict[str, Any], *, check: bool = True) -> Path:
    """`judge.yaml` as `_write_judge_yaml` leaves it — the `EpisodeGrade` schema dumped with
    `sort_keys=False` through the guarded replace lane — and read back through `read_grade`
    so a document the reader refuses fails here, not in the page."""
    path = Path(episode_dir) / "judge.yaml"
    write_guarded(path, yaml.safe_dump(doc, sort_keys=False), mode="replace")
    if check:
        record = J.sym("learning.judge", "read_grade")(episode_dir)
        assert record is not None, "fixture bug: judge.yaml did not read back as a grade"
    return path


def plant_raw(path: Path, data: bytes | str) -> Path:
    """Bytes at a record's name, VERBATIM — for the scenarios whose subject is an unreadable
    record. Replaces whatever is there (a file, a link) so a scenario can turn an intact record
    into a broken one in one line."""
    path = Path(path)
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        path.write_text(data, encoding="utf-8")
    else:
        path.write_bytes(data)
    return path


def finding(*, subject: str = "defender", bucket: str = "lead-set",
            claim: str = "the holding system was never re-queried",
            root_cause: str = "the lead was set and never revisited", anchor: str = "l-001",
            topic: str = "holding-system coverage", evidence: list[str] | None = None,
            **over: Any) -> dict[str, Any]:
    """One finding row in a per-draw document — `_judge_921.finding_doc`'s shape plus the
    two `None` fields every ARCHIVED row carries (`world`, `finding_id`; c23/g11)."""
    row = J.finding_doc(subject=subject, bucket=bucket, claim=claim, root_cause=root_cause,
                        anchor=anchor, topic=topic, evidence=evidence)
    row.update({"unresolved_evidence": [], "world": None, "finding_id": None})
    row.update(over)
    return row


def draw_document(episode_dir: Path, label: str, draw: int | str, doc: dict[str, Any], *,
                  check: bool = True) -> Path:
    """`worlds/<label>/judge/<draw>.yaml` — the per-draw document `_run_world_draws` writes —
    read back through `enqueue.draws_on_disk` (the ONE reader, c27) unless the stem is one the
    reader is meant to ignore (`check=False`: `01.yaml`, a non-ASCII digit)."""
    draw_dir = Path(episode_dir) / "worlds" / label / "judge"
    draw_dir.mkdir(parents=True, exist_ok=True)
    path = draw_dir / f"{draw}.yaml"
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    if check:
        on_disk = J.sym("learning.judge.enqueue", "draws_on_disk")(draw_dir)
        assert int(draw) in on_disk, f"fixture bug: draw {draw} did not read back"
    return path


def draw_doc(*, findings: list[dict[str, Any]] | None = None, episode_outcome: str = "gradable",
             dropped: int = 0, **over: Any) -> dict[str, Any]:
    """A per-draw document: `episode_outcome`, `noise_floor_note`, the three pass tables, the
    findings and `dropped_findings` (a COUNT, amendment 2)."""
    doc = J.reply_doc(episode_outcome=episode_outcome,
                      findings=findings if findings is not None else [finding()])
    doc["dropped_findings"] = dropped
    doc.update(over)
    return doc


def trace_rows(agent_id: str, *, prompt: str = "the framed prompt", reply: str = "the reply",
               usage: tuple[int, int] | None = (1_000, 100), duration_ms: float | None = 1_000.0,
               model: str | None = MODEL, instructions: str = "You are the seat.",
               response: bool = True) -> list[dict[str, Any]]:
    """One call's rows in the run wire log's record shape (c2): a `request` row whose message
    carries `instructions` and a `user-prompt` part, then a `response` row carrying top-level
    `model`, `usage` and `duration_ms` plus its `thinking`/`text` parts. `usage=None`,
    `duration_ms=None` and `model=None` DROP the field (the missing-usage arm); `response=False`
    leaves the request alone (the faulted-call arm)."""
    request = {
        "event_type": "message", "agent_id": agent_id, "seq": 0, "id": f"{agent_id}#0",
        "kind": "request",
        "message": {"parts": [{"content": prompt, "timestamp": "2026-09-09T17:14:43Z",
                               "part_kind": "user-prompt"}],
                    "timestamp": "2026-09-09T17:14:43Z", "instructions": instructions,
                    "kind": "request", "run_id": "r", "conversation_id": "c", "metadata": None},
    }
    if not response:
        return [request]
    reply_row: dict[str, Any] = {
        "event_type": "message", "agent_id": agent_id, "seq": 1, "id": f"{agent_id}#1",
        "kind": "response",
        "message": {"parts": [{"content": "thinking…", "part_kind": "thinking"},
                              {"content": reply, "part_kind": "text"}],
                    "timestamp": "2026-09-09T17:16:11Z", "kind": "response",
                    "model_name": model or "", "finish_reason": "stop"},
    }
    if model is not None:
        reply_row["model"] = model
    if usage is not None:
        reply_row["usage"] = {"input_tokens": usage[0], "output_tokens": usage[1],
                              "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0}
    if duration_ms is not None:
        reply_row["duration_ms"] = duration_ms
    return [request, reply_row]


def trace_stem(agent_id: str) -> str:
    """`<agent_id with ':'->'_'>_trace` — the writer's own rule (g2), spelled once."""
    return f"{agent_id.replace(':', '_')}_trace"


def write_trace(episode_dir: Path, agent_id: str, rows: list[dict[str, Any]] | None = None,
                *, raw: str | None = None, **kw: Any) -> Path:
    """`wire_logs/<stem>.jsonl` — what `run_stage`'s `RequestLogger` leaves for one call. `raw=`
    writes the bytes verbatim (a torn tail, an empty file)."""
    d = Path(episode_dir) / "wire_logs"
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"{trace_stem(agent_id)}.jsonl"
    if raw is not None:
        path.write_text(raw, encoding="utf-8")
        return path
    if rows is None:
        rows = trace_rows(agent_id, **kw)  # lint-default: ok — the default is a fresh per-call row set built from the other keywords, not a constant
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return path


def write_framed(episode_dir: Path, agent_id: str, *, prompt: str = "the framed prompt",
                 reply: str | None = "the reply", failure: str | None = None) -> Path:
    """`wire_logs/<stem>_framed_trace.jsonl` — `_write_wire_log`'s one-row record (c8)."""
    d = Path(episode_dir) / "wire_logs"
    d.mkdir(parents=True, exist_ok=True)
    name = f"{agent_id.replace(':', '_')}_framed_trace.jsonl"
    path = d / name
    row = {"agent_id": agent_id, "prompt": prompt, "reply": reply, "failure": failure,
           "wire_log_written_at": name}
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    return path


def result_event(*, cost: float | Any = 0.25, duration_ms: int | Any = 180_000,
                 **over: Any) -> dict[str, Any]:
    """The tail `result` event of a run's `tool_trace.jsonl` (c4)."""
    row: dict[str, Any] = {"type": "result", "duration_ms": duration_ms,
                           "duration_api_ms": duration_ms, "total_cost_usd": cost,
                           "num_turns": 21,
                           "usage": {"input_tokens": 80_029, "output_tokens": 21_304,
                                     "cache_read_input_tokens": 0,
                                     "cache_creation_input_tokens": 0}}
    row.update(over)
    return row


def write_tool_trace(run_dir: Path, rows: list[dict[str, Any]]) -> Path:
    """`<run_dir>/tool_trace.jsonl` as `observe.write_trace` leaves it: the events, then the
    result event LAST (c4) — when the caller puts it there."""
    path = Path(run_dir) / "tool_trace.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return path


def run_dir(episode_dir: Path, label: str, *, cost: float | Any = 0.25,
            duration_ms: int | Any = 180_000, result: bool = True, runtime_html: bool = True,
            events: list[dict[str, Any]] | None = None) -> Path:
    """`runs/<episode_id>-<label>/` — the sibling's run dir plus its scrub sidecar
    (`_triplet_947.sibling_run_dir`), with `tool_trace.jsonl` ending in a result event and the
    `runtime.html` the run's own visualizer leaves (x11)."""
    runs = Path(episode_dir) / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    rd = T.sibling_run_dir(runs, label)
    rows = list(events or [{"type": "assistant", "message": {"content": [{"type": "text",
                                                                         "text": "hello"}]}}])
    if result:
        rows.append(result_event(cost=cost, duration_ms=duration_ms))
    write_tool_trace(rd, rows)
    if runtime_html:
        (rd / "runtime.html").write_text("<!doctype html><title>run</title>", encoding="utf-8")
    return rd


def write_timing(episode_dir: Path, steps: list[tuple[str, str, str]] | None = None, *,
                 raw: str | None = None, check: bool = True) -> Path:
    """`timing.json` in `StageClock`'s shape — `{"steps": [{step, started_at, ended_at}]}` —
    through the guarded replace lane, read back through `read_stage_timings` unless the
    scenario wants a record the reader refuses (`check=False`, or `raw=`)."""
    timing = J.mod("learning.branch.timing")
    path = timing.timing_path(Path(episode_dir))
    if raw is not None:
        plant_raw(path, raw)
        return path
    rows = [{"step": s, "started_at": a, "ended_at": b} for s, a, b in (steps or [])]
    write_guarded(path, json.dumps({"steps": rows}, indent=2) + "\n", mode="replace")
    if check:
        assert timing.read_stage_timings(episode_dir) == rows
    return path


def six_steps(*, minute: int = 0) -> list[tuple[str, str, str]]:
    """A complete six-step record, one minute per step from `10:0<minute>`."""
    out = []
    for i, step in enumerate(J.mod("learning.branch.steps").STEPS):
        m = minute + i * 2
        out.append((str(step), f"2026-09-09T10:{m:02d}:00Z", f"2026-09-09T10:{m + 1:02d}:00Z"))
    return out


def write_stamp(episode_dir: Path, *, commit: str = LESSONS_COMMIT, dirty: bool = False,
                dirty_paths: list[str] | None = None, allow_dirty: bool = False) -> Path:
    """The episode-root family stamp `provenance.json` as `cli._write_family_stamp` leaves it:
    `{agreed: {commit, dirty, dirty_path_count, dirty_paths, model, scope, unavailable},
    allow_dirty}` — a DIFFERENT shape from the per-world run stamp (fk-8/J12)."""
    paths = dirty_paths or []
    doc = {"agreed": {"commit": commit, "dirty": dirty, "dirty_path_count": len(paths),
                      "dirty_paths": paths, "model": "glm-5.2", "scope": "defender",
                      "unavailable": None},
           "allow_dirty": allow_dirty}
    path = Path(episode_dir) / "provenance.json"
    write_guarded(path, json.dumps(doc, indent=2, sort_keys=True) + "\n", mode="replace")
    return path


def write_samples(episode_dir: Path, doc: dict[str, Any] | None = None) -> Path:
    """`samples.yaml` — the questioner's reference document per staged pattern."""
    doc = doc if doc is not None else {
        "logs-system.auth-*": {"user.name": "root", "event.outcome": "success"},
        "logs-falco.alerts-*": {"falco.rule": "Adding ssh keys to authorized_keys"},
    }
    path = Path(episode_dir) / "samples.yaml"
    path.write_text(yaml.safe_dump(doc, sort_keys=True), encoding="utf-8")
    return path


def stage_names(episode_dir: Path, labels: tuple[str, ...] = (WITHHELD_WORLD, GRADED_WORLD)) -> list[dict]:
    """`staged.yaml` through the PRODUCTION writer `staging.record_staged`: one index row and one
    alias row per world, in the shape the launcher appends."""
    staging = J.mod("learning.branch.staging")
    rows = []
    for label in labels:
        token = T.world_token(label)
        for kind, name in (("index", f"wv-{token}-logs-system.auth-.inject"),
                           ("alias", f"wv-{token}-logs-system.auth-")):
            rows.append(staging.record_staged(
                Path(episode_dir), {"world": token, "name": name, "kind": kind,
                                    "derived_from": "logs-system.auth-*"}))
    return rows


def reachability(*, envelope_ran: bool = True, envelope_failed: str | None = None,
                 injected_present: int = 0, injected_retrieved: int = 0,
                 capture_reasks_faulted: int = 0, capture_addressed: bool = True,
                 reachable_by_capture: bool | None = True) -> dict[str, Any]:
    return {"envelope_ran": envelope_ran, "envelope_failed": envelope_failed,
            "injected_retrieved": injected_retrieved, "injected_present": injected_present,
            "patched_visible": False, "exclusion_matches": None,
            "exclusion_count_failed": False, "base_documents": None, "capture_replays": [],
            "capture_addressed": capture_addressed, "capture_reasks_faulted": capture_reasks_faulted,
            "reachable_by_capture": reachable_by_capture}


def review_world(role: str, label: str, *, reach: dict[str, Any] | None = None,
                 inventions: list | None = None, decision: str = "accepted") -> dict[str, Any]:
    """One `review.yaml` `worlds.<label>` block: role, world_token, consistency, reachability,
    inventions, decision — the shape the archived record carries."""
    block: dict[str, Any] = {
        "role": role, "world_token": T.world_token(label),
        "consistency": {"replayed": [], "mismatches": [], "control_mismatch_keys": [],
                        "faults": []},
        "inventions": inventions or [], "decision": decision,
    }
    if reach is not None:
        block["reachability"] = reach
    return block


# --------------------------------------------------------------------------------------
# The sample-shaped episode.
# --------------------------------------------------------------------------------------


def _world_findings_rows(withheld: bool) -> list[dict[str, Any]]:
    """Five per-draw findings for a sibling: four addressed to the defender, one to the world
    author (the sample's split)."""
    rows = [finding(subject="defender", bucket=b, claim=f"defender claim {i}",
                    root_cause=f"defender root cause {i}", topic=f"defender topic {i}",
                    anchor=f"l-00{i + 1}")
            for i, b in enumerate(("lead-set", "observability", "decision-discipline",
                                   "analyze-discipline"))]
    rows.append(finding(subject="world", bucket="story-overlay-gap",
                        claim="the overlay never reached the defender as a readable document",
                        root_cause="injected rows were present but retrieval faulted",
                        topic="injected precedent never retrieved", anchor="l-002"))
    return rows


def family_findings() -> list[dict[str, Any]]:
    return [finding(subject="world", bucket="unreachable-difference",
                    claim=f"family claim {i}", root_cause=f"family root cause {i}",
                    topic=f"family topic {i}",
                    anchor=f"worlds.{WITHHELD_WORLD}.reachability.envelope_failed")
            for i in range(3)]


def world_row(label: str, *, declared: str, withheld_reason: str | None = None,  # noqa: PLR0913 — one keyword per row field the ladder and chips read; a scenario names only the field it is about
              bucket: str | None = "decision-discipline", verdict: str = "inconclusive",
              holding_queried: bool = True, doctored: bool = True, difference_shown: bool = True,
              has_refused: bool | None = False, resolution_moved: bool = True,
              world_findings: list[dict[str, Any]] | None = None, **over: Any) -> dict[str, Any]:
    """One `judge.yaml` world row in the post-#1007 shape (every flag the chips and ladder
    name), with `has_refused` STORED (prep 2b) unless `has_refused=None` drops it."""
    row: dict[str, Any] = {
        "world": label, "declared": declared, "holding_system": "elastic",
        "holding_queried": holding_queried, "scope_discriminated": False,
        "doctored_answer_served": doctored, "resolution_moved": resolution_moved,
        "verdict": verdict, "malformed_rows": 0, "served_nothing": not holding_queried,
        "difference_shown": difference_shown, "reachable_by_capture": difference_shown or None,
        "capture_addressed": True, "capture_reasks_faulted": 0 if difference_shown else 5,
        "injected_retrieved": 0, "injected_present": 2 if difference_shown else 0,
        "withheld_reason": withheld_reason,
        "world_findings": world_findings if world_findings is not None else [],
        "mechanical_world_findings": [], "sample_unavailable": False,
        "sample_unavailable_patterns": [], "pattern": "logs-system.auth-*", "bucket": bucket,
        "agreed_without_difference": False, "completed_draws": 1,
        "spread": {bucket: 1} if bucket else {}, "malformed_replies": 0,
    }
    if has_refused is not None:
        row["has_refused"] = has_refused
    row.update(over)
    return row


def ungradable_row(label: str, *, declared: str = "malicious",
                   reason: str = "a call on 'elastic' faulted — the defender is not graded on "
                                 "a call the estate could not answer") -> dict[str, Any]:
    """The THIRD world state (c13 refuted): `ungradable: True`, its reason, no ladder flags,
    `bucket: None` — live-996's `sshpass_confirmed` row."""
    return {"world": label, "declared": declared, "ungradable": True,
            "ungradable_reason": reason, "bucket": None, "completed_draws": 0,
            "world_findings": [], "mechanical_world_findings": []}


def world_finding_queue_row(finding_id: str, text: str, *, anchor: str = "l-002",
                            topic: str = "injected precedent never retrieved") -> dict[str, Any]:
    """One episode-level `world_findings` row — the questioner-queue `FindingRow` shape (g28),
    joined to the draw by `finding_id` ONLY."""
    return {"schema_version": 1, "finding_id": finding_id, "run_id": EPISODE_ID,
            "alert_rule_key": "rule-v2-falco-authorized-keys-modification",
            "direction": "world", "subject": "world", "type": "unreachable-difference",
            "subject_anchor": anchor, "subject_topic": topic, "finding": text,
            "judge_outcome": "discard", "citations": ["investigation.md"],
            "source_run_dir": f"/runs/{EPISODE_ID}"}


def family_queue_row(draw: int, index: int, *, topic: str | None = None,
                     claim: str | None = None) -> dict[str, Any]:
    """The episode-level `world_findings` row for family finding `(family, draw, index)` —
    the record's side of the join a family draw's row needs to reach the lede (J7 ii)."""
    topic = topic if topic is not None else f"family topic {index}"
    claim = claim if claim is not None else f"family claim {index}"
    return world_finding_queue_row(f"{EPISODE_ID}/{FAMILY}/{draw}/{index}",
                                   f"{claim} — family root cause {index}",
                                   anchor=f"worlds.{WITHHELD_WORLD}.reachability.envelope_failed",
                                   topic=topic)


def sample_grade(*, withheld_findings: list[dict[str, Any]] | None = None,
                 family: bool = True) -> dict[str, Any]:
    """The sample-shaped `judge.yaml` document: two graded rows (one withheld), the control
    absent (no row), `verdict_word: undecidable`, `family_outcome: discard`, four defender rows
    enqueued, five world-author rows (two without the family's three when `family=False` —
    the record of an episode whose family call never ran), four withheld."""
    withheld_docs = _world_findings_rows(withheld=True)
    graded_docs = _world_findings_rows(withheld=False)
    prefix = f"{EPISODE_ID}"
    world_rows = ([family_queue_row(0, i) for i in range(3)] if family else []) + [
        world_finding_queue_row(f"{prefix}/{WITHHELD_WORLD}/0/4",
                                withheld_docs[4]["claim"] + " — " + withheld_docs[4]["root_cause"]),
        world_finding_queue_row(f"{prefix}/{GRADED_WORLD}/0/4",
                                graded_docs[4]["claim"] + " — " + graded_docs[4]["root_cause"]),
    ]
    return {
        "worlds": [
            world_row(WITHHELD_WORLD, declared="benign",
                      withheld_reason=SAMPLE.withheld_reason, bucket="lead-set",
                      holding_queried=False, doctored=False, difference_shown=False,
                      has_refused=None, world_findings=[withheld_docs[4]]),
            world_row(GRADED_WORLD, declared="malicious", bucket="decision-discipline",
                      has_refused=None, world_findings=[graded_docs[4]]),
        ],
        "verdict_word": "undecidable", "episode_outcome": "gradable",
        "enqueued_rows": SAMPLE.defender_enqueued, "enqueued_to": ENQUEUED_TO,
        "draws": {"configured": 1, "completed": 1},
        "knobs": {"draws": 1, "model": "kimi-k3", "effort": "medium", "payload_cap": 20000},
        "lessons_commit": LESSONS_COMMIT,
        "discard_evidence": {"review_pointer": f"{EPISODE_ID}/review.yaml#worlds.*.consistency.control_mismatch_keys"},
        "queue_malformed_rows": 0, "world_queue_malformed_rows": 0,
        "unqueueable_findings": [], "family_outcome": "discard", "family_failed_reason": None,
        "family_malformed_replies": 0, "world_enqueued_rows": len(world_rows),
        "world_enqueued_to": WORLD_ENQUEUED_TO, "world_findings": world_rows,
        "withheld_findings": withheld_findings if withheld_findings is not None else [
            {"finding": row, "world": WITHHELD_WORLD, "reason": SAMPLE.withheld_reason}
            for row in withheld_docs[:4]],
    }


def sample_manifest_worlds() -> list[dict[str, Any]]:
    return [
        T.world_doc(CONTROL, role="A", axis=None, disposition_declared="malicious", ov={}),
        T.world_doc(WITHHELD_WORLD, role="B", axis=AXIS_WITHHELD, disposition_declared="benign",
                    ov=T.overlay(elastic=T.elastic_overlay(inject=[{"_id": "i-b"}]))),
        T.world_doc(GRADED_WORLD, role="C", axis=AXIS_GRADED, disposition_declared="malicious",
                    ov=T.overlay(elastic=T.elastic_overlay(inject=[{"_id": "i-c"}]))),
    ]


def sample_manifest(**over: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {"worlds": sample_manifest_worlds(), "base_story": BASE_STORY}
    fields.update(over)
    return T.family_doc(**fields)


@dataclass
class Episode:
    """A built episode and the handles a scenario reaches for."""

    dir: Path
    tmp_path: Path

    @property
    def page(self) -> Path:
        return self.dir / PAGE_NAME

    def world(self, label: str) -> Path:
        return self.dir / "worlds" / label

    def run(self, label: str) -> Path:
        return self.dir / "runs" / f"{EPISODE_ID}-{label}"

    def record(self, name: str) -> Path:
        return self.dir / name


def sample_episode(tmp_path: Path, *, root: Path | None = None, judge: bool = True,  # noqa: PLR0913, C901 — one switch per record so a scenario about a record's absence names exactly that record
                   family_draw: bool = True, traces: bool = True, runs: bool = True,
                   timing: bool = False, stamp: bool = True, samples: bool = True,
                   staged: bool = True) -> Episode:
    """The fresh-authkeys-SHAPED episode, suite-built (F27), every record through its writer.

    Switches turn a record off for the scenarios about its absence; `timing=True` adds the
    six-step `timing.json` a post-prep launch leaves (the archives predate it, c25)."""
    manifest = sample_manifest()
    ep = J.accepted_episode(
        tmp_path, root=root, worlds=manifest["worlds"], labels=WORLDS,
        dispositions={CONTROL: "malicious", WITHHELD_WORLD: "benign", GRADED_WORLD: "malicious"},
        ledgers={CONTROL: [J.ledger_row(source="passthrough", world_label=CONTROL)],
                 WITHHELD_WORLD: [J.staged_row(WITHHELD_WORLD)],
                 GRADED_WORLD: [J.staged_row(GRADED_WORLD)]})
    # the manifest the sample carries: base story, a real axis per sibling, the control's null
    T.write_family(ep, manifest)
    # world alerts name the rule the header shows
    for label in WORLDS:
        (ep / "worlds" / label / "alert.json").write_text(json.dumps(
            {"alert_id": ALERT_ID, "rule": {"id": "v2-falco-authorized-keys-modification",
                                            "name": ALERT_RULE}}), encoding="utf-8")
        _leads(ep / "worlds" / label, label)
    withheld_docs = _world_findings_rows(withheld=True)
    graded_docs = _world_findings_rows(withheld=False)
    draw_document(ep, WITHHELD_WORLD, 0, draw_doc(findings=withheld_docs))
    draw_document(ep, GRADED_WORLD, 0, draw_doc(findings=graded_docs))
    if family_draw:
        draw_document(ep, FAMILY, 0, draw_doc(findings=family_findings(),
                                              episode_outcome="discard"))
    J.review_record(ep, worlds={
        CONTROL: review_world("A", CONTROL),
        WITHHELD_WORLD: review_world("B", WITHHELD_WORLD, reach=reachability(
            envelope_ran=False, envelope_failed=ENVELOPE_FAILED, capture_reasks_faulted=5,
            reachable_by_capture=None)),
        GRADED_WORLD: review_world("C", GRADED_WORLD, reach=reachability(
            injected_present=2, capture_reasks_faulted=2)),
    })
    if judge:
        write_judge(ep, sample_grade(family=family_draw))
    if traces:
        for agent_id, usage, ms in zip(("questioner", "questioner:b", "questioner:c"),
                                       SAMPLE.questioner_usage, SAMPLE.questioner_ms, strict=True):
            write_trace(ep, agent_id, usage=usage, duration_ms=float(ms),
                        prompt=f"questioner prompt for {agent_id}", reply=f"reply of {agent_id}")
        labels = ((FAMILY, 0), (WITHHELD_WORLD, 0), (GRADED_WORLD, 0))
        for (label, n), usage, ms in zip(labels, SAMPLE.judge_usage, SAMPLE.judge_ms, strict=True):
            agent_id = f"judge:{label}:{n}"
            write_trace(ep, agent_id, usage=usage, duration_ms=float(ms),
                        prompt=f"judge prompt for {label}", reply=f"judge reply for {label}")
            write_framed(ep, agent_id, prompt=f"framed prompt for {label}",
                         reply=f"framed reply for {label}")
    if runs:
        for label in WORLDS:
            run_dir(ep, label, cost=SAMPLE.run_cost[label], duration_ms=SAMPLE.run_ms[label])
    if timing:
        write_timing(ep, six_steps())
    if stamp:
        write_stamp(ep)
    if samples:
        write_samples(ep)
    if staged:
        stage_names(ep)
    return Episode(ep, tmp_path)


def _leads(world_dir: Path, label: str) -> None:
    """The world's leads in the surface's shape: `gather_raw/<lead>.lead.json` (the goal), the
    queries table, and `gather_summaries/<lead>.md`. `l-000` is the PRE-BRANCH alert fetch —
    present in the table and the lead files, never in a summary or a resolution row — so the
    judge's leads-view set (`referenced_leads ∪ summary stems`, x12) excludes it."""
    from defender._run_paths import RunPaths

    leads = ["l-000", "l-001", "l-002", "l-00c"]
    rows = []
    for i, lid in enumerate(leads):
        rows.append({"lead_id": lid, "seq": i, "system": "elastic", "verb": "esql",
                     "query_id": f"q-{lid}", "params": {"index": "logs-*", "lead": lid},
                     "raw_command": f"elastic esql lead={lid}",
                     "payload_path": f"gather_raw/{lid}/0.json", "payload_digest": f"digest-{lid}",
                     "exit_code": 0, "error_class": None})
        (world_dir / "gather_raw" / f"{lid}.lead.json").write_text(
            json.dumps({"lead_id": lid, "goal": f"goal of {lid} in {label}"}), encoding="utf-8")
    RunPaths(world_dir).executed_queries.write_text(
        "".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    summaries = world_dir / "gather_summaries"
    summaries.mkdir(parents=True, exist_ok=True)
    for lid in ("l-001", "l-002", "l-00c"):
        (summaries / f"{lid}.md").write_text(f"summary of {lid} for {label}\n", encoding="utf-8")


def copy_episode(ep: Episode, dest: Path) -> Episode:
    """A whole-tree copy under another root AND another directory name — the O6 fixture
    (correction 4: the page takes the episode id from the manifest, never the directory)."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(ep.dir, dest, symlinks=True)
    return Episode(dest, ep.tmp_path)


# --------------------------------------------------------------------------------------
# Driving the page.
# --------------------------------------------------------------------------------------


def page_module():
    return mod(PAGE_MODULE)


def render(ep: Episode | Path, *, module: Any = None) -> Page:
    """`render_episode(episode_dir)` — the real entry point — then the page it wrote, parsed.
    `module` is the page module a test file resolved through its own `visualize_episode()`
    helper (so the static reach check sees the target from the test); default: imported here."""
    d = ep.dir if isinstance(ep, Episode) else Path(ep)
    target = module if module is not None else page_module()
    out = target.render_episode(d)
    assert Path(out) == d / PAGE_NAME, f"render_episode returned {out!r}"
    return read_page(d)


def read_page(ep: Episode | Path) -> Page:
    d = ep.dir if isinstance(ep, Episode) else Path(ep)
    page = d / PAGE_NAME
    assert page.is_file(), f"no {PAGE_NAME} under {d}"
    return Page.parse(page.read_text(encoding="utf-8"))


def cli(argv: list[str], capsys, *, module: Any = None) -> tuple[int, str, str]:
    """`visualize_episode.main(argv)` with its stdout / stderr captured."""
    target = module if module is not None else page_module()
    rc = target.main(argv)
    out = capsys.readouterr()
    return rc, out.out, out.err


def snapshot(tree: Path) -> dict[str, tuple[int, int]]:
    """Every entry under `tree` with its (size, mtime_ns) — what a render may and may not touch."""
    out = {}
    for root, dirs, files in os.walk(tree):
        for name in dirs + files:
            p = Path(root) / name
            st = p.lstat()
            out[str(p.relative_to(tree))] = (st.st_size, st.st_mtime_ns)
    return out


class Rescue:
    """Feed a planted FIFO from a background thread AFTER `after` seconds, so a reader that
    follows it into a blocking `open` is released with a sentinel instead of hanging the suite
    (p2: a FIFO at `investigation.md` blocks `read_world_facts` indefinitely today).

    The two observables a test reads off this: whether the sentinel reached the page (the
    target's content never appears) and whether the call took longer than `after` (the render
    never blocks) — a screened reader returns in milliseconds and the writer thread finds no
    reader to feed."""

    SENTINEL = "FIFO-SENTINEL-CONTENT-NEVER-ON-THE-PAGE"

    def __init__(self, fifo: Path, *, after: float = 2.0) -> None:
        self.fifo = Path(fifo)
        self.after = after
        self.fed = False
        self._cancel = threading.Event()
        self._thread = threading.Thread(target=self._feed, daemon=True)

    def _feed(self) -> None:
        # Waited on the cancel event, not a bare `sleep`: `__exit__` sets it the moment the
        # guarded call inside the `with` block has already RETURNED — and reaching `__exit__`
        # at all already proves that call did not block, so there is nothing left to rescue.
        # Without this, a correctly-screened reader still paid the full `after` seconds on
        # every run (the wait was unconditional), which is the tax `_feed`'s own docstring says
        # a screened reader should never owe.
        if self._cancel.wait(self.after):
            return
        try:
            fd = os.open(self.fifo, os.O_WRONLY | os.O_NONBLOCK)
        except OSError:
            return          # no reader blocked on it — the screened arm
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(self.SENTINEL + "\n")
        self.fed = True

    def __enter__(self) -> Rescue:
        self._thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._cancel.set()
        self._thread.join(timeout=self.after + 5)


#: The page module's file name — what `when_inside` looks for on the stack.
PAGE_FILE = "visualize_episode.py"


@contextlib.contextmanager
def when_inside(act: Callable[[], Any], *, marker: str = PAGE_FILE, tick: float = 0.001,
                budget: float = 60.0) -> Iterator[dict[str, Any]]:
    """Run `act()` from a signal handler the first time a frame of `marker` is on the main
    thread's stack — an interrupt, a rewrite or a raise landing INSIDE the render, with no seam
    on the render itself (d40: the renderer is a plain call).

    The interval timer re-arms every `tick` until the frame is seen or `budget` runs out, so
    the observation is "what happened when the fault landed mid-render", not "what happened at
    some unrelated moment". The dict yielded reports `hit` (the frame was seen) so a test can
    fail for the right reason when the render never ran or finished under a tick."""
    seen = {"hit": False, "count": 0}
    started = time.monotonic()

    def handler(_signum: int, frame: Any) -> None:
        seen["count"] += 1
        f = frame
        while f is not None:
            if f.f_code.co_filename.endswith(marker):
                seen["hit"] = True
                act()
                return
            f = f.f_back
        if time.monotonic() - started < budget:
            signal.setitimer(signal.ITIMER_REAL, tick)

    previous = signal.signal(signal.SIGALRM, handler)
    signal.setitimer(signal.ITIMER_REAL, tick)
    try:
        yield seen
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def raise_now(exc: BaseException) -> Callable[[], None]:
    def _raise() -> None:
        raise exc
    return _raise


def plant_fifo(path: Path) -> Path:
    plant_raw(path, b"")
    path.unlink()
    os.mkfifo(path)
    return path


def plant_link(path: Path, target: Path) -> Path:
    if path.is_symlink() or path.exists():
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.symlink_to(target)
    return path


# --------------------------------------------------------------------------------------
# The page, parsed — assertions sit on observable surfaces (ids, hrefs, text), never internals.
# --------------------------------------------------------------------------------------


@dataclass
class Node:
    tag: str
    attrs: dict[str, str]
    parent: Node | None
    children: list[Node] = field(default_factory=list)
    #: Text pieces and child nodes in document order — what `text()` walks.
    order: list[Any] = field(default_factory=list)

    @property
    def id(self) -> str | None:
        return self.attrs.get("id")

    @property
    def classes(self) -> set[str]:
        return set((self.attrs.get("class") or "").split())

    def text(self) -> str:
        """The element's rendered text (descendants included, entities decoded), whitespace
        collapsed to single spaces."""
        parts: list[str] = []

        def walk(n: Node) -> None:
            for piece in n.order:
                if isinstance(piece, str):
                    parts.append(piece)
                else:
                    walk(piece)
        walk(self)
        return " ".join("".join(parts).split())

    def descendants(self) -> list[Node]:
        out: list[Node] = []
        for c in self.children:
            out.append(c)
            out.extend(c.descendants())
        return out

    def find_all(self, tag: str | None = None, *, cls: str | None = None) -> list[Node]:
        return [n for n in self.descendants()
                if (tag is None or n.tag == tag) and (cls is None or cls in n.classes)]

    def ancestor_with_id(self, prefix: str) -> Node | None:
        n = self.parent
        while n is not None:
            if n.id and n.id.startswith(prefix):
                return n
            n = n.parent
        return None


_VOID = {"br", "hr", "img", "input", "meta", "link", "source", "wbr", "col", "area", "base"}


class _Builder(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.root = Node("document", {}, None)
        self.cur = self.root
        self.raw_texts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        node = Node(tag, {k: (v if v is not None else "") for k, v in attrs}, self.cur)
        self.cur.children.append(node)
        self.cur.order.append(node)
        if tag not in _VOID:
            self.cur = node

    def handle_endtag(self, tag: str) -> None:
        n: Node | None = self.cur
        while n is not None and n.tag != tag:
            n = n.parent
        if n is not None and n.parent is not None:
            self.cur = n.parent

    def handle_data(self, data: str) -> None:
        self.cur.order.append(data)
        if self.cur.tag not in ("style", "script"):
            self.raw_texts.append(data)


@dataclass
class Page:
    """`learning.html`, parsed: the bytes, the id map, the hrefs and the text."""

    raw: str
    root: Node
    by_id: dict[str, Node]
    ids: list[str]
    #: Every `id` value, with duplicates kept — the uniqueness assertions read this.
    all_ids: list[str]
    hrefs: list[str]
    #: The rendered TEXT (script/style excluded, entities decoded) — a planted `<script>` that
    #: was escaped shows up here as text and in `raw` only as `&lt;script&gt;`.
    text: str

    @classmethod
    def parse(cls, raw: str) -> Page:
        b = _Builder()
        b.feed(raw)
        by_id: dict[str, Node] = {}
        all_ids: list[str] = []
        hrefs: list[str] = []
        for n in b.root.descendants():
            if n.id is not None:
                all_ids.append(n.id)
                by_id.setdefault(n.id, n)
            if n.tag == "a" and "href" in n.attrs:
                hrefs.append(n.attrs["href"])
        text = " ".join("".join(b.raw_texts).split())
        return cls(raw, b.root, by_id, list(by_id), all_ids, hrefs, text)

    def __contains__(self, needle: str) -> bool:
        return needle in self.text

    def section(self, anchor: str) -> Node:
        assert anchor in self.by_id, f"no element with id={anchor!r} on the page (ids: {self.ids[:40]}…)"
        return self.by_id[anchor]

    def text_of(self, anchor: str) -> str:
        return self.section(anchor).text()

    def ids_with(self, prefix: str) -> list[str]:
        return [i for i in self.ids if i.startswith(prefix)]

    def elements(self, tag: str | None = None, *, cls: str | None = None) -> list[Node]:
        return self.root.find_all(tag, cls=cls)

    def group_of(self, row_id: str) -> Node:
        """The `fg-<n>` group a finding row sits in — a row in no group is the test's failure."""
        group = self.section(row_id).ancestor_with_id("fg-")
        assert group is not None, f"{row_id} sits in no fg-<n> group"
        return group

    def one(self, tag: str | None = None, *, cls: str | None = None) -> Node:
        """Exactly one element of `tag` / class `cls` — a missing or repeated one is the
        test's own failure, not an `IndexError`."""
        found = self.elements(tag, cls=cls)
        assert len(found) == 1, f"expected one <{tag or '*'} class={cls!r}>, found {len(found)}"
        return found[0]

    def anchors_in(self, anchor: str) -> list[str]:
        return [n.attrs["href"] for n in self.section(anchor).find_all("a") if "href" in n.attrs]


def escaped(s: str) -> str:
    """What `esc` / `esc_untrusted` makes of `s` — the bytes an escaped occurrence carries."""
    return html.escape(s)


__all__ = [
    "AXIS_GRADED", "AXIS_WITHHELD", "ALERT_ID", "ALERT_RULE", "BASE_STORY", "CONTROL",
    "ENQUEUED_TO", "ENVELOPE_FAILED", "EPISODE_ID", "EPISODE_TOKEN", "FAMILY", "GRADED_WORLD",
    "LESSONS_COMMIT", "MODEL", "PAGE_MODULE", "PAGE_NAME", "SAMPLE", "WITHHELD_WORLD",
    "WORLD_ENQUEUED_TO", "WORLDS",
    "Episode", "Node", "Page", "Rescue", "PAGE_FILE", "raise_now", "when_inside",
    "cli", "copy_episode", "draw_doc", "draw_document", "escaped", "family_findings",
    "finding", "mod", "page_module", "plant_fifo", "plant_link", "plant_raw", "reachability",
    "read_page", "render", "result_event", "review_world", "run_dir", "sample_episode",
    "family_queue_row", "sample_grade", "sample_manifest", "sample_manifest_worlds", "six_steps", "snapshot",
    "stage_names", "sym", "trace_rows", "trace_stem", "ungradable_row", "world_finding_queue_row",
    "world_row", "write_framed", "write_judge", "write_samples", "write_stamp", "write_timing",
    "write_tool_trace", "write_trace",
]
