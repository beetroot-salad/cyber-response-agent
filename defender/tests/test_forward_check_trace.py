"""The R2 trace-sink demands for the in-process forward-check tool (#558).

In-process, ``os.getpid()`` no longer varies per check (the four curators fan their checks
inside ONE spawn), so the pre-port trace name — ``{error_prefix}.{lesson_stem}.{pid}.trace.jsonl``
— collides for two checks of the same lesson stem in one source bundle (the same lesson in both
directions). The fix keys the name on a per-check COUNTER. ``RequestLogger`` opens its file in
truncate mode (``path.open("w")``), so a shared name would silently clobber one check's log.

These tests drive the REAL transport (``_run_verify_pydantic`` with a ``FunctionModel`` injected
via ``make_model``), so a genuine ``RequestLogger`` writes to disk — a FAKED transport writes no
trace and the uniqueness demand would pass vacuously. The env check is model-free and writes NO
trace (m2 — the negative control shape). The tool/checks target module does not exist yet; the
module-top import is the expected collection-time red.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart  # noqa: E402
from pydantic_ai.models import override_allow_model_requests  # noqa: E402

from defender.learning.author.curator_engine import (  # noqa: E402
    CuratorDeps,
    _run_curator_pydantic,
    run_curator_stage,
)
from defender.learning.author.verify_forward.engine import _run_verify_pydantic  # noqa: E402
from defender.tests._engine_helpers import fake_model as _fake_model  # noqa: E402

from defender.learning.author.verify_forward.checks import (  # noqa: E402
    ENV_CHECK,
    FINDINGS_CHECK,
)
from defender.learning.author.verify_forward.tool import (  # noqa: E402
    Pair,
    run_forward_check,
)

_AUTHOR_RESULT_OK = (
    'AUTHOR_RESULT: {"committed": [], "consumed_skip": [], "commit_message": "noop"}'
)




def _verifier(text: str, *, delay: float = 0.0):
    """A verify-model fn: an optional (thread-blocking) delay, then a scripted verdict. The
    delay forces two concurrent checks to overlap so the interleaving is genuine."""
    def fn(messages, info):
        if delay:
            time.sleep(delay)
        return ModelResponse(parts=[TextPart(content=text)])
    return fn




def _scene(tmp_path: Path):
    repo = tmp_path / "wt"
    corpus = repo / "defender" / "lessons"
    corpus.mkdir(parents=True)
    runs = tmp_path / "state" / "runs"
    runs.mkdir(parents=True)
    pending = tmp_path / "state" / "_pending" / "findings.jsonl"
    pending.parent.mkdir(parents=True)
    pending.write_text("")
    curdir = tmp_path / "state" / "_pending"
    return SimpleNamespace(
        tmp=tmp_path, repo=repo, corpus=corpus, runs=runs, pending=pending, curdir=curdir,
    )


def _bundle(scene, run_id: str, *, disposition: str = "malicious") -> Path:
    d = scene.runs / run_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "investigation.md").write_text(f"TRANSCRIPT-for-{run_id}\n")
    (d / "source_refs.yaml").write_text(f"normalized_disposition: {disposition}\n")
    return d


def _deps(scene, *, run_verify, check=None, queued=(), corpus=None, runs=None, pending=None):
    return CuratorDeps.for_run(
        scene.curdir, scene.repo, corpus if corpus is not None else scene.corpus,
        check=check if check is not None else FINDINGS_CHECK,
        runs_dir=runs if runs is not None else scene.runs,
        pending=pending if pending is not None else scene.pending,
        queued_ids=frozenset(queued), run_verify=run_verify,
    )


def _counts(out: str) -> tuple[int, int, int]:
    import re
    m = re.search(r"BATCH:\s*n_good=(\d+)\s+n_bad=(\d+)\s+n_error=(\d+)", out)
    assert m, f"no BATCH summary in output:\n{out}"
    return tuple(int(x) for x in m.groups())  # type: ignore[return-value]




def test_d11_trace_names_distinct_per_check(tmp_path):
    """Two concurrent checks of the same lesson stem in one source bundle — the same lesson in
    both directions — write to distinct trace files, under a genuine interleaving, and both
    files hold that check's own real content."""
    scene = _scene(tmp_path)
    (scene.corpus / "samelesson.md").write_text("---\nname: samelesson\n---\nlesson body\n")
    src = _bundle(scene, "run-X", disposition="malicious")

    lock = threading.Lock()
    inflight = [0]
    peak = [0]

    def _transport(**kw):
        with lock:
            inflight[0] += 1
            peak[0] = max(peak[0], inflight[0])
        try:
            return _run_verify_pydantic(**kw, make_model=_fake_model(_verifier("VERDICT: GOOD", delay=0.05)))
        finally:
            with lock:
                inflight[0] -= 1

    deps = _deps(scene, run_verify=_transport, queued={"run-X"})
    pairs = [
        Pair("defender/lessons/samelesson.md", "run-X", "adversarial"),
        Pair("defender/lessons/samelesson.md", "run-X", "benign"),
    ]
    with override_allow_model_requests(False):
        out = asyncio.run(run_forward_check(deps, pairs))
    assert _counts(out) == (2, 0, 0)

    traces = sorted(src.glob("*.trace.jsonl"))
    assert len(traces) == 2, f"same-stem checks did not write DISTINCT trace files: {traces}"
    contents = [t.read_text() for t in traces]
    assert all(c.strip() for c in contents)
    def carries(disposition: str, content: str) -> bool:
        return bool(re.search(
            rf"<run-(?P<salt>[0-9a-f]+)-case_ground_truth_disposition>\\n{disposition}\\n</run-(?P=salt)-case_ground_truth_disposition>",
            content,
        ))

    assert sum(carries("malicious", content) for content in contents) == 1
    assert sum(carries("benign", content) for content in contents) == 1
    assert peak[0] >= 2, "the two same-stem checks did not genuinely interleave"




def test_d12_curator_trace_in_a_separate_root(tmp_path):
    """The curator spawn's own trace and the nested checks' traces land in different
    directories, so no nested check can truncate the curator's trace."""
    scene = _scene(tmp_path)
    (scene.corpus / "l.md").write_text("---\nname: l\n---\nbody\n")
    src = _bundle(scene, "run-X")

    curator_fn = _make_curator_fn([
        {"lesson_path": "defender/lessons/l.md", "source_id": "run-X", "direction": "adversarial"},
    ])

    def _transport(**kw):
        return _run_verify_pydantic(**kw, make_model=_fake_model(_verifier("VERDICT: GOOD")))

    prompt = scene.tmp / "curator.md"
    prompt.write_text("Curate. Emit AUTHOR_RESULT when done.\n")
    with override_allow_model_requests(False):
        run_curator_stage(
            system_prompt_file=prompt, batch_id="batch-A", user_prompt="u",
            corpus_dir=scene.corpus, check=FINDINGS_CHECK,
            runs_dir=scene.runs, pending=scene.pending, queued_ids=frozenset({"run-X"}),
            repo_root=scene.repo, learning_run_dir=scene.curdir,
            log=lambda *a, **k: None, model="glm-5.2", effort="low",
            request_limit=8, timeout=180,
            source_key=lambda model, label=None: None,
            run_author=lambda **kw: _run_curator_pydantic(**kw, make_model=_fake_model(curator_fn)),
            run_verify=_transport,
        )

    curator_traces = list(scene.curdir.glob("*.trace.jsonl"))
    assert curator_traces, "the curator spawn wrote no trace in its learning_run_dir"
    nested_traces = list(src.glob("*.trace.jsonl"))
    assert nested_traces, "the nested check wrote no trace in the source bundle"
    assert scene.curdir.resolve() != src.resolve()
    assert any(t.read_text().strip() for t in curator_traces)


def _make_curator_fn(pairs_args):
    state = {"i": 0}

    def fn(messages, info):
        i = state["i"]
        state["i"] = i + 1
        if i == 0:
            return ModelResponse(parts=[ToolCallPart(tool_name="forward_check",
                                                     args={"pairs": pairs_args})])
        return ModelResponse(parts=[TextPart(content=_AUTHOR_RESULT_OK)])
    return fn




def test_m2_env_checks_write_no_trace(tmp_path):
    """The deterministic environment check runs no model and creates no trace file in the
    source bundle, so the trace-uniqueness fix targets the two model-backed checks only."""
    scene = _scene(tmp_path)
    env_corpus = scene.repo / "defender" / "lessons-environment"
    env_corpus.mkdir(parents=True)
    src = scene.runs / "run-E"
    src.mkdir(parents=True)
    (src / "investigation.md").write_text(
        "```invlang\n:V prologue.vertices [id|type|class|ident|attrs?]\n"
        "v-001|process|process:nc|nc[1]|\n```\n"
    )
    scene.pending.write_text(json.dumps(
        {"observation_id": "obs-1", "alert_rule_key": "rule-Z", "source_run_dir": "run-E"}
    ) + "\n")

    calls: list = []

    def _transport(**kw):
        calls.append(kw)
        return "VERDICT: GOOD"

    deps = _deps(scene, run_verify=_transport, check=ENV_CHECK, corpus=env_corpus, queued={"obs-1"})
    asyncio.run(run_forward_check(deps, [Pair("defender/lessons-environment/x.md", "obs-1")]))
    assert calls == []
    assert not list(src.glob("*.trace.jsonl"))

    (scene.corpus / "m.md").write_text("---\nname: m\n---\nbody\n")
    src2 = _bundle(scene, "run-M")

    def _real(**kw):
        return _run_verify_pydantic(**kw, make_model=_fake_model(_verifier("VERDICT: GOOD")))

    deps2 = _deps(scene, run_verify=_real, check=FINDINGS_CHECK, queued={"run-M"})
    with override_allow_model_requests(False):
        asyncio.run(run_forward_check(deps2, [Pair("defender/lessons/m.md", "run-M", "adversarial")]))
    assert list(src2.glob("*.trace.jsonl")), "a model-backed check wrote no trace (control failed)"




def _fd_count() -> int:
    return len(os.listdir("/proc/self/fd"))


def test_m13_trace_handle_closed_when_a_check_raises(tmp_path):
    """A check that raises still closes its trace file handle, so a batch of raising checks
    leaks no file descriptors."""
    scene = _scene(tmp_path)
    rids = [f"run-{i}" for i in range(10)]
    for r in rids:
        (scene.corpus / f"l-{r}.md").write_text(f"---\nname: l-{r}\n---\nbody\n")
        _bundle(scene, r)

    def _transport(**kw):
        return _run_verify_pydantic(**kw, make_model=_fake_model(_verifier("")))

    pairs = [Pair(f"defender/lessons/l-{r}.md", r, "adversarial") for r in rids]
    deps = _deps(scene, run_verify=_transport, queued=set(rids))

    before = _fd_count()
    with override_allow_model_requests(False):
        out = asyncio.run(run_forward_check(deps, pairs))
    after = _fd_count()

    assert _counts(out) == (0, 0, 10)
    assert after - before <= 2, f"leaked file descriptors: {before} -> {after}"
    written = sum(1 for r in rids if list((scene.runs / r).glob("*.trace.jsonl")))
    assert written == 10
