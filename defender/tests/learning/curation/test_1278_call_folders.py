"""#1278 A1 sketch: each curator call runs in a private folder of its own, holding only its trace.

The folder is reached through `defender.learning.call_folders.call_folder(tenant, batch_id, stage,
call, make=...)` (sketch seam). The binding and the read gate are the real ones (`CuratorDeps.for_run`,
`permission.decide_read`); the model is a scripted FunctionModel, so the trace is the stage's own.
"""
from __future__ import annotations

import importlib
import json
import logging
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.models import override_allow_model_requests  # noqa: E402

from defender.learning.author.curator_engine import CuratorDeps, _run_curator_pydantic, run_curator_stage  # noqa: E402
from defender.tests.support.learning.core._stage_args import as_curator_stage_args  # noqa: E402
from defender.tests.support.learning.curation._curator_691_harness import read_decision  # noqa: E402
from defender.tests.support.runtime.engine._engine_helpers import fake_model, replay_once  # noqa: E402
from defender.tests.support.shared._fixture_uuid import fixture_uuid  # noqa: E402
from defender.tests.support.shared._locations_1210 import location_path  # noqa: E402
from defender.tests.support.tenancy import _tenants1106 as tenants  # noqa: E402

TENANT = fixture_uuid("tenant:1278-a1")
_RESULT = 'AUTHOR_RESULT: {"committed": [], "consumed_skip": [], "commit_message": "noop"}'


def _folders():
    return importlib.import_module("defender.learning.call_folders")


def _tenant(tmp_path):
    root = tmp_path / "data"
    tenants.place_tenant(root, TENANT)
    return tenants.accept(root, TENANT)


def _draft(tmp_path) -> tuple[Path, Path]:
    """A batch draft's `stage/` and its lessons corpus, holding one lesson."""
    stage = tmp_path / "drafts" / "b-1278" / "stage"
    corpus = stage / "agent" / "lessons"
    corpus.mkdir(parents=True)
    (corpus / "seed.md").write_text("---\nsource_finding_ids: []\n---\n\nseed\n", encoding="utf-8")
    return stage, corpus


def test_o8_a_curator_call_cannot_read_learning_state_or_another_calls_folder(tmp_path):
    """Bound over its call folder, the curator is denied today's learning state and a sibling call's trace; its corpus reads. (O8, P7)"""
    tenant = _tenant(tmp_path)
    folders = _folders()
    mine = folders.call_folder(tenant, "b-1278", "curator", 1, make=True)
    other = folders.call_folder(tenant, "b-1278", "curator", 2, make=True)
    tenant_root = Path(location_path(tenant.tenant_root))
    learning = tenant_root / "learning"
    for folder in (mine, other):
        assert not folder.resolve().is_relative_to(learning.resolve()), folder
        assert not folder.resolve().is_relative_to((tenant_root / "drafts").resolve()), folder
    assert mine != other
    queue = learning / "_pending" / "findings.jsonl"
    queue.parent.mkdir(parents=True, exist_ok=True)
    queue.write_text(json.dumps({"finding_id": "f1"}) + "\n", encoding="utf-8")
    sibling_trace = other / "wire_logs" / "curator.jsonl"
    sibling_trace.parent.mkdir(parents=True)
    sibling_trace.write_text("{}\n", encoding="utf-8")
    stage, corpus = _draft(tmp_path)

    deps = CuratorDeps.for_run(mine, stage, corpus, box=None)

    assert read_decision(deps, str(corpus / "seed.md")).allow, "control: the curator reads its corpus"
    assert not read_decision(deps, str(queue)).allow
    assert not read_decision(deps, str(sibling_trace)).allow


def test_o9_a_curator_calls_trace_is_kept_in_its_call_folder_and_found_by_its_key(tmp_path):
    """A call that reached the model leaves its trace in the folder its (tenant, batch, stage, call) names. (O9)"""
    tenant = _tenant(tmp_path)
    folders = _folders()
    folder = folders.call_folder(tenant, "b-1278", "curator", 1, make=True)
    stage, corpus = _draft(tmp_path)
    prompt = tmp_path / "curator.md"
    prompt.write_text("Curate the corpus. Emit AUTHOR_RESULT when done.\n", encoding="utf-8")
    args = as_curator_stage_args(dict(
        system_prompt_file=prompt, batch_id="b-1278", user_prompt="u", corpus_dir=corpus, repo_root=stage,
        learning_run_dir=folder, model="glm-5.3", effort="low", request_limit=5, timeout=60,
        log=logging.getLogger("defender.test"), source_key=lambda model, label=None: None,
        run_author=lambda wiring, ctx, **kw: _run_curator_pydantic(
            wiring, ctx, **kw, make_model=fake_model(replay_once(_RESULT)))))

    with override_allow_model_requests(False):
        run_curator_stage(**args)

    found = folders.call_folder(tenant, "b-1278", "curator", 1, make=False)
    assert found == folder
    traces = [p for p in found.rglob("*") if p.is_file()]
    assert traces, "no trace kept in the call folder"
    assert any(_RESULT.split(":")[0] in p.read_text(encoding="utf-8") for p in traces), traces
