"""M2 — what the controller actually PUTs into the stack (O6 + O4 in the body).

These assert on the payload the fake exec seam captured, not on a return value.
The shapes are the ones the design proved on the live pipeline with `_simulate`:

  * a *bare* rename stamps `event.kind: pipeline_error` + `error.message` onto
    the field-less majority of auth lines (a sudo line has no `source.port`),
    and those error fields land in the agent-visible auth index. So
    `ignore_missing: true` **and** `ignore_failure: true` are mandatory on every
    schema-drift processor, for rename and remove alike.
  * a drop condition must be null-guarded on `ctx.message != null` or the same
    field-less line throws.
  * no `tag` / `description` on any processor: those are harness-named strings
    sitting in cluster state next to the agent's telemetry.
"""
from __future__ import annotations

import re

import pytest
from _fakes import FakeExecSeam, write_profile

from chaos import ctl

AUTH_PIPELINE = "logs-system.auth@custom"
SYSLOG_PIPELINE = "logs-system.syslog@custom"


def _pipeline_put(execer: FakeExecSeam, pipeline: str) -> dict:
    puts = execer.calls_for(target="es", method="PUT", path_contains=pipeline)
    assert len(puts) == 1, f"expected one PUT of {pipeline}, got {execer.calls_for(target='es')}"
    call = puts[0]
    assert call["path"].startswith("/_ingest/pipeline/"), call["path"]
    assert call["path"].endswith(pipeline), call["path"]
    return call["body"]


def _sole_processor(body: dict, kind: str) -> dict:
    processors = body["processors"]
    matching = [p[kind] for p in processors if kind in p]
    assert len(matching) == 1, f"expected one {kind} processor, got {processors}"
    return matching[0]


def _activate(profile_id, profiles_dir, rules_dir, ledger_dir, execer, seed=42):
    return ctl.activate(
        profile_id,
        seed=seed,
        execer=execer,
        profiles_dir=profiles_dir,
        rules_dir=rules_dir,
        ledger_dir=ledger_dir,
    )


@pytest.mark.parametrize(
    ("profile_id", "params", "kind"),
    [
        ("drift-rename", {"rename": {"from": "user.name", "to": "user.id"}}, "rename"),
        ("drift-remove", {"remove": "source.port"}, "remove"),
    ],
)
def test_schema_drift_processor_is_always_ignore_missing_and_ignore_failure(
    profiles_dir, rules_dir, ledger_dir, profile_id, params, kind
):
    write_profile(profiles_dir, profile_id, "schema-drift", params)
    execer = FakeExecSeam()
    _activate(profile_id, profiles_dir, rules_dir, ledger_dir, execer)

    processor = _sole_processor(_pipeline_put(execer, AUTH_PIPELINE), kind)
    assert processor["ignore_missing"] is True
    assert processor["ignore_failure"] is True
    # A harness-named string in cluster state is a tell (O6).
    assert "tag" not in processor
    assert "description" not in processor


def test_schema_drift_rename_carries_the_profiles_from_and_to(profiles_dir, rules_dir, ledger_dir):
    write_profile(
        profiles_dir, "drift-rename2", "schema-drift", {"rename": {"from": "user.name", "to": "user.id"}}
    )
    execer = FakeExecSeam()
    _activate("drift-rename2", profiles_dir, rules_dir, ledger_dir, execer)

    processor = _sole_processor(_pipeline_put(execer, AUTH_PIPELINE), "rename")
    assert processor["field"] == "user.name"
    assert processor["target_field"] == "user.id"


def test_schema_drift_remove_carries_the_profiles_field(profiles_dir, rules_dir, ledger_dir):
    write_profile(profiles_dir, "drift-remove2", "schema-drift", {"remove": "source.port"})
    execer = FakeExecSeam()
    _activate("drift-remove2", profiles_dir, rules_dir, ledger_dir, execer)

    processor = _sole_processor(_pipeline_put(execer, AUTH_PIPELINE), "remove")
    assert processor["field"] == "source.port"


def test_data_drop_condition_is_null_guarded_and_salted(profiles_dir, rules_dir, ledger_dir):
    write_profile(
        profiles_dir, "drop-syslog", "data-drop", {"target_stream": "logs-system.syslog-*", "rate": 30}
    )
    execer = FakeExecSeam()
    _activate("drop-syslog", profiles_dir, rules_dir, ledger_dir, execer, seed=7)

    drop = _sole_processor(_pipeline_put(execer, SYSLOG_PIPELINE), "drop")
    condition = drop["if"]
    # Field-less lines must survive untouched — a throw here becomes a
    # pipeline_error doc in an index the agent reads.
    assert condition.startswith("ctx.message != null")
    assert "(ctx.message + '7')" in condition
    assert "& 0x7fffffff" in condition
    assert "% 100 < 30" in condition
    assert "tag" not in drop
    assert "description" not in drop


def test_data_drop_never_touches_the_auth_pipeline(profiles_dir, rules_dir, ledger_dir):
    write_profile(
        profiles_dir, "drop-syslog2", "data-drop", {"target_stream": "logs-system.syslog-*", "rate": 30}
    )
    execer = FakeExecSeam()
    _activate("drop-syslog2", profiles_dir, rules_dir, ledger_dir, execer)
    assert execer.calls_for(path_contains=AUTH_PIPELINE) == []


def test_no_captured_payload_names_the_harness(profiles_dir, rules_dir, ledger_dir):
    """O6 by construction: nothing the controller writes into the stack may
    carry a word that identifies it as a test harness."""
    write_profile(
        profiles_dir, "drift-rename3", "schema-drift", {"rename": {"from": "user.name", "to": "user.id"}}
    )
    execer = FakeExecSeam()
    _activate("drift-rename3", profiles_dir, rules_dir, ledger_dir, execer)

    blob = repr(execer.calls).lower()
    # Word-boundary matched: "default" is a legitimate word in a pipeline body.
    for marker in ("chaos", "fault", "inject", "injected", "harness", "defender"):
        assert not re.search(rf"\b{marker}\b", blob), f"{marker!r} leaked into a payload: {blob}"
