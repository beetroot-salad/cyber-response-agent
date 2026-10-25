"""#1108 P4 slice S-B — O2 end to end: a run's model sees its own tenant's knowledge at one
revision on every surface, all from the run copy.

Entry: `run.main` over the REAL driver with replay models (`_replay_harness.Turn` scripts via
`investigate_as_handed`), production's lifecycle and production's unsandboxed box (the replay
harness's mode), the real `materialize`, and the `publish=` seam reporting `fresh`. The tenant
is S0's fixture tenant published for real; a second tenant shares the data root.

Each scenario advances `current` (a merge, published for real) at the model's FIRST request —
after the run copied its export, before any read — so every surface below must answer from the
seeded revision (`SEEDED_MARK`), never the merge (`MERGED_MARK`) nor the clone's working tree.

Surfaces covered here: typed read, bash `cat`, bash `defender-lessons`, the opening message
(orient's lessons section over the real shim, whose environment names the copy), the gather dispatch prompt's descriptor index, and the read
gate (own copy admitted; the other tenant's export, our own clone and our own export refused).
`list_verbs` messages are O-TEXT's (slice S-A); the tacit adapter is reported as uncovered.
"""
from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any

import pytest

from defender.tests.e2e import _replay_harness as R
from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B
from defender.tests.tenancy.tenant_1108_p4._support import (
    OTHER_LESSON,
    current_commit,
    export_dir,
    second_tenant,
)

pytestmark = pytest.mark.e2e

LESSON_IN_BOX = f"/agent/{B.LESSON_REL}"
#: The fixture system skill's description (frontmatter), which the descriptor index shows.
FIXTURE_CMDB_DESCRIPTION = "Fixture CMDB reference"
#: The lesson whose `source_signature` the alert's signature matches (orient's lookup).
SIGNATURE = "fixture-unclaimed-host"


@pytest.fixture
def tenants(tmp_path, data_root):
    with B.run_tenant(tmp_path, data_root) as t, second_tenant(t) as other:
        yield t, other


class AdvancingReplay(R.ReplayFn):
    """`ReplayFn` that, at its first request, merges and publishes on the tenant (a human merge
    followed by another launch's publish), so `current` moves while this run is live."""

    __name__ = "AdvancingReplay"

    def __init__(self, turns: list[R.Turn], tenant: Any) -> None:
        super().__init__(turns)
        self.tenant = tenant
        self.merged: str | None = None

    def __call__(self, messages, info):
        if self.merged is None:
            self.merged = self.tenant.merge(B.MERGE_FILES)
            self.tenant.publish()
        return super().__call__(messages, info)


def _read(surface: str, path: str) -> R.Turn:
    if surface == "typed":
        return R.Turn(tool_calls=[("read_file", {"path": path})])
    return R.Turn(tool_calls=[("bash", {"command": f"cat {shlex.quote(path)}"})])


@pytest.mark.parametrize("surface", ["typed", "bash"])
def test_o2_own_copy_reads_answer_at_the_copied_revision_and_every_other_root_is_refused(
        tenants, tmp_path, monkeypatch, surface):
    """O2: the run's own lesson reads back the SEEDED revision after `current` moved to the
    merge; the other tenant's export, this tenant's clone working tree and this tenant's export
    folder are refused by the read gate (only the run copy is a read root)."""
    t, other = tenants
    # The clone is left clean (P3 refuses to publish a dirty clone); the mid-run publish
    # fast-forwards its working tree to MERGED, so a clone read would show MERGED_MARK.
    clone_lesson = B.clone_dir(t) / B.LESSON
    other_path = export_dir(other.tenant, other.commit) / OTHER_LESSON[0]
    own_export = export_dir(t.tenant, t.commit) / B.LESSON
    main = AdvancingReplay([
        _read(surface, LESSON_IN_BOX),
        _read(surface, str(other_path)),
        _read(surface, str(clone_lesson)),
        _read(surface, str(own_export)),
        R.Turn(text="done"),
    ], t)

    out = B.drive_main(t, tmp_path, monkeypatch, main=main)

    assert out.reached, out.text()
    assert out.rc == 0, out.text()
    assert main.calls == 5, f"the model did not finish its script: {main.calls}"
    assert current_commit(t.tenant) == main.merged, "premise: current advanced mid-run"
    assert B.SEEDED_MARK in main.seen[1], (
        f"O2: the run's own lesson ({surface}) did not answer at the copied revision")
    everything = "\n".join(main.seen)
    assert B.MERGED_MARK not in everything, "O2: a read answered from the advanced `current`"
    assert "Second-tenant fixture content" not in everything, "O2: another tenant's file read"
    # `seen[i]` is the whole conversation so far: each refused read adds exactly one `Blocked`.
    for i, what in ((2, "the other tenant's export"), (3, "this tenant's clone"),
                    (4, "this tenant's export folder")):
        assert main.seen[i].count("Blocked") == main.seen[i - 1].count("Blocked") + 1, (
            f"O2: the read of {what} was not refused: {main.seen[i][-400:]}")


def test_o2_defender_lessons_in_bash_answers_from_the_run_copy(tenants, tmp_path, monkeypatch):
    """O2: `defender-lessons` (box-side tool reading `DEFENDER_AGENT_DIR`) finds the fixture
    lesson by its signature — the product corpus has no such lesson — and shows the copied
    revision's description."""
    t, _other = tenants
    main = AdvancingReplay([
        R.Turn(tool_calls=[("bash", {"command": f"defender-lessons --signature {SIGNATURE}"})]),
        R.Turn(text="done"),
    ], t)
    out = B.drive_main(t, tmp_path, monkeypatch, main=main)
    assert out.reached, out.text()
    assert out.rc == 0, out.text()
    answer = main.seen[1]
    assert "fixture-owner-before-close" in answer, f"O2: defender-lessons missed the copy: {answer[-600:]}"
    assert B.SEEDED_MARK in answer, answer[-600:]
    assert B.MERGED_MARK not in answer, answer[-600:]


class ShimRecorder:
    """Orient's shim seam running the REAL shim (`orient._shim`), recording each env."""

    def __init__(self) -> None:
        self.envs: list[dict[str, str]] = []

    def __call__(self, argv: list[str], env: dict[str, str]) -> Any:
        from defender.runtime import orient

        self.envs.append(dict(env))
        return orient._shim(argv, env)


def test_o2_the_opening_messages_orientation_shows_the_copys_lessons(tenants, tmp_path,
                                                                   monkeypatch):
    """O2: orient's lessons section in MAIN's opening message (over the REAL `defender-lessons`
    shim) finds the copy's lesson by the run's signature at the copied revision; orient's shims
    run with `DEFENDER_AGENT_DIR` naming the run copy (P2's orient case, re-rooted). The
    workspace map renders over the copy."""
    t, _other = tenants
    shim = ShimRecorder()
    main = AdvancingReplay([R.Turn(text="done")], t)
    out = B.drive_main(t, tmp_path, monkeypatch, main=main, orient_shim=shim,
                       signature=SIGNATURE)
    assert out.reached, out.text()
    assert out.rc == 0, out.text()
    opening = main.seen[0]
    copy_root = B.run_copies(t) / out.seen[0].run_dir.name
    assert "fixture-owner-before-close" in opening, (
        "O2: orient's lessons section did not find the copy's lesson by the run's signature")
    assert B.SEEDED_MARK in opening
    assert B.MERGED_MARK not in opening
    assert shim.envs, "orient never ran a shim"
    agent_dirs = {env.get("DEFENDER_AGENT_DIR") for env in shim.envs}
    assert all(d and Path(d).resolve().is_relative_to(copy_root.resolve()) for d in agent_dirs), (
        f"O2: orient's shims were not pointed at the run copy {copy_root}: {agent_dirs}")
    assert "_(unavailable" not in opening, "orient's workspace map failed over the run copy"


def test_o2_the_gather_dispatch_prompt_shows_the_copys_descriptor_index(tenants, tmp_path,
                                                                        monkeypatch):
    """O2: a gather lead's dispatch prompt opens with the descriptor index from the copy."""
    t, _other = tenants
    main = AdvancingReplay([
        R.Turn(tool_calls=[("gather", {"lead_id": "l-sb1", "system": "cmdb",
                                      "goal": "who owns web-1",
                                      "what_to_summarize": ["owner"]})]),
        R.Turn(text="done")], t)
    gather = R.ReplayFn([R.Turn(text="Summary: no call issued.")])
    out = B.drive_main(t, tmp_path, monkeypatch, main=main, gather=gather)
    assert out.reached, out.text()
    assert out.rc == 0, out.text()
    assert gather.calls >= 1, "the gather lead was never dispatched"
    prompt = gather.seen[0]
    assert FIXTURE_CMDB_DESCRIPTION in prompt, (
        "O2: the gather dispatch prompt's descriptor index is not the copy's")
    assert "CMDB stub system reference" not in prompt, "O2: the product's cmdb skill was shown"
    assert "/defender/skills/cmdb" not in prompt, (
        "O2/O-TEXT: the gather prompt points the model at the product tree's cmdb skill")


# --- the tacit adapter ------------------------------------------------------------------------

REGISTRY = "agent/skills/tacit-knowledge/registry.yaml"
TACIT_LEAD = "l-001"


def _registry(entry_id: str, pattern: str, host_scope: str) -> str:
    """One hand-written registry entry valid today (S0: the fixture registry is empty because a
    dated entry expires; `find_entry` answers only while `added_at <= today <= review_by`)."""
    import datetime as dt

    today = dt.datetime.now(dt.UTC).date()
    fields = {"id": entry_id, "pattern": pattern, "actor_scope": "svc-sb-backup",
              "host_scope": host_scope, "added_by": "ops@example.invalid",
              "added_at": (today - dt.timedelta(days=10)).isoformat(),
              "review_by": (today + dt.timedelta(days=30)).isoformat(),
              "justification": "Made-up fixture sanction (#1108 P4, slice S-B)."}
    lines = ["entries:"]
    for i, (key, value) in enumerate(fields.items()):
        lines.append(f"{'  - ' if i == 0 else '    '}{key}: {value!r}")
    return "\n".join(lines) + "\n"


OWN_ENTRY = ("tk-sb-own-nightly-backup", "nightly rsync of /srv/backup", "backup-node-*.sb")
OTHER_ENTRY = ("tk-sb-other-tenant-only", "weekly tar of /srv/archive", "archive-node-*.sb")


def _lookup(pattern: str, host: str) -> R.Turn:
    return R.Turn(tool_calls=[("query", {
        "system": "tacit-knowledge", "verb": "lookup",
        "params": {"actor": "svc-sb-backup", "host": host, "pattern": pattern}})])


def test_o2_the_tacit_adapter_answers_from_the_run_copys_registry_and_not_another_tenants(
        tmp_path, data_root, monkeypatch):
    """O2 (tacit adapter): this tenant's registry entry (only in its export) answers a lookup
    the run's gather lead makes through the real adapter; the second tenant's entry, whose
    scope covers the second lookup, answers nothing. The product registry holds neither."""
    import json

    with B.run_tenant(tmp_path, data_root, files={REGISTRY: _registry(*OWN_ENTRY)}) as t, \
            second_tenant(t, files={REGISTRY: _registry(*OTHER_ENTRY)}):
        main = R.ReplayFn([
            R.Turn(tool_calls=[("gather", {
                "lead_id": TACIT_LEAD, "system": "tacit-knowledge",
                "goal": "is the backup service account's rsync sanctioned",
                "what_to_summarize": ["the matching entry id, if any"]})]),
            R.Turn(text="done")])
        gather = R.ReplayFn([
            _lookup(OWN_ENTRY[1], "backup-node-03.sb"),
            _lookup(OTHER_ENTRY[1], "archive-node-03.sb"),
            R.Turn(text="Summary: reported what the registry answered.")])
        out = B.drive_main(t, tmp_path, monkeypatch, main=main, gather=gather)

    assert out.reached, out.text()
    assert out.rc == 0, out.text()
    raw = out.run_dir / "gather_raw" / TACIT_LEAD
    payloads = [json.loads((raw / f"{i}.json").read_text(encoding="utf-8")) for i in (0, 1)]
    assert (payloads[0].get("matched") or {}).get("id") == OWN_ENTRY[0], (
        f"O2: the tacit adapter did not read the run copy's registry: {payloads[0]}")
    assert payloads[1].get("matched") is None, (
        f"O2: another tenant's registry entry answered this run's lookup: {payloads[1]}")


# --- R-I6: traversal at the copy's geometry ---------------------------------------------------

class StageClimbReplay(R.ReplayFn):
    """`ReplayFn` whose climb turns are built at its first request, once the live run copy
    exists: it lists the copy's `stage/` on the host to learn the staged token's name (only one
    run copy exists), then scripts reads of `/agent/../<token>` and `/agent/../../owner`."""

    __name__ = "StageClimbReplay"

    def __init__(self, turns: list[R.Turn], tenant: Any, surface: str) -> None:
        super().__init__(turns)
        self.tenant = tenant
        self.surface = surface
        self.token: str | None = None
        self.token_bytes: bytes = b""
        self.owner_bytes: bytes = b""

    def __call__(self, messages, info):
        if self.calls == 0:
            (root,) = list(B.run_copies(self.tenant).iterdir())
            stage = root / "stage"
            others = sorted(p.name for p in stage.iterdir() if p.name != "agent")
            # The token climb: the staged token's own name when one is staged (U9); a placeholder
            # name otherwise (the read gate must refuse the climb either way).
            self.token = others[0] if others else "s-b-no-token-staged"
            if others and (stage / self.token).is_file():
                self.token_bytes = (stage / self.token).read_bytes()
            if (root / "owner").is_file():
                self.owner_bytes = (root / "owner").read_bytes()
            self._turns[2:2] = [_read(self.surface, f"/agent/../{self.token}"),
                                _read(self.surface, "/agent/../../owner")]
        return super().__call__(messages, info)


@pytest.mark.parametrize("surface", ["typed", "bash"])
def test_r_i6_reads_climbing_out_of_the_agent_half_are_refused(tenants, tmp_path, monkeypatch,
                                                                surface):
    """R-I6/U9: `/agent/..` is the copy's `stage/` (the staged token) and `/agent/../..` the copy
    root (its `settings/`, its `owner` record). Reads of the copy's settings, the token and the
    owner record through those climbs are each refused and their bytes never reach the model; a
    listing of `/agent/..` shows the model neither the token nor any copy sibling. Positive
    control: the own-copy lesson read in the same run returns its bytes."""
    t, _other = tenants
    climb = f"/agent/../../{B.CMDB_ENV}"
    listing = R.Turn(tool_calls=[("bash", {"command": "ls -a /agent/.. /agent/../.."})])
    main = StageClimbReplay([_read(surface, LESSON_IN_BOX), _read(surface, climb), listing,
                             R.Turn(text="done")], t, surface)
    out = B.drive_main(t, tmp_path, monkeypatch, main=main)
    assert out.reached, out.text()
    assert out.rc == 0, out.text()
    assert main.calls == 6, f"the model did not finish its script: {main.calls}"
    assert B.SEEDED_MARK in main.seen[1], "control: the own-copy read returned its bytes"
    for i, what in ((2, climb), (3, f"/agent/../{main.token}"), (4, "/agent/../../owner")):
        assert main.seen[i].count("Blocked") == main.seen[i - 1].count("Blocked") + 1, (
            f"R-I6: {what} was not refused: {main.seen[i][-400:]}")
    everything = "\n".join(main.seen)
    assert B.MARK_KEY not in everything, "R-I6: the copy's settings reached the model"
    assert main.owner_bytes, "premise (U9): the live run copy has an `owner` record"
    assert main.owner_bytes.decode(errors="replace").strip() not in everything, (
        "R-I6: the copy's owner record reached the model")
    if main.token_bytes.strip():
        assert main.token_bytes.decode(errors="replace").strip() not in everything, (
            "R-I6: the staged token's bytes reached the model")
    shown = main.seen[5][len(main.seen[4]):]
    for sibling in ("settings", "owner", main.token):
        assert sibling not in shown, (
            f"R-I6: a listing above `/agent` shows the copy's {sibling}: {shown[-400:]}")
