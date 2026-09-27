"""#1105 D2, D4, J5-J7, J16, J19 — the episode source's doors, the merged alert screen, and the
episode tool's checks the service now owns.

THE DOORS (D4 as amended by J5): the launcher is the only door that takes a path — it resolves
the operator's argument once, opens it once, and records the source's IDENTITY (runs base + run
id) in the manifest. The questioner (inside the launcher's process), a sibling's `run.py
--resume` and the source-alert screen open the source by that identity and never split a path.

Every door is driven through its own entry point: the launcher through `cli.main` with #947's
declarative fakes (`_triplet_947`: `FakeSpawn`, `FakeDoor`, `FakeAgent`, `FakeAdapters`,
`source_capture`), `run.py` through `run.main` with its own seams, and a sibling's resume opener
through the REAL lifecycle and driver (`_spec1105.drive_sibling`). The faults are real: a record
corrupted on disk (for the questioner's door: corrupted at the launcher's `preflight=` seam,
AFTER the launcher's own open and before the questioner's), an `alert.json` replaced by a link,
a directory or nothing, a source moved after materialize.

The merged screen's function name is the implementer's (F11): it is reached through its two
doors, and its `RunServiceError` is read off the door's exception chain.

RED against ed5386bc: the manifest has no `source_runs_base` (AM-1, so every post-#1105
manifest here is refused by `parse_family` at base), the doors do not read the tenant record,
the two screens speak two messages, and `defender.run_service` does not exist.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import shutil
import sys
from pathlib import Path

import pytest

from defender._episode_paths import EpisodePaths
from defender.tests import _spec1105 as S
from defender.tests import _triplet_947 as T


def _resume(manifest: Path, *, materialize, world: str = "b", lifecycle=S.quiet_lifecycle):
    return S.run_py().main(["--resume", str(manifest), "--world", world],
                           lifecycle=lifecycle, visualize=lambda p: None,
                           preflight=S.no_preflight, materialize=materialize)


def _source(tmp_path: Path, monkeypatch, *, source_run_id: str = T.SOURCE_RUN_ID,
            where: str = "src") -> tuple[Path, Path, Path]:
    """Configured roots, a branchable source whose session clock the test knows
    (`clocked_source`) and a post-#1105 episode whose manifest names that source by identity
    and agrees with its clock. Returns `(runs_base_of_source, source, episode)`.

    THE CLOCK IS WHAT MAKES THE RESUME DOOR'S REFUSAL MEAN SOMETHING: over a source whose T0
    disagreed with the manifest, a resume would end in `BranchError` for that reason alone, and a
    door that never read the tenant record would look like one that refused it. Here a resume
    that is not refused goes on to ask the model (`NeverAsked`), which fails the test."""
    S.configure_roots(tmp_path, monkeypatch)
    base = tmp_path / where / "defender-runs"
    src = S.clocked_source(base, source_run_id)
    ep = T.episode(tmp_path / where, doc=S.manifest_doc(
        src, as_of=S.AT_Z, fences_at=S.FENCES_AT_BRANCH))
    return base, src, ep


def _link_alert(src: Path, tmp_path: Path) -> Path:
    secret = tmp_path / "outside-alert.json"
    secret.write_text(json.dumps({"rule": {"id": "planted"}}), encoding="utf-8")
    alert = src / "alert.json"
    alert.unlink()
    alert.symlink_to(secret)
    return alert


def _message(e: BaseException) -> str:
    return str(getattr(e, "code", e))


def _launcher_refused():
    return S.cli().LauncherRefused


def _agent():
    return T.FakeAgent(T.family_doc(), T.world_doc("b"), T.world_doc("c"))


class CorruptAtPreflight:
    """The launcher's `preflight=` seam: the role-model preflight answers 0 AFTER corrupting the
    source's tenant record — so the launcher's own open has already read a good record, and
    the next door to read it is the questioner's. Real bytes, at a real moment."""

    def __init__(self, base: Path) -> None:
        self.base = base
        self.calls = 0

    def __call__(self, _model=None) -> int:
        self.calls += 1
        (self.base / S.TENANT_RECORD).write_text("{not json", encoding="utf-8")
        return 0


# ---------------------------------------------------------------------------------------
# the doors refuse a present bad record (O4.1) and open everything else as today (O3)
# ---------------------------------------------------------------------------------------


def test_1105_every_episode_source_door_refuses_a_present_bad_record(tmp_path, monkeypatch):
    """each door that opens the episode source refuses a source whose runs base holds a corrupt
    `tenant_record`, and none proceeds past its source read. The four doors are the launcher
    (which opens `open_run(resolved.parent, resolved.name)`), the questioner, a sibling's
    `run.py --resume` and the source-alert screen (which open the source by the identity the
    launcher recorded, never by splitting a path).
    """
    base, src, ep = _source(tmp_path, monkeypatch)
    S.write_record(base)

    # the launcher: the record is bad before it starts
    (base / S.TENANT_RECORD).write_text("{not json", encoding="utf-8")
    agent, spawn = _agent(), T.FakeSpawn()
    with pytest.raises(_launcher_refused()) as launcher:
        S.launch(tmp_path, src, questioner=agent, spawn=spawn)
    assert S.TENANT_RECORD in _message(launcher.value), _message(launcher.value)
    assert agent.prompts == []
    assert spawn.launches == []
    assert not S.episode_dir_of(src).exists(), "the launcher went past its source read"

    # the questioner: the record goes bad after the launcher's own open (preflight seam)
    S.write_record(base)
    monkeypatch.setenv("DEFENDER_EPISODES_BASE", str(tmp_path / "episodes-questioner"))
    agent, spawn = _agent(), T.FakeSpawn()
    hook = CorruptAtPreflight(base)
    with pytest.raises(_launcher_refused()) as questioner:
        S.launch(tmp_path, src, questioner=agent, spawn=spawn, preflight=hook)
    assert hook.calls == 1, "the launcher refused before the questioner's door was reached"
    assert S.TENANT_RECORD in _message(questioner.value), _message(questioner.value)
    assert agent.prompts == []
    assert spawn.launches == []

    # the source-alert screen inside `run.py --resume`: bad from the start
    mat = S.fake_materialize(tmp_path / "sibling-runs")
    with pytest.raises(SystemExit) as screen:
        _resume(ep / "family.yaml", materialize=mat)
    assert S.TENANT_RECORD in _message(screen.value), _message(screen.value)
    assert mat.calls == [], "the resumed sibling materialized past a refused source"

    # the sibling's resume opener: the record goes bad after materialize, before the opener
    S.write_record(base)
    rc, summaries, _handed = S.drive_sibling(
        ep / "family.yaml", "b",
        after_materialize=lambda run_dir: (base / S.TENANT_RECORD).write_text(
            "{not json", encoding="utf-8"))
    assert rc == 0
    assert [s["truncated_by"] for s in summaries] == ["store"], summaries
    assert summaries[0]["exit_reason"] == "BranchError", summaries


def test_1105_questioner_refuses_a_present_bad_tenant_record(tmp_path, monkeypatch):
    """the branch questioner's report and investigation reads over a source run refuse — the
    source's runs base holds a corrupt `tenant_record` by the time the questioner opens the
    source (`TenantRecordCorrupt`, reported by the episode tool as `LauncherRefused` naming the
    record, J7), and the questioner is never called. With no record they return what they
    return today: the questioner is shown the source's own frontier and the family names the
    source.
    """
    S.configure_roots(tmp_path, monkeypatch)
    base, src = T.runs_base(tmp_path / "src")
    agent = _agent()
    rc, ep = S.launch(tmp_path, src, questioner=agent)
    assert rc == 0
    frontier = T.branchable_investigation().split("```invlang\n", 1)[1].split("```", 1)[0]
    assert frontier.strip() in agent.prompts[0]
    assert S.read_manifest(ep)["source_run_id"] == src.name

    monkeypatch.setenv("DEFENDER_EPISODES_BASE", str(tmp_path / "episodes-bad"))
    agent = _agent()
    with pytest.raises(_launcher_refused()) as refused:
        S.launch(tmp_path, src, questioner=agent, preflight=CorruptAtPreflight(base))
    text = _message(refused.value)
    assert text.startswith('[branch] '), text
    assert S.TENANT_RECORD in text, text
    assert agent.prompts == [], "the questioner was paid for over a refused source"


def test_1105_episode_source_opens_imported_fixture_and_pre_1077_folders_as_today(
        tmp_path, monkeypatch):
    """the episode tool opens three kinds of source in place, and each yields the same alert and
    report paths it does today: a source folder with no `tenant_record` beside it (imported); a
    checked-in fixture used in place (non-case-stable `caseA`); a pre-#1077 source named
    `20260728T161745Z-fresh-case`. Each launch completes, the manifest names the source folder
    itself, and the questioner is shown that folder's own frontier.
    """
    S.configure_roots(tmp_path, monkeypatch)
    for name in ("imported-case-1", S.FIXTURE_ID, S.PRE_1077_ID):
        _base, src = T.runs_base(tmp_path / f"kind-{name}", source_run_id=name)
        assert not (src.parent / S.TENANT_RECORD).exists()
        agent = _agent()
        rc, ep = S.launch(tmp_path, src, questioner=agent)
        assert rc == 0, name
        doc = S.read_manifest(ep)
        assert doc['source_run_dir'] == str(src), doc
        assert doc['source_run_id'] == name, doc
        assert "```invlang" in agent.prompts[0], name


# ---------------------------------------------------------------------------------------
# the merged source-alert screen (D2, O4.3) and its two doors
# ---------------------------------------------------------------------------------------


def _break_alert(src: Path, tmp_path: Path, shape: str) -> Path:
    alert = src / "alert.json"
    if shape == "symlink":
        _link_alert(src, tmp_path)
    elif shape == "directory":
        alert.unlink()
        alert.mkdir()
    elif shape == "absent":
        alert.unlink()
    return alert


def test_1105_merged_alert_screen_refuses_a_linked_alert_with_one_run_service_error(
        tmp_path, monkeypatch):
    """the merged source-alert screen raises `RunServiceError` for a source run whose
    `alert.json` is a symlink, a directory or absent, with one message naming the alert path. It
    returns the alert path for a plain file. Reached through its `run.py --resume` door: the
    refusal is the door's exit, with the screen's `RunServiceError` on its chain; the plain
    file's path is the alert run setup is handed.
    """
    for shape in ("plain", "symlink", "directory", "absent"):
        _base, src, ep = _source(tmp_path / shape, monkeypatch)
        alert = _break_alert(src, tmp_path / shape, shape)
        mat = S.fake_materialize(tmp_path / shape / "sibling-runs")
        if shape == "plain":
            assert _resume(ep / "family.yaml", materialize=mat) == 0
            assert [a[0] for a, _kw in mat.calls] == [alert], mat.calls
            continue
        with pytest.raises(SystemExit) as refused:
            _resume(ep / "family.yaml", materialize=mat)
        assert "RunServiceError" in S.chain_types(refused.value), (shape, S.chain_types(
            refused.value))
        assert str(alert) in _message(refused.value), (shape, _message(refused.value))
        assert mat.calls == [], shape


def test_1105_both_doors_surface_the_same_screen_message_over_their_own_path(
        tmp_path, monkeypatch):
    """for the same linked `alert.json`, the two doors surface one message: `run.py --resume`
    exits with the screen's `RunServiceError` message. The episode tool raises `LauncherRefused`
    whose text is `"[branch] " + <that message>`. Each door passes the path it resolved itself —
    `run.py` from the manifest's identity, the launcher from the operator's argument — and both
    resolve to the same source.
    """
    _base, src, ep = _source(tmp_path, monkeypatch)
    _link_alert(src, tmp_path)
    with pytest.raises(SystemExit) as run_py_door:
        _resume(ep / "family.yaml", materialize=S.fake_materialize(tmp_path / "sib"))
    message = _message(run_py_door.value)
    assert str(src / "alert.json") in message, message
    with pytest.raises(_launcher_refused()) as launcher_door:
        S.launch(tmp_path, src)
    assert _message(launcher_door.value) == "[branch] " + message, (
        _message(launcher_door.value), message)


def test_1105_episode_tool_translates_run_service_error_to_launcher_refused(tmp_path,
                                                                            monkeypatch):
    """when a service episode check raises `RunServiceError` (here the merged screen over a
    linked source alert), the episode tool raises `LauncherRefused` whose text starts
    `"[branch] "` and carries the service message; no questioner is paid and no sibling
    launched.
    """
    _base, src, _ep = _source(tmp_path, monkeypatch)
    _link_alert(src, tmp_path)
    agent, spawn = _agent(), T.FakeSpawn()
    with pytest.raises(_launcher_refused()) as refused:
        S.launch(tmp_path, src, questioner=agent, spawn=spawn)
    text = _message(refused.value)
    assert text.startswith("[branch] "), text
    chain = S.chain_types(refused.value)
    assert "RunServiceError" in chain, chain
    cause = refused.value.__cause__ or refused.value.__context__
    assert str(cause) in text, (text, cause)
    assert agent.prompts == []
    assert spawn.launches == []


def test_1105_run_py_screen_refusal_exit_status_and_stream(tmp_path, monkeypatch):
    """`run.py` meeting the merged screen's refusal exits via `sys.exit(message)` as today: run
    by script path as a sibling is, the process exits with status 1 and the message — naming the
    alert — is on stderr, nothing on stdout; no run directory is materialized. Only the text
    changes (O4.3).
    """
    runs = S.configure_roots(tmp_path, monkeypatch)
    _base, src = T.runs_base(tmp_path / "src")
    ep = T.episode(tmp_path / "src", doc=S.manifest_doc(src))
    _link_alert(src, tmp_path)
    proc = S.fresh_interpreter(
        "", cwd=tmp_path,
        argv=[sys.executable, str(S.DEFENDER / "run.py"), "--resume",
              str(ep / "family.yaml"), "--world", "b"])
    assert proc.returncode == 1, (proc.returncode, proc.stderr)
    assert str(src / "alert.json") in proc.stderr, proc.stderr
    assert proc.stdout == ""
    assert not runs.exists() or not any(runs.iterdir())


def test_1105_launcher_exit_status_for_a_service_refusal(tmp_path, monkeypatch):
    """The episode tool's translated refusal takes today's `LauncherRefused` path: it is a
    `SystemExit` carrying its message (so the process exits 1 with it), and it leaves the same
    on-disk state as today's `LauncherRefused` from the preflight — no episode directory, no
    staged name, no sibling.
    """
    _base, src, _ep = _source(tmp_path, monkeypatch)
    _link_alert(src, tmp_path)
    door, spawn = T.FakeDoor(), T.FakeSpawn()
    with pytest.raises(SystemExit) as refused:
        S.launch(tmp_path, src, door=door, spawn=spawn)
    assert isinstance(refused.value, _launcher_refused())
    assert isinstance(refused.value.code, str)
    assert refused.value.code.startswith('[branch] ')
    assert not S.episode_dir_of(src).exists()
    assert door.created() == []
    assert spawn.launches == []


def test_1105_questioner_and_alert_screen_doors_surface_an_open_run_refusal(tmp_path,
                                                                             monkeypatch):
    """each process shows a refused source one way. In the episode tool, the launcher and the
    questioner turn every run-service refusal (`RunServiceError`, and `open_run`'s `ValueError`
    or `TenantRecordCorrupt`) into `LauncherRefused` whose text starts `"[branch] "` and names
    the record or id. `run.py`, plain and `--resume`, exits through `sys.exit(message)` with that
    message on stderr, as its screen does today; inside `--resume` the screen runs before
    materialize, so a refused source alert leaves no run directory. Inside the driver the resume
    opener raises `BranchError` and the run ends `truncated_by="store"`. A moved episode check
    keeps raising the `FamilyError` or `BranchError` its catch site catches.
    """
    base, src, ep = _source(tmp_path, monkeypatch)

    # the launcher: open_run's plain ValueError (another tenant) and TenantRecordCorrupt
    for shape in ("other_tenant", "corrupt"):
        monkeypatch.setenv("DEFENDER_EPISODES_BASE", str(tmp_path / f"episodes-{shape}"))
        if (base / S.TENANT_RECORD).exists():
            (base / S.TENANT_RECORD).unlink()
        S.plant_bad_record(base, shape, elsewhere=tmp_path / f"elsewhere-{shape}")
        with pytest.raises(_launcher_refused()) as refused:
            S.launch(tmp_path, src)
        assert _message(refused.value).startswith("[branch] "), _message(refused.value)
        text = _message(refused.value)
        assert S.TENANT_RECORD in text or str(base) in text or src.name in text, (shape, text)

    # the questioner: TenantRecordCorrupt after the launcher's open
    S.write_record(base)
    monkeypatch.setenv("DEFENDER_EPISODES_BASE", str(tmp_path / "episodes-questioner"))
    with pytest.raises(_launcher_refused()) as refused:
        S.launch(tmp_path, src, preflight=CorruptAtPreflight(base))
    assert _message(refused.value).startswith("[branch] ")
    assert S.TENANT_RECORD in _message(refused.value), _message(refused.value)

    # run.py --resume: the screen's open refuses before materialize — no run directory
    mat = S.fake_materialize(tmp_path / "sibling-runs")
    with pytest.raises(SystemExit) as screen:
        _resume(ep / "family.yaml", materialize=mat)
    assert isinstance(screen.value.code, str)
    assert S.TENANT_RECORD in screen.value.code
    assert mat.calls == []

    # run.py plain: a refusal is an exit with its message, as today
    alert = tmp_path / "alert.json"
    alert.write_text("{}", encoding="utf-8")
    with pytest.raises(SystemExit) as plain:
        S.run_py().main([str(alert), "--run-id", "Not Valid"], lifecycle=S.quiet_lifecycle,
                        visualize=lambda p: None, preflight=S.no_preflight)
    assert isinstance(plain.value.code, str)
    assert 'Not Valid' in plain.value.code

    # inside the driver: the opener's refusal is BranchError and the run ends at store setup
    S.write_record(base)
    rc, summaries, _ = S.drive_sibling(
        ep / "family.yaml", "b",
        after_materialize=lambda run_dir: (base / S.TENANT_RECORD).write_text(
            "{not json", encoding="utf-8"))
    assert rc == 0, summaries
    assert summaries[0]['truncated_by'] == 'store', summaries
    assert summaries[0]["exit_reason"] == "BranchError", summaries

    # a moved episode check keeps its class
    with pytest.raises(S.sym("FamilyError")):
        S.sym("refuse_bad_episode_id")("Not/An-Episode")


def test_1105_merged_alert_screen_over_a_hardlinked_alert_json(tmp_path, monkeypatch):
    """the merged source-alert screen screens `alert.json` with `artifact_file` as today: a
    hard-linked `alert.json` (link count 2) passes and the screen returns its path, and a
    mode-000 `alert.json` passes too, with the later read raising `PermissionError` as at base
    (non-root reader). No new refusal is added (N-c).
    """
    _base, src, ep = _source(tmp_path, monkeypatch)
    alert = src / "alert.json"
    twin = tmp_path / "alert-twin.json"
    os.link(alert, twin)
    assert alert.stat().st_nlink == 2
    mat = S.fake_materialize(tmp_path / "sibling-runs")
    assert _resume(ep / "family.yaml", materialize=mat) == 0
    assert [a[0] for a, _kw in mat.calls] == [alert]

    twin.unlink()
    alert.chmod(0)
    child = """
        import json
        from pathlib import Path
        from defender import run as run_mod
        out = {}
        class Stop(Exception):
            pass
        def mat(alert, run_id, **kw):
            out["alert"] = str(alert)
            try:
                Path(alert).read_bytes()
                out["read"] = "ok"
            except Exception as e:
                out["read"] = type(e).__name__
            raise Stop
        try:
            run_mod.main(["--resume", MANIFEST, "--world", "b"], materialize=mat,
                         lifecycle=lambda **k: {}, visualize=lambda p: None,
                         preflight=lambda m: 0)
        except Stop:
            pass
        except SystemExit as e:
            out["exit"] = str(e.code)
        print(json.dumps(out))
    """.replace("MANIFEST", repr(str(ep / "family.yaml")))
    with S.restoring_modes(alert):
        got = S.unprivileged(child, cwd=tmp_path)
    assert got.get("alert") == str(alert), got
    assert got.get("read") == "PermissionError", got


# ---------------------------------------------------------------------------------------
# J5 / J5a — one door takes a path; the rest open by the recorded identity
# ---------------------------------------------------------------------------------------


def test_1105_episode_source_argument_shapes(tmp_path, monkeypatch):
    """the launcher is the only door that takes a path. Given the source spelled as an absolute
    path, with a trailing slash, as `.` from inside the run directory, as a relative path through
    `..`, and as a symlink into another runs base, it resolves the path once and opens
    `open_run(resolved.parent, resolved.name)`. The family manifest it writes records the
    source's identity: `source_runs_base` is the resolved parent, `source_run_id` is the
    resolved folder name, and `source_run_dir` equals their join. For the symlinked source, the
    identity names the link target's base and folder, so that base's tenant record is the one
    every door consults — a corrupt record in the LINK's base refuses nothing.
    """
    S.configure_roots(tmp_path, monkeypatch)
    base, src = T.runs_base(tmp_path / "real")
    S.write_record(base)
    other = tmp_path / "other-runs"
    other.mkdir()
    (other / "alias-run").symlink_to(src)
    S.plant_bad_record(other, "corrupt", elsewhere=tmp_path / "elsewhere")
    (base / "sub").mkdir()
    shapes = {
        "absolute": str(src),
        "trailing-slash": str(src) + "/",
        "dot": ".",
        "dotdot": os.path.join("sub", "..", src.name),
        "symlink": str(other / "alias-run"),
    }
    for shape, spelling in shapes.items():
        monkeypatch.setenv("DEFENDER_EPISODES_BASE", str(tmp_path / f"episodes-{shape}"))
        monkeypatch.chdir(src if shape == "dot" else base)
        rc, ep = S.launch(tmp_path, spelling)
        assert rc == 0, shape
        doc = S.read_manifest(S.cli().episode_dir_for(
            S.cli().episode_id_for(src.name, T.BRANCH_MESSAGE_ID)))
        assert doc.get(S.SOURCE_RUNS_BASE_FIELD) == str(base), (shape, doc)
        assert doc.get("source_run_id") == src.name, (shape, doc)
        assert doc.get("source_run_dir") == str(Path(doc[S.SOURCE_RUNS_BASE_FIELD]) / src.name), (
            shape, doc)


def test_1105_manifest_source_run_id_disagrees_with_the_source_folder_name(tmp_path,
                                                                            monkeypatch):
    """the doors after the launcher never split a path. Given a manifest whose `source_run_dir`
    string, split into parent and name, would name a different base and id than its
    `source_runs_base` and `source_run_id`, a sibling's `run.py --resume` and the source-alert
    screen each open `open_run(Path(source_runs_base), source_run_id)` and nothing else — the
    decoy at the split path is never read — and the questioner opens the source with the base
    and id the launcher resolved. A source moved or deleted after launch makes a sibling's
    resume end `truncated_by="store"` with `BranchError` (D6), not open whatever sits at the
    decoy path.
    """
    S.configure_roots(tmp_path, monkeypatch)
    src = S.clocked_source(tmp_path / "real-runs", S.PRE_1077_ID)
    # THE DECOY IS A SOURCE THAT WOULD RESUME: same clock, its own store and pointer — so a
    # door that split `source_run_dir` would open it and ask the model a turn, which
    # `NeverAsked` refuses; a decoy that could not resume would hide that door behind a
    # BranchError of its own.
    decoy = S.clocked_source(tmp_path / "decoy-runs", "decoy-run", case_id="case-decoy")
    (decoy / "alert.json").write_text(json.dumps({"rule": {"id": "DECOY"}}), encoding="utf-8")
    ep = T.episode(tmp_path / "ep", doc=S.manifest_doc(
        src, source_run_dir=str(decoy), as_of=S.AT_Z, fences_at=S.FENCES_AT_BRANCH))

    mat = S.fake_materialize(tmp_path / "sibling-runs")
    assert _resume(ep / "family.yaml", materialize=mat) == 0
    assert [a[0] for a, _kw in mat.calls] == [src / "alert.json"], mat.calls

    agent = _agent()
    rc, _ep = S.launch(tmp_path, src, questioner=agent)
    assert rc == 0
    assert '```invlang' in agent.prompts[0]

    moved = tmp_path / "moved-away"

    def move_source(run_dir: Path) -> None:
        shutil.move(str(src), str(moved))

    model = S.NeverAsked()
    rc, summaries, _ = S.drive_sibling(ep / "family.yaml", "b", main=model,
                                       after_materialize=move_source)
    assert rc == 0
    assert summaries[0]["truncated_by"] == "store", summaries
    assert summaries[0]["exit_reason"] == "BranchError", summaries
    assert model.calls == 0


def _base_shape_manifest(src: Path) -> dict:
    """A `family.yaml` document in the shape ed5386bc's launcher writes for source `src` — the
    fields of `_FAMILY_FIELDS` at base (AM-1), with `source_run_dir` the resolved source and
    `source_run_id` its folder name — SPELLED OUT HERE AS DATA.

    Deliberately not built by `_triplet_947.family_doc` / `T.episode` / `T.write_family`: the one
    sanctioned route by which existing manifest fixtures gain `source_runs_base` is a DEFAULT in
    `_triplet_947.family_doc` (phase-F §7 R3, `o4_test_diff_scope`), and a legacy manifest built
    through that helper would silently stop being legacy the day the default lands."""
    return {
        "episode_id": "20260728t161845z-fresh-case-n59",
        "source_run_dir": str(src),
        "source_run_id": src.name,
        "branch_message_id": 59,
        "fences_at": 4,
        "as_of": "2026-07-28T16:18:45Z",
        "continuation_prompt": "Continue from here.",
        "base_story": "the captured story",
        "discriminator": {"predicate": "p", "holding_system": "elastic",
                          "envelope": {"system": "elastic", "verb": "esql",
                                       "params": {"query": "FROM logs-* | LIMIT 5"}}},
        "worlds": [
            {"world_id": "a", "role": "A", "story": "a story", "axis": None,
             "disposition_declared": "malicious", "label_basis": "policy-rule", "overlay": {}},
            {"world_id": "b", "role": "B", "story": "a story", "axis": "an axis",
             "disposition_declared": "malicious", "label_basis": "policy-rule",
             "overlay": {"elastic": {"logs-*": {"inject": [{"_id": "i1"}], "exclude": None}}}},
            {"world_id": "c", "role": "B", "story": "a story", "axis": "an axis",
             "disposition_declared": "malicious", "label_basis": "policy-rule",
             "overlay": {"patches": {"identity": {"web-1": {"owner": "platform"}}}}},
        ],
    }


def _hand_written_episode(root: Path, doc: dict) -> Path:
    """An episode dir holding `doc` as its `family.yaml` and the primed, empty `served/base.jsonl`
    every launched episode has — written here with `yaml.safe_dump`, through no shared helper."""
    import yaml

    ep = root / "episodes" / "20260728t161845z-fresh-case-n59"
    (ep / "served").mkdir(parents=True)
    (ep / "served" / "base.jsonl").write_text("", encoding="utf-8")
    (ep / "family.yaml").write_text(yaml.safe_dump(doc), encoding="utf-8")
    return ep


def test_1105_resume_and_alert_screen_refuse_a_manifest_without_the_source_runs_base(
        tmp_path, monkeypatch):
    """a sibling's `run.py --resume` and the source-alert screen, each given a `family.yaml`
    written before #1105, which carries `source_run_dir` and `source_run_id` but no
    source-runs-base field, refuse with `FamilyError` naming the missing field. Neither splits
    `source_run_dir` into a base and an id, calls `open_run`, or materializes a run directory.
    The positive control: the same manifest with the field added opens the source by that
    identity. Both manifests are written by hand in this test — never through
    `_triplet_947.family_doc`, whose `source_runs_base` default would make the legacy one
    current — and differ by that one field only.
    """
    import yaml

    S.configure_roots(tmp_path, monkeypatch)
    _base, src = T.runs_base(tmp_path / "src")
    legacy_doc = _base_shape_manifest(src)
    legacy = _hand_written_episode(tmp_path / "legacy", legacy_doc)
    written = yaml.safe_load((legacy / "family.yaml").read_text(encoding="utf-8"))
    assert S.SOURCE_RUNS_BASE_FIELD not in written, "the legacy manifest is not legacy"

    with pytest.raises(S.sym("FamilyError")) as parsed:
        S.sym("load_family")(legacy / "family.yaml")
    assert S.SOURCE_RUNS_BASE_FIELD in str(parsed.value)

    mat = S.fake_materialize(tmp_path / "sibling-runs")
    with pytest.raises(SystemExit) as refused:
        _resume(legacy / "family.yaml", materialize=mat)
    assert S.SOURCE_RUNS_BASE_FIELD in _message(refused.value), _message(refused.value)
    assert mat.calls == []

    current = _hand_written_episode(
        tmp_path / "current", {**legacy_doc, S.SOURCE_RUNS_BASE_FIELD: str(src.parent)})
    assert _resume(current / "family.yaml", materialize=mat) == 0
    assert [a[0] for a, _kw in mat.calls] == [src / "alert.json"]


#: Names whose case-fold passes `is_valid_run_id` although the name itself does not: the base
#: launcher derives the episode id from `name.casefold()` (`strasse-n59`, `kase-n59`) and LAUNCHES
#: them (E2-J6, executed at ed5386bc: rc 0, three sibling spawns). The second is `Kase` spelled
#: with U+212A KELVIN SIGN, which case-folds to ASCII `k`.
CASEFOLD_PASSES = ("straße", "Kase")


def test_1105_imported_source_folder_whose_name_fails_the_id_shape(tmp_path, monkeypatch):
    """for an imported source folder with no tenant record beside it whose name fails
    `is_valid_run_id`, the launcher refuses at the source-open step with `LauncherRefused`
    whose message names the folder and tells the operator to rename it to a valid run id; no
    episode directory is created, the questioner is not asked and no sibling launches. For
    `run (1)`, `my case` and `_import` this is the refusal class base already raises through the
    derived episode id, with a clearer message; the case-fold cell — `straße`, and `Kase`
    spelled with U+212A KELVIN SIGN, whose case-fold passes and which base launches — is the
    new refusal. The positive control: the same folder renamed `run-1` opens as today.
    """
    S.configure_roots(tmp_path, monkeypatch)
    for name in ("run (1)", "my case", "_import", *CASEFOLD_PASSES):
        _base, src = T.runs_base(tmp_path / f"imp-{name.replace(' ', '_')}", source_run_id=name)
        agent, spawn = _agent(), T.FakeSpawn()
        with pytest.raises(_launcher_refused()) as refused:
            S.launch(tmp_path, src, questioner=agent, spawn=spawn)
        text = _message(refused.value)
        assert name in text, (name, text)
        assert 'rename' in text.lower(), (name, text)
        assert agent.prompts == []
        assert spawn.launches == []
        episodes = tmp_path / "episodes-root"
        assert not episodes.exists() or not any(episodes.iterdir()), name

    _base, src = T.runs_base(tmp_path / "imp-renamed", source_run_id="run-1")
    rc, _ep = S.launch(tmp_path, src)
    assert rc == 0


def test_1105_episode_source_is_itself_a_former_sibling(tmp_path, monkeypatch):
    """A source that is itself a former sibling opens like any other source at every door:
    case-stable id → `for_tenant` under `<ep>/runs`, whose default record `ensure_tenant` wrote.
    The launcher opens it, records `<ep>/runs` as its runs base, and a resumed sibling of the new
    episode opens it by that identity.
    """
    S.configure_roots(tmp_path, monkeypatch)
    former = tmp_path / "old-episode" / "runs"
    src = S.clocked_source(former, "20260728t161845z-fresh-case-n59-b")
    S.mod("_tenant").ensure_tenant(former)
    opened = S.sym("open_run")(former, src.name)
    assert opened.runs_base == former
    assert opened.tenant_id == S.DEFAULT_TENANT

    rc, ep = S.launch(tmp_path, src)
    assert rc == 0
    doc = S.read_manifest(ep)
    assert doc[S.SOURCE_RUNS_BASE_FIELD] == str(former)
    assert doc['source_run_id'] == src.name

    mat = S.fake_materialize(tmp_path / "sibling-runs")
    assert _resume(ep / "family.yaml", materialize=mat) == 0
    assert [a[0] for a, _kw in mat.calls] == [src / "alert.json"]


# ---------------------------------------------------------------------------------------
# the episode tool's run checks, moved (D1): store, clock, fence count
# ---------------------------------------------------------------------------------------


def test_1105_pre_1077_named_source_reaches_the_session_store_and_branch_point_clock(
        tmp_path, monkeypatch):
    """A pre-#1077 source (`20260728T161745Z-fresh-case`, bare `Run.at` handle) passes the
    branch-point check, the T0 clock (with its file-time fallback) and the source store exactly
    as today; none of them reads a runs-base sidecar (a bare handle refuses every sidecar, so a
    sidecar read would have ended the launch). With its session, T0 is the branch point's own
    moment and the fence count is the count at the branch point; without one (an imported copy,
    no pointer), T0 is the newest file time and the fence count the document's total — the
    values `cli.branch_point_clock` / `cli._fence_count` gave at ed5386bc.
    """
    S.configure_roots(tmp_path, monkeypatch)
    base = tmp_path / "runs"
    src = S.clocked_source(base, S.PRE_1077_ID)
    rc, ep = S.launch(tmp_path, src)
    assert rc == 0
    doc = S.read_manifest(ep)
    assert doc['as_of'] == S.AT_Z, doc
    assert doc['fences_at'] == S.FENCES_AT_BRANCH, doc

    storeless = S.storeless_copy(src, base / "20260728T161746Z-fresh-case",
                                 newest=1785000123)
    rc, ep = S.launch(tmp_path, storeless)
    assert rc == 0
    doc = S.read_manifest(ep)
    newest = dt.datetime.fromtimestamp(1785000123, tz=dt.UTC)
    assert doc["as_of"] == newest.isoformat().replace("+00:00", "Z"), doc
    assert doc["fences_at"] == S.FENCES_TOTAL, doc


def test_1105_pre_1077_named_source_under_fence_count(tmp_path):
    """`fence_count` over a pre-#1077 source opened as a bare handle counts as it does today:
    3 fences at message 59 of a document holding 7 (the session says when), and the document's
    own total, 7, for the same source with no session (measured through `cli._fence_count` at
    ed5386bc).
    """
    base = tmp_path / "runs"
    src = S.clocked_source(base, S.PRE_1077_ID)
    fence_count = S.sym("fence_count")
    assert fence_count(src, S.BRANCH_MESSAGE_ID, continuation_prompt="go",
                       as_of=S.AT) == S.FENCES_AT_BRANCH
    storeless = S.storeless_copy(src, base / "20260728T161746Z-fresh-case")
    assert fence_count(storeless, S.BRANCH_MESSAGE_ID, continuation_prompt="go",
                       as_of=S.AT) == S.FENCES_TOTAL


def test_1105_fence_count_is_public_and_counts_as_before(tmp_path):
    """`fence_count` from `defender.run_service` returns the same count for a source transcript
    that `learning/branch/cli._fence_count` returns at the base commit — here over a
    case-stable source: 3 at the branch point with a session, 7 (the document's total) without.
    """
    base = tmp_path / "runs"
    src = S.clocked_source(base, "20260728t161845z-fresh-case")
    fence_count = S.sym("fence_count")
    assert fence_count(src, S.BRANCH_MESSAGE_ID, continuation_prompt="go",
                       as_of=S.AT) == S.FENCES_AT_BRANCH
    storeless = S.storeless_copy(src, base / "20260728t161846z-fresh-case")
    assert fence_count(storeless, S.BRANCH_MESSAGE_ID, continuation_prompt="go",
                       as_of=S.AT) == S.FENCES_TOTAL


def test_1105_source_store_is_opened_through_the_service_and_refuses_a_foreign_pointer(
        tmp_path, monkeypatch):
    """the service's `open_source_store` refuses a source run whose `session_pointer` names a
    store other than the one its case id derives. The handle's `session_db().open()` would not
    refuse it (X8), and the episode tool reaches the store only through the service call: a
    launch over that source is refused before the questioner is paid.
    """
    S.configure_roots(tmp_path, monkeypatch)
    base = tmp_path / "runs"
    src = S.clocked_source(base, "20260728t161845z-fresh-case", case_id="case-1105")
    open_source_store = S.sym("open_source_store")
    good = open_source_store(src)
    good.close()

    ss = S.mod("runtime.session_store")
    foreign = ss.open_store(case_id="case-foreign", runs_base=base)
    foreign_path = foreign.path
    foreign.close()
    pointer = src / "session_store_pointer.json"
    doc = json.loads(pointer.read_text(encoding="utf-8"))
    doc["store_path"] = str(foreign_path)
    pointer.write_text(json.dumps(doc), encoding="utf-8")

    with pytest.raises(S.sym("BranchError")):
        open_source_store(src)
    handle = S.sym("open_run")(base, src.name)
    store = handle.session.session_db("case-1105").open()
    store.close()

    agent = _agent()
    with pytest.raises(_launcher_refused()):
        S.launch(tmp_path, src, questioner=agent)
    assert agent.prompts == []


# ---------------------------------------------------------------------------------------
# the episode, end to end (Key flows), and verification's refusal (O4.1, J9, J16)
# ---------------------------------------------------------------------------------------


class BuildingSpawn(T.FakeSpawn):
    """#947's process seam, which also leaves each sibling's finished run dir behind — the
    shape a real `run.py --resume` child leaves under the episode's own runs base — and then
    writes `record` (bytes) as that runs base's tenant record: the siblings' shared record, as
    their `ensure_tenant` race or a crash left it."""

    def __init__(self, record: str | None = None) -> None:
        super().__init__()
        self.record = record

    def __call__(self, argv, *, env=None, **kw):
        world = argv[argv.index("--world") + 1]
        runs = Path(env["DEFENDER_RUNS_BASE"])
        T.sibling_run_dir(runs, world)
        if self.record is not None:
            (runs / S.TENANT_RECORD).write_text(self.record, encoding="utf-8")
        return super().__call__(argv, env=env, **kw)


def _review(ep: Path) -> dict:
    import yaml

    path = ep / "review.yaml"
    return yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else {}


#: A branch point inside the launcher's ceiling that no message on the fixture's main path holds.
BAD_BRANCH_POINT = 5999


def test_1105_episode_opens_source_then_todays_preflight_then_launches_and_verifies_siblings(
        tmp_path, monkeypatch):
    """an episode run takes its steps in order: `open_run` on the source first, then the
    launcher's preflight in today's order — the branch-point check before the merged alert
    screen — then the sibling launches, and then `verify_family` opening each sibling through
    `open_run`. A refusal at any earlier step launches no sibling. Observed by stacking faults:
    with a bad record, a linked alert and a bad branch point together the refusal is the
    record's; with the alert and the branch point it is the branch point's, as at base (E2-R1);
    the linked alert alone is refused by the screen; and a clean launch starts every sibling
    before verification opens them (a bad sibling record refuses only after the launches).
    """
    S.configure_roots(tmp_path, monkeypatch)

    def attempt(tag: str, *, record: bool, alert: bool, branch: bool):
        base, src = T.runs_base(tmp_path / tag)
        if record:
            S.plant_bad_record(base, "corrupt", elsewhere=tmp_path / f"{tag}-elsewhere")
        if alert:
            _link_alert(src, tmp_path / tag)
        spawn = T.FakeSpawn()
        argv_mid = str(BAD_BRANCH_POINT if branch else T.BRANCH_MESSAGE_ID)
        monkeypatch.setenv("DEFENDER_EPISODES_BASE", str(tmp_path / f"episodes-{tag}"))
        with pytest.raises(_launcher_refused()) as refused:
            S.cli().main([str(src), argv_mid, "--continuation-prompt", "go"], spawn=spawn,
                         door=T.FakeDoor(), questioner=_agent(), adapters=T.FakeAdapters(),
                         invoke=T.FakeAgent(*["same"] * 24), preflight=T.no_preflight,
                         live_tree=T.source_capture())
        assert spawn.launches == [], tag
        return _message(refused.value), src

    text, _src = attempt("all-three", record=True, alert=True, branch=True)
    assert S.TENANT_RECORD in text, text
    # TODAY'S PREFLIGHT ORDER (phase-F §7 R1): `_check_branch_point` runs before the alert
    # screen, so the branch point's refusal — which names the source run, never its alert — is
    # the one an operator with both faults sees.
    text, src = attempt("alert-and-branch", record=False, alert=True, branch=True)
    assert str(BAD_BRANCH_POINT) in text, text
    assert str(src / "alert.json") not in text, text
    text, src = attempt("alert-only", record=False, alert=True, branch=False)
    assert str(src / "alert.json") in text, text
    # the tmp path is cut first: pytest's numbered base dir could itself spell the digits
    assert str(BAD_BRANCH_POINT) not in text.replace(str(tmp_path), "<tmp>"), text

    monkeypatch.setenv("DEFENDER_EPISODES_BASE", str(tmp_path / "episodes-verify"))
    _base, src = T.runs_base(tmp_path / "verify")
    spawn = BuildingSpawn(record="{not json")
    with pytest.raises(_launcher_refused()):
        S.launch(tmp_path, src, spawn=spawn)
    assert sorted(spawn.worlds) == ["a", "b", "c"], "verification ran before the launches"


def test_1105_sibling_refusal_lands_at_verify_top_teardown_runs_and_no_outcome_is_recorded(
        tmp_path, monkeypatch):
    """when `verify_family` opens a sibling through `open_run` and the siblings' runs base holds
    a corrupt `tenant_record`, three things are observable: The refusal is raised from the top
    of `verify_family` or `archive_episode`, before any world is archived. The launcher's
    teardown still runs. No episode outcome is recorded in the review record.
    """
    S.configure_roots(tmp_path, monkeypatch)
    _base, src = T.runs_base(tmp_path / "src")
    door, spawn = T.FakeDoor(), BuildingSpawn(record="{not json")
    with pytest.raises(_launcher_refused()) as refused:
        S.launch(tmp_path, src, door=door, spawn=spawn)
    assert "TenantRecordCorrupt" in _message(refused.value) or S.TENANT_RECORD in _message(
        refused.value), _message(refused.value)
    ep = S.episode_dir_of(src)
    assert spawn.launches, "the siblings never launched — the refusal is not verification's"
    worlds = EpisodePaths(ep).worlds
    assert not [p for p in worlds.rglob("*") if p.is_file()] if worlds.exists() else True
    assert door.deleted(), "the launcher's teardown did not run"
    assert "outcome" not in (_review(ep).get("episode") or {}), _review(ep)


def test_1105_family_stamp_base_world_read_after_open_run_accepted_the_record(tmp_path,
                                                                              monkeypatch):
    """`verify_family` opens each sibling through `open_run`, so a sibling runs base whose
    `_tenant.json` is empty (a crashed first sibling) or corrupt refuses at the top: teardown
    runs and no outcome is recorded. Under a default record `open_run` accepts,
    `_family_base_world_id` still makes its own best-effort read, unchanged, and the family stamp
    carries the same base world id as at base.
    """
    S.configure_roots(tmp_path, monkeypatch)
    for shape, record in (("empty", ""), ("corrupt", "{not json")):
        monkeypatch.setenv("DEFENDER_EPISODES_BASE", str(tmp_path / f"episodes-{shape}"))
        _base, src = T.runs_base(tmp_path / f"src-{shape}")
        door = T.FakeDoor()
        with pytest.raises(_launcher_refused()):
            S.launch(tmp_path, src, door=door, spawn=BuildingSpawn(record=record))
        ep = S.episode_dir_of(src)
        assert door.deleted(), shape
        assert "outcome" not in (_review(ep).get("episode") or {}), (shape, _review(ep))

    ep = T.episode(tmp_path / "direct")
    runs = ep / "runs"
    dirs = [T.sibling_run_dir(runs, w) for w in T.WORLDS]
    (runs / S.TENANT_RECORD).write_text(json.dumps(
        {"tenant_id": S.DEFAULT_TENANT, "base_world_id": "f" * 32,
         "created_at": "2026-09-21T14:30:00+00:00"}) + "\n", encoding="utf-8")
    report = S.cli().verify_family(ep, dirs, source=T.provenance_record())
    assert report["outcome"] == "accepted", report
    stamp = json.loads(EpisodePaths(ep).family_stamp.read_text(encoding="utf-8"))
    assert stamp["base_world_id"] == "f" * 32, stamp
