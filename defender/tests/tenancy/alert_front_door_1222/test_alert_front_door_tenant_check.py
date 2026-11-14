"""One tenant check, the same verdict at every entry point, for the required
`settings/alert-mapping.yaml` and for a legacy `systems/case-history/` folder (#1359)."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import contextlib
import dataclasses
import json
import shutil
import os
import re
import threading
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from typing import Any

import pytest

from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.support.tenancy import _systems1366 as R
from defender.tests.tenancy.alert_front_door_1222 import _spec1222 as S

# Names

#: The alert mapping's file name.
ALERT_MAPPING = S.ALERT_MAPPING_REL
#: The case-history mapping, named the way every reason naming it spells it.
CASE_MAPPING = S.CASE_MAPPING_REL.split("/", 1)[1]
#: The file that replaced it (#1359): a reason about the retired folder names this.
CASE_RECORD = "case-record.yaml"
MAPPING_NAMES = (ALERT_MAPPING, CASE_MAPPING, CASE_RECORD)
#: The old top-level section of the case mapping; a reason refusing it names it.
SOURCE_SECTION = re.compile(r"\bsource\b")
#: The move a `source:` refusal names: to the alert mapping, by its file name or in words.
THE_MOVE = re.compile(r"alert[ _-]mapping", re.IGNORECASE)
#: `tenant.py`'s documented refusal / finding prefix ("Every refusal is printed as `[tenant.py]
#: <message>`").
TENANT_PY = "[tenant.py] "
#: What the recording role preflight answers: a launch or a sibling that reached it stops there.
PAST_THE_CHECK = 97
#: How long a site may sit on the FIFO before the watcher stands in for a writer.
FIFO_GRACE_S = 10.0

SITES = ("acceptance", "check-folder", "run-start", "branch-launch", "sibling-resume",
         "policy-cli")

def _shape_params(shapes: Iterable[str]) -> list[Any]:
    return [pytest.param(s, marks=S.needs_non_root) if s in S.ROOT_BLIND_SHAPES else s
            for s in shapes]


#: Case-history mapping contents the one check refuses, as the BYTES written at its name.
#: `unreadable` is a valid file put at mode 000 by `World.case_bytes`.
CASE_FAULTS: dict[str, bytes | None] = {
    "non_utf8": S.legacy_case_mapping_text().encode("utf-8").replace(
        b"reporter: defender", b"reporter: d\xff\xfefender"),
    "unreadable": None,
    "unparseable_yaml": b"open: [key\ncomment: {\n",
    "not_a_mapping": b"- open\n- comment\n",
    **{shape: S.legacy_case_mapping_text(source=text).encode("utf-8")
       for shape, text in S.CASE_SOURCE_SHAPES.items()},
}

# The tenant world: one planted tenant, and (for launch / resume) a source run and an episode
# built while its mapping was still valid


@dataclass
class World:
    tmp: Path
    capsys: Any
    planted: S.Planted
    source_run: Path | None = None
    episode: Path | None = None
    n: int = 0

    @property
    def scratch(self) -> Path:
        return self.tmp / "mapping-scratch"

    def next_id(self, what: str) -> str:
        """A fresh run id for this world's next `what` drive: a canonical UUID derived from a
        readable label."""
        self.n += 1
        return fixture_uuid(f"1222-tenant-check-{what}-{self.n}")

    def alert_shape(self, shape: str) -> Path:
        """Put the alert mapping into one of `S.plant_mapping_shape`'s shapes."""
        return S.plant_mapping_shape(self.planted, shape, scratch=self.scratch)

    def case_bytes(self, data: bytes | None) -> Path:
        """Write the case-history mapping's bytes (`None`: a valid file at mode 000)."""
        path = self.planted.case_mapping
        path.parent.mkdir(parents=True, exist_ok=True)  # the shipped template no longer has it
        with contextlib.suppress(FileNotFoundError):
            path.unlink()
        if data is None:
            path.write_text(S.legacy_case_mapping_text(), encoding="utf-8")
            path.chmod(0)
        else:
            path.write_bytes(data)
        return path

    def case_text(self, text: str) -> Path:
        return self.case_bytes(text.encode("utf-8"))

    def case_source(self, shape: str) -> Path:
        """A case-mapping `source` shape, through the shared planter."""
        self.case_text(S.legacy_case_mapping_text())
        return S.plant_case_source(self.planted, shape)

    def reset(self) -> None:
        """Back to a tenant the check accepts: the generic alert mapping, no case file."""
        S.restore_modes(self.planted.settings)
        self.alert_shape("valid")



def world(tmp_path: Path, capsys: Any, *, launchable: bool = False, **plant: Any) -> World:
    """A planted tenant whose mapping the check accepts. `launchable` also builds, while it is
    still valid, the branchable source run (`T.runs_base`) and a family manifest naming it
    (`T.episode`), so launch and sibling resume can be driven over the tenant afterwards."""
    w = World(tmp=Path(tmp_path), capsys=capsys, planted=S.plant_tenant(**plant))
    # A tenant tree after #1366 holds neither `settings/systems/` nor `settings/case-record.yaml` (the records hold them;
    # DC8: `check` reports a leftover of either as retired and ignored, a finding). The planter still writes both for the
    # many tests that derive their records from them; this world is about the tenant CHECK, so it drops them and the
    # directory's seeder falls back to the fixture's records.
    shutil.rmtree(w.planted.settings / "systems")
    (w.planted.settings / "case-record.yaml").unlink()
    if launchable:
        # A branch launch pins the knowledge commit its source's stamp names, so the tenant is
        # published for real first and the source stamped after, naming that commit (not the
        # placeholder a never-published tenant leaves in the stamp).
        published, refusal = S.publish_planted(w.tmp, w.planted)
        assert published is not None, f"the valid planted tenant did not publish: {refusal}"
        _base, src = location_path(T.runs_base)(w.tmp, tenant_id=w.planted.tenant_id)
        stamp = json.loads((src / "provenance.json").read_text(encoding="utf-8"))
        assert stamp.get("knowledge") == {"commit": published.commit}, stamp
        w.source_run = src
        w.episode = T.episode(w.tmp, root=w.planted.root / w.planted.tenant_id / "episodes",
                              doc=T.family_doc(source_run_dir=str(src)))
        with S.sym("records._episode_handle", "Episode").open(w.episode) as episode:
            T.episode_view(episode, tenant=w.planted.accept())
    return w


# The sites


@dataclass
class Verdict:
    """What one site did with the tenant: `refused` (and `text`, what it told its caller) or
    `passed` (positive evidence it went past the tenant check). `detail` is the site's own
    observation object (a `Drive`, the launcher's spawn double)."""

    site: str
    refused: bool
    text: str
    passed: bool
    detail: Any = None


class RolePreflight:
    """The role-model preflight seam of the launcher and of a sibling's `run.main`: records each
    call and answers `PAST_THE_CHECK`, so an entry point that reached it stops right there."""

    def __init__(self) -> None:
        self.calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def __call__(self, *args: Any, **kw: Any) -> int:
        self.calls.append((args, kw))
        return PAST_THE_CHECK


def _exit_text(stop: SystemExit) -> str:
    return stop.code if isinstance(stop.code, str) else f"exit {stop.code!r}"


def at_acceptance(w: World) -> Verdict:
    refused_cls = S.sym("tenancy._tenant", "TenantRefused")
    try:
        w.planted.accept()
    except refused_cls as refused:
        return Verdict("acceptance", True, str(refused), False)
    return Verdict("acceptance", False, "", True)


def tenant_py(capsys: Any, *argv: str, directory: Any = None) -> tuple[int, str]:
    """`cli/tenant.py`'s `main(argv, directory=)` in this process: its exit code and what it printed
    on stderr (its refusals and findings, `[tenant.py] <message>` each). `directory` defaults to
    one that knows no tenant (`check --folder` names none; Flow 4 fails closed otherwise)."""
    from defender.tests.support.tenancy._launch_publish_p4 import directory_for_argv

    capsys.readouterr()
    rc = S.mod("cli.tenant").main(list(argv), directory=directory if directory is not None else directory_for_argv(()))
    return rc, capsys.readouterr().err


def check_folder_verdict(capsys: Any, folder: Path) -> Verdict:
    rc, err = tenant_py(capsys, "check", "--folder", str(folder))
    on_mapping = bool(mapping_lines(err))
    return Verdict("check-folder", rc != 0 and on_mapping, err, not on_mapping)


def at_check_folder(w: World) -> Verdict:
    return check_folder_verdict(w.capsys, w.planted.knowledge)


def at_run_start(w: World, **run: Any) -> Verdict:
    run_id = w.next_id("run")
    d = S.run_alert(w.tmp / run_id, tenant=w.planted, **run)
    if d.raised is not None:
        return Verdict("run-start", False, f"run.main raised {d.raised!r}", False, d)
    started = bool(d.lifecycle_calls)
    return Verdict("run-start", d.refusal is not None and not started, d.refusal or "", started, d)


def at_branch_launch(w: World) -> Verdict:
    assert w.source_run is not None, "the world was not built launchable"
    preflight, spawn = RolePreflight(), T.FakeSpawn()
    # The launch pins the knowledge commit the source's stamp names, and the live capture
    # stamps that pinned export, not wherever `current` has moved since (another site of this
    # test may have republished the tenant): the fake live tree answers with the source's own.
    stamp = json.loads((w.source_run / "provenance.json").read_text(encoding="utf-8"))
    from defender.tests.support.tenancy._launch_publish_p4 import directory_for_argv

    text = ""
    argv = ["--tenant", w.planted.tenant_id, w.source_run.name, str(T.BRANCH_MESSAGE_ID)]
    try:
        S.mod("cli.learning.branch").main(
            argv, directory=directory_for_argv(argv),
            spawn=spawn, preflight=preflight,
            live_tree=T.source_capture(knowledge=stamp["knowledge"]))
    except SystemExit as stop:
        text = _exit_text(stop)
    passed = bool(preflight.calls)
    return Verdict("branch-launch", not passed and bool(text), text, passed, spawn)


def at_sibling_resume(w: World) -> Verdict:
    assert w.episode is not None, "the world was not built launchable"
    preflight = RolePreflight()
    lifecycles: list[dict[str, Any]] = []

    def lifecycle(**kw: Any) -> dict[str, Any]:
        lifecycles.append(kw)
        return {"output": "", "requests": 0, "truncated_by": None}

    from defender.tests.support.tenancy._launch_publish_p4 import in_process_publish

    text = ""
    try:
        # The in-process launch-time publish.
        S.mod("run").main(
            ["--episode", w.episode.name, "--world", "b",
             "--tenant", w.planted.tenant_id],
            directory=w.planted.directory, lifecycle=lifecycle, visualize=lambda *_a, **_k: None,
            preflight=preflight, publish=in_process_publish())
    except SystemExit as stop:
        text = _exit_text(stop)
    passed = bool(preflight.calls)
    return Verdict("sibling-resume", not passed and bool(text) and not lifecycles, text, passed,
                   lifecycles)


def at_policy_cli(w: World) -> Verdict:
    from defender.tests.support.tenancy._launch_publish_p4 import directory_for_argv

    w.capsys.readouterr()
    argv = ["show", "gather", "--run-dir", str(w.tmp / "policy-run"), "--tenant", w.planted.tenant_id]
    try:
        rc = S.mod("cli.policy_cli").main(argv, directory=directory_for_argv(argv))
    except SystemExit as stop:
        return Verdict("policy-cli", True, _exit_text(stop), False)
    out = w.capsys.readouterr().out
    return Verdict("policy-cli", False, "", rc == 0 and out.startswith("agent: gather"))


DRIVERS: dict[str, Callable[[World], Verdict]] = {
    "acceptance": at_acceptance,
    "check-folder": at_check_folder,
    "run-start": at_run_start,
    "branch-launch": at_branch_launch,
    "sibling-resume": at_sibling_resume,
    "policy-cli": at_policy_cli,
}


@contextlib.contextmanager
def fifo_never_blocks(path: Path) -> Iterator[None]:
    """A FIFO at the mapping's name is refused by LOOKING at it: a site that opens it for
    reading blocks until a writer comes. pytest here has no timeout, so after `FIFO_GRACE_S` a
    watcher stands in for the writer (the reader then sees end-of-file) and the test fails
    naming the block instead of hanging its worker."""
    stop = threading.Event()
    blocked: list[bool] = []

    def watch() -> None:
        if stop.wait(FIFO_GRACE_S):
            return
        while not stop.wait(0.05):
            try:
                fd = os.open(path, os.O_WRONLY | os.O_NONBLOCK)
            except OSError:
                continue  # no reader (ENXIO) — nobody is blocked on it
            os.close(fd)
            blocked.append(True)
            return

    watcher = threading.Thread(target=watch, daemon=True)
    watcher.start()
    try:
        yield
    finally:
        stop.set()
        watcher.join(timeout=5)
    assert not blocked, f"a site opened the FIFO at {path} for reading and blocked on it"


def verdicts(w: World, sites: Iterable[str] = SITES) -> dict[str, Verdict]:
    """Drive each named site over the tenant as it stands."""
    path = w.planted.alert_mapping
    is_fifo = path.is_fifo() and not path.is_symlink()
    guard = fifo_never_blocks(path) if is_fifo else contextlib.nullcontext()
    with guard:
        return {site: DRIVERS[site](w) for site in sites}


# The oracles


def mapping_lines(text: str) -> list[str]:
    """The lines of `text` naming a mapping file — a site's reasons — without the tenant CLI's
    `[tenant.py] ` prefix."""
    return [line.removeprefix(TENANT_PY) for line in text.splitlines()
            if any(name in line for name in MAPPING_NAMES)]


def assert_refused(v: Verdict, *names: str) -> None:
    assert v.refused, (
        f"{v.site} went past the tenant check instead of refusing it (it said {v.text!r})")
    assert not v.passed, f"{v.site} both refused and went past the check: {v.text!r}"
    assert "Traceback (most recent call last)" not in v.text, f"{v.site} crashed: {v.text}"
    for name in names:
        assert name in v.text, f"{v.site}'s refusal does not name {name}: {v.text!r}"


def assert_passed(v: Verdict) -> None:
    assert v.passed, f"{v.site} did not pass a tenant the check accepts (it said {v.text!r})"
    assert not v.refused, f"{v.site} both passed and refused: {v.text!r}"


def assert_no_run(v: Verdict) -> None:
    """Run start refused before anything existed: no run folder, no lifecycle, no model
    request, no lead."""
    d = v.detail
    assert d.run_dir is None, f"a run folder was made for a refused tenant: {d.run_dir}"
    assert not d.lifecycle_calls, "the investigation ran on a tenant the check refuses"
    assert d.main.requests == 0, "MAIN's model was asked on a refused tenant"
    assert not d.router.leads(), "a lead's model was asked on a refused tenant"


#: What a legacy tenant (#1359) still holds at the retired mapping, as the bytes written: a file under the retired
#: `settings/systems/` folder, which since #1366 is itself retired (the tenant's systems are records).
LEGACY_FOLDER = "settings/systems/"


@pytest.mark.parametrize("shape", _shape_params(CASE_FAULTS))
def test_a_legacy_case_history_folder_is_a_check_finding_naming_the_retired_folder(
        tmp_path: Path, capsys: Any, shape: str) -> None:
    """Whatever the retired case-history mapping holds, it sits in the retired `settings/systems/` folder, which
    `check --folder` reports as retired and ignored (nonzero exit, never parsed: every shape is the same finding, with no
    crash); acceptance and run start go on. (#1359 r4, then #1366 DC8: the new home of the case record is a record, not
    `settings/case-record.yaml`, so the finding names the retired folder, not a replacement file.)"""
    w = world(tmp_path, capsys)
    # The tenant's records are stated: the leftover folder planted below puts a `systems/` directory in `settings/`, which
    # the seeder's reading of the planted folder would take for "planted no systems" (R8: imported, empty).
    w.planted = dataclasses.replace(w.planted, records=R.fixture_records())
    sites = ("acceptance", "run-start")
    for v in verdicts(w, ("acceptance", "check-folder", "run-start")).values():
        assert_passed(v)  # control: with no case folder every site passes
    rc, err = tenant_py(capsys, "check", "--folder", str(w.planted.knowledge))
    assert not [line for line in err.splitlines() if LEGACY_FOLDER in line], f"control: no folder, no finding: {err}"
    try:
        w.case_bytes(CASE_FAULTS[shape])
        # A run starts from a published tenant, and `git add` cannot read a file at mode 000: an
        # unreadable file never reaches a published tenant, so that shape has no run-start site.
        planted_sites = tuple(site for site in sites if not (shape == "unreadable" and site == "run-start"))
        vs = verdicts(w, planted_sites)
        rc, err = tenant_py(capsys, "check", "--folder", str(w.planted.knowledge))
        assert rc != 0, err
        retired = [line for line in err.splitlines() if LEGACY_FOLDER in line and "retired" in line]
        assert retired, f"check --folder does not report the retired {LEGACY_FOLDER} folder: {err}"
        assert "Traceback" not in err, err
        assert_passed(vs["acceptance"])
        if "run-start" in vs:
            assert_passed(vs["run-start"])
    finally:
        S.restore_modes(w.planted.root)


# A5 — one tenant check at every entry point

#: A leftover `settings/alert-mapping.yaml` as bytes the retired rule refused (#1222 A5), each a regular file; or none.
#: A link, directory or FIFO at the name is the link walk's refusal, unchanged by #1345 and not a mapping finding.
LEFTOVER_SHAPES = ("missing_file", "valid", "empty_file", "comment_only", "explicit_null", "unparseable_yaml",
                   "non_utf8", "unknown_key", "misspelled_key", "null_entry", "empty_entry", "number_entry",
                   "list_entry", "empty_segment")
#: `unreadable` cannot be published (`git add` reads it), so only the sites that do not publish judge it.
UNPUBLISHED_SITES = ("acceptance", "check-folder", "policy-cli")


@pytest.mark.parametrize("shape", [*LEFTOVER_SHAPES, pytest.param("unreadable", marks=S.needs_non_root)])
def test_1345_o5_a_leftover_alert_mapping_file_is_inert_at_every_entry_point(tmp_path: Path, capsys: Any,
                                                                             shape: str) -> None:
    """Whatever bytes (or none) `settings/alert-mapping.yaml` holds, every site gives the same pass and names no mapping
    file: nothing requires or parses it. (#1345 O5, M1; retires #1222 A5's alert-mapping rows)"""
    w = world(tmp_path, capsys, launchable=True)
    for v in verdicts(w).values():
        assert_passed(v)  # control: the tenant passes every one of the seven sites
    try:
        w.alert_shape(shape)
        sites = UNPUBLISHED_SITES if shape == "unreadable" else SITES
        vs = verdicts(w, sites)
        for v in vs.values():
            assert_passed(v)
            assert mapping_lines(v.text) == [], f"{v.site} names a mapping file: {v.text!r}"
    finally:
        S.restore_modes(w.planted.root)


def test_1345_o5_the_run_settings_check_neither_requires_nor_parses_the_alert_mapping_file(tmp_path: Path,
                                                                                         capsys: Any) -> None:
    """`check_run_settings` over a run's settings copy passes with the file absent or malformed, and still refuses a
    settings folder missing a required file. (#1345 O5)"""
    w = world(tmp_path, capsys)
    check, refused = S.sym("tenancy._tenant", "check_run_settings"), S.sym("tenancy._tenant", "TenantRefused")
    w.alert_shape("missing_file")
    check(w.planted.settings)
    w.alert_shape("unparseable_yaml")
    check(w.planted.settings)
    (w.planted.settings / "verb-grants.yaml").unlink()  # control: the check still looks at what it requires
    with pytest.raises(refused, match="verb-grants.yaml"):
        check(w.planted.settings)


# Further cases

def test_p102_a_run_with_no_alert_mapping_starts_nothing(tmp_path: Path, capsys: Any) -> None:
    """A run for a tenant with no mapping saved is refused and reaches neither the ticket leg nor the curation enqueue;
    with its mapping both happen. (#1345 O4; was #1222 p102 over a faulted file)"""
    w = world(tmp_path, capsys)
    enqueued: list[Any] = []

    def enqueue(*args: Any, **kw: Any) -> bool:
        enqueued.append((args, kw))
        return True

    # Positive control, on both channels a refused run must leave untouched: a started run is
    # enqueued for curation and its record leg comments on the alert's ticket.
    S.ticket_the_tenant(w.planted)
    store = S.TicketStore(w.tmp)
    ok = at_run_start(w, alert=S.ticketed_alert(), tickets=S.ticket_writer(store),
                      update_ticket=True, enqueue=enqueue)
    assert_passed(ok)
    assert enqueued, "a started run was not enqueued for curation"
    assert store.paths(S.COMMENTS_SUFFIX) == [f"/tickets/{S.TICKET_KEY}/comments"], store.calls
    from defender.records.formats import ALERT_MAPPING_MISSING

    S.remap(w.planted, None)
    store = S.TicketStore(w.tmp)
    enqueued.clear()
    v = at_run_start(w, alert=S.ticketed_alert(), tickets=S.ticket_writer(store),
                     update_ticket=True, enqueue=enqueue)
    assert v.refused, v.text
    assert not v.passed, v.text
    assert " ".join(ALERT_MAPPING_MISSING.split()) in " ".join(v.text.split()), v.text
    assert_no_run(v)
    assert store.calls == [], f"a ticket leg ran for a refused run: {store.calls!r}"
    assert not enqueued, "a refused run was enqueued for curation"
    assert not v.detail.enqueued, "a refused run reached the curation enqueue"


# #1345 O5 — the file is retired: the tenant check neither requires nor parses it


def test_1345_a_knowledge_folder_without_an_alert_mapping_file_is_accepted(tmp_path: Path, capsys: Any) -> None:
    """No `settings/alert-mapping.yaml`: acceptance admits the tenant and `tenant.py check --folder` passes it,
    naming no mapping file. (#1345 O5)"""
    w = world(tmp_path, capsys)
    assert not w.planted.alert_mapping.exists()  # premise: the planted tenant carries no mapping file (#1345 O5)

    assert_passed(at_acceptance(w))
    rc, err = tenant_py(capsys, "check", "--folder", str(w.planted.knowledge))
    assert mapping_lines(err) == [], err  # not `rc == 0`: other findings (no `settings/systems/`) may fail the check


@pytest.mark.parametrize("template", ["tenant-fixture", "tenant-template"])
def test_1345_the_committed_tenants_carry_no_alert_mapping_file(template: str) -> None:
    """The shipped template and fixture drop the file (#1345 O5); the mapping lives in the database."""
    from defender.tests.support.tenancy._tenants1106 import committed_folder
    assert not (committed_folder(S.REPO_ROOT, template) / "settings" / ALERT_MAPPING).exists()
