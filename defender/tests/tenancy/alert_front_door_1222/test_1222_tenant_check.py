"""One tenant check, the same verdict at every entry point, for the required
`settings/alert-mapping.yaml` and the case mapping's top-level `source:` key."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import contextlib
import os
import re
import stat
import threading
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from typing import Any

import pytest
import yaml

from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.tenancy.alert_front_door_1222 import _spec1222 as S

# Names

#: The alert mapping's file name (spec-fixed, F-MAPPING-FILE).
ALERT_MAPPING = S.ALERT_MAPPING_REL
#: The case-history mapping, named the way every reason naming it spells it.
CASE_MAPPING = S.CASE_MAPPING_REL.split("/", 1)[1]
MAPPING_NAMES = (ALERT_MAPPING, CASE_MAPPING)
#: The old top-level section of the case mapping; a reason refusing it names it (C45).
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

SITES = ("acceptance", "setup", "check-folder", "run-start", "branch-launch", "sibling-resume",
         "policy-cli")

#: `alert_mapping.domain.distinguished`'s faults, `unreadable` only where the kernel can say so.
FAULT_PARAMS = [pytest.param(s, marks=S.needs_non_root) if s in S.ROOT_BLIND_SHAPES else s
                for s in S.MAPPING_FAULT_SHAPES]


def _shape_params(shapes: Iterable[str]) -> list[Any]:
    return [pytest.param(s, marks=S.needs_non_root) if s in S.ROOT_BLIND_SHAPES else s
            for s in shapes]


#: Case-history mapping contents the one check refuses (r7), as the BYTES written at its name.
#: `unreadable` is a valid file put at mode 000 by `World.case_bytes`.
CASE_FAULTS: dict[str, bytes | None] = {
    "non_utf8": S.case_mapping_text().encode("utf-8").replace(
        b"reporter: defender", b"reporter: d\xff\xfefender"),
    "unreadable": None,
    "unparseable_yaml": b"open: [key\ncomment: {\n",
    "not_a_mapping": b"- open\n- comment\n",
    **{shape: S.case_mapping_text(source=text).encode("utf-8")
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
        """A fresh run id for this world's `what`-th drive: #1187 (declared change 1) — a
        canonical UUID, derived from a readable label."""
        self.n += 1
        return fixture_uuid(f"1222-tenant-check-{what}-{self.n}")

    def alert_shape(self, shape: str) -> Path:
        """Put the alert mapping into one of `alert_mapping.domain.distinguished`'s shapes."""
        return S.plant_mapping_shape(self.planted, shape, scratch=self.scratch)

    def case_bytes(self, data: bytes | None) -> Path:
        """Write the case-history mapping's bytes (`None`: a valid file at mode 000)."""
        path = self.planted.case_mapping
        with contextlib.suppress(FileNotFoundError):
            path.unlink()
        if data is None:
            path.write_text(S.case_mapping_text(), encoding="utf-8")
            path.chmod(0)
        else:
            path.write_bytes(data)
        return path

    def case_text(self, text: str) -> Path:
        return self.case_bytes(text.encode("utf-8"))

    def case_source(self, shape: str) -> Path:
        """`mapping_yaml.domain.distinguished`'s shapes, through the shared planter."""
        self.case_text(S.case_mapping_text())
        return S.plant_case_source(self.planted, shape)

    def reset(self) -> None:
        """Back to a tenant the check accepts: the generic alert mapping, a source-free case
        mapping."""
        S.restore_modes(self.planted.settings)
        self.alert_shape("valid")
        self.case_text(S.case_mapping_text())



def world(tmp_path: Path, capsys: Any, *, launchable: bool = False, **plant: Any) -> World:
    """A planted tenant whose mapping the check accepts. `launchable` also builds, while it is
    still valid, the branchable source run (`T.runs_base`) and a family manifest naming it
    (`T.episode`), so launch and sibling resume can be driven over the tenant afterwards."""
    w = World(tmp=Path(tmp_path), capsys=capsys, planted=S.plant_tenant(**plant))
    if launchable:
        _base, src = location_path(T.runs_base)(w.tmp, tenant_id=w.planted.tenant_id)
        w.source_run = src
        w.episode = T.episode(w.tmp, root=w.planted.root / w.planted.tenant_id / "episodes",
                              doc=T.family_doc(source_run_dir=str(src)))
        with S.sym("episodes._episode_handle", "Episode").open(w.episode) as episode:
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


def tenant_py(capsys: Any, *argv: str) -> tuple[int, str]:
    """`cli/tenant.py`'s `main(argv)` in this process: its exit code and what it printed
    on stderr (its refusals and findings, `[tenant.py] <message>` each)."""
    capsys.readouterr()
    rc = S.mod("cli.tenant").main(list(argv))
    return rc, capsys.readouterr().err


def at_setup(w: World) -> Verdict:
    rc, err = tenant_py(w.capsys, "setup", w.planted.tenant_id)
    return Verdict("setup", rc != 0, err, rc == 0)


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
    text = ""
    try:
        S.mod("learning.branch.cli").main(
            ["--tenant", w.planted.tenant_id, w.source_run.name,
             str(T.BRANCH_MESSAGE_ID), *T.retired_continuation_argv()],
            spawn=spawn, preflight=preflight, live_tree=T.source_capture())
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

    text = ""
    try:
        S.mod("run").main(
            ["--episode", w.episode.name, "--world", "b",
             "--tenant", w.planted.tenant_id],
            lifecycle=lifecycle, visualize=lambda *_a, **_k: None, preflight=preflight)
    except SystemExit as stop:
        text = _exit_text(stop)
    passed = bool(preflight.calls)
    return Verdict("sibling-resume", not passed and bool(text) and not lifecycles, text, passed,
                   lifecycles)


def at_policy_cli(w: World) -> Verdict:
    w.capsys.readouterr()
    try:
        rc = S.mod("cli.policy_cli").main(
            ["show", "gather", "--run-dir", str(w.tmp / "policy-run"),
             "--tenant", w.planted.tenant_id])
    except SystemExit as stop:
        return Verdict("policy-cli", True, _exit_text(stop), False)
    out = w.capsys.readouterr().out
    return Verdict("policy-cli", False, "", rc == 0 and out.startswith("agent: gather"))


DRIVERS: dict[str, Callable[[World], Verdict]] = {
    "acceptance": at_acceptance,
    "setup": at_setup,
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


def normalized(text: str, folders: Iterable[Path]) -> str:
    for folder in folders:
        text = text.replace(str(folder), "<knowledge>")
    return text


def assert_same_reasons(vs: dict[str, Verdict], *, reference: str = "check-folder",
                        folders: Iterable[Path] = ()) -> list[str]:
    """Every site carries the check's reasons — `reference`'s lines naming a mapping file —
    verbatim and in that order, and names no mapping file more often than they do. `folders`
    are knowledge folders spelled `<knowledge>` before comparing (one tenant repo checked in
    two places)."""
    folders = tuple(folders)
    ref = [normalized(r, folders) for r in mapping_lines(vs[reference].text)]
    assert ref, f"{reference} named no mapping file: {vs[reference].text!r}"
    for site, v in vs.items():
        if site == reference:
            continue
        text = normalized(v.text, folders)
        pos = 0
        for reason in ref:
            at = text.find(reason, pos)
            assert at >= 0, (
                f"{site} does not carry the check's reason {reason!r} (in the check's order); "
                f"{site} said {v.text!r}, the check said {vs[reference].text!r}")
            pos = at + len(reason)
        for name in MAPPING_NAMES:
            want = sum(r.count(name) for r in ref)
            assert text.count(name) == want, (
                f"{site} names {name} {text.count(name)}x where the check's reasons name it "
                f"{want}x — a reason the check does not give, or one it gives that {site} drops: "
                f"{v.text!r}")
    return ref


def first_named(text: str) -> tuple[str, ...]:
    """The mapping files `text` names, in the order it first names them."""
    found = [(text.find(n), n) for n in MAPPING_NAMES if n in text]
    return tuple(n for _at, n in sorted(found))


def parser_text(path: Path) -> list[str]:
    """What the UTF-8 decoder and the YAML parser THEMSELVES say about the bytes at `path` — the
    text a fixed reason must not carry. Empty for a file they both accept or cannot be handed
    (a link, a directory, a FIFO — never opened here — or a file this user cannot read)."""
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            return []
        raw = path.read_bytes()
    except OSError:
        return []
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError as bad:
        return [bad.reason, "codec can't decode"]
    try:
        yaml.safe_load(decoded)
    except yaml.MarkedYAMLError as bad:
        out = [s for s in (bad.problem, bad.context) if s]
        if bad.problem_mark is not None:
            mark = bad.problem_mark
            out.append(f"line {mark.line + 1}, column {mark.column + 1}")
        return out
    return []


def assert_no_parser_text(v: Verdict, fragments: Iterable[str]) -> None:
    for fragment in fragments:
        assert fragment not in v.text, (
            f"{v.site}'s refusal carries the parser's own text {fragment!r}: {v.text!r}")


def carried_values(doc: Any) -> set[str]:
    """Every scalar an alert document carries, as text (a fact a mapping names is one of these,
    carried as-is: C16)."""
    if isinstance(doc, dict):
        return set().union(*(carried_values(v) for v in doc.values())) if doc else set()
    if isinstance(doc, list):
        return set().union(*(carried_values(v) for v in doc)) if doc else set()
    if isinstance(doc, (str, int)) and not isinstance(doc, bool):
        return {str(doc)}
    return set()


# bad_alert_mapping_refused_by_tenant_check


@pytest.mark.parametrize("shape", FAULT_PARAMS)
def test_bad_alert_mapping_is_refused_by_the_tenant_check(tmp_path: Path, capsys: Any,
                                                          shape: str) -> None:
    w = world(tmp_path, capsys)
    # Positive control: the same tenant with its valid mapping is accepted and its run starts.
    for v in verdicts(w, ("acceptance", "run-start")).values():
        assert_passed(v)
    try:
        oracle = parser_text(w.alert_shape(shape))
        vs = verdicts(w, ("acceptance", "run-start"))
        for v in vs.values():
            assert_refused(v, ALERT_MAPPING)
            assert_no_parser_text(v, oracle)
        assert_no_run(vs["run-start"])
        assert vs["acceptance"].text in vs["run-start"].text, (
            "run start does not give the tenant check's own reason: "
            f"{vs['run-start'].text!r} vs {vs['acceptance'].text!r}")
        # Every fault reported, one reason each, in a fixed order: a second fault, in the
        # other file, joins the first.
        w.case_source("top_level_source_populated")
        both = verdicts(w, ("acceptance", "run-start"))
        for v in both.values():
            assert_refused(v, ALERT_MAPPING, CASE_MAPPING)
        assert_no_run(both["run-start"])
        assert both["acceptance"].text in both["run-start"].text
        assert first_named(both["acceptance"].text) == first_named(both["run-start"].text)
        assert at_acceptance(w).text == both["acceptance"].text, "the report's order is not fixed"
    finally:
        S.restore_modes(w.planted.root)


# case_mapping_top_level_source_refused


@pytest.mark.parametrize("shape", sorted(S.CASE_SOURCE_SHAPES))
def test_case_mapping_carrying_a_top_level_source_is_refused(tmp_path: Path, capsys: Any,
                                                             shape: str) -> None:
    w = world(tmp_path, capsys)
    # Positive control: a `source` field inside `open:` is ticket configuration — accepted.
    w.case_source("open_source_field")
    assert_passed(at_acceptance(w))
    # The same key at the top level is the old section: refused, naming the file, the section
    # and (the alert mapping being in place, nothing else would name it) the move to it.
    w.case_source(shape)
    v = at_acceptance(w)
    assert_refused(v, CASE_MAPPING)
    assert SOURCE_SECTION.search(v.text), f"the refusal does not name the source section: {v.text!r}"
    assert THE_MOVE.search(v.text), f"the refusal does not name the move to the alert mapping: {v.text!r}"


# a5_one_tenant_check_at_every_entry_point

A5_FAULTS: dict[str, tuple[str | None, str | None, tuple[str, ...]]] = {
    # label: (alert-mapping shape, case-mapping source shape, files the refusal names)
    "alert-mapping-missing": ("missing_file", None, (ALERT_MAPPING,)),
    "alert-mapping-unparseable": ("unparseable_yaml", None, (ALERT_MAPPING,)),
    "alert-mapping-unknown-key": ("unknown_key", None, (ALERT_MAPPING,)),
    "case-mapping-top-level-source": (None, "top_level_source_populated", (CASE_MAPPING,)),
    "both-files": ("missing_file", "top_level_source_populated", (ALERT_MAPPING, CASE_MAPPING)),
}


@pytest.mark.parametrize("fault", sorted(A5_FAULTS))
def test_a5_every_entry_point_gives_the_same_tenant_verdict(tmp_path: Path, capsys: Any,
                                                            fault: str) -> None:
    w = world(tmp_path, capsys, launchable=True)
    # Positive control: the valid tenant passes every one of the seven.
    for v in verdicts(w).values():
        assert_passed(v)
    alert_shape, case_shape, names = A5_FAULTS[fault]
    if alert_shape is not None:
        w.alert_shape(alert_shape)
    if case_shape is not None:
        w.case_source(case_shape)
    vs = verdicts(w)
    for v in vs.values():
        assert_refused(v, *names)
    assert_same_reasons(vs)
    assert_no_run(vs["run-start"])
    assert not vs["branch-launch"].detail.launches, "a sibling was spawned on a refused tenant"


# tenants_ship_alert_mapping


# r7_run_start_never_carries_a_faulted_case_mapping


@pytest.mark.parametrize("shape", _shape_params(CASE_FAULTS))
def test_r7_run_start_never_carries_a_faulted_case_mapping_into_a_started_run(
        tmp_path: Path, capsys: Any, shape: str) -> None:
    w = world(tmp_path, capsys, launchable=True)
    sites = ("run-start", "branch-launch", "sibling-resume")
    # Positive control: `open.source` loads, the run starts and its tenant record carries the
    # loaded mapping, never a kept fault; launch and resume get past the check.
    w.case_source("open_source_field")
    ok = verdicts(w, sites)
    for v in ok.values():
        assert_passed(v)
    kept_fault = S.sym("runtime.case_ticket", "CaseTicketError")
    carried = ok["run-start"].detail.lifecycle_calls[0]["tenant"].ticket_mapping
    assert not isinstance(carried, kept_fault), f"the run carried a kept fault: {carried!r}"
    try:
        w.case_bytes(CASE_FAULTS[shape])
        vs = verdicts(w, sites)
        for v in vs.values():
            assert_refused(v, CASE_MAPPING)
        run = vs["run-start"].detail
        assert not run.lifecycle_calls, (
            "a run started carrying the case mapping as a kept fault: "
            f"{[c['tenant'].ticket_mapping for c in run.lifecycle_calls]!r}")
        assert_no_run(vs["run-start"])
        assert not vs["branch-launch"].detail.launches, "a sibling was opened on the tenant"
        assert not vs["sibling-resume"].detail, "a sibling's investigation ran on the tenant"
    finally:
        S.restore_modes(w.planted.root)


# The settled alert-mapping premises

ENTRY_SHAPES = ("null_entry", "empty_entry", "number_entry", "list_entry", "empty_segment")


@pytest.mark.parametrize("shape", ENTRY_SHAPES)
def test_p051_mapping_entry_is_not_a_dotted_path(tmp_path: Path, capsys: Any, shape: str) -> None:
    w = world(tmp_path, capsys)
    # Positive control: omitting the key is how absence is said — accepted, and the run starts.
    w.alert_shape("no_signature_key")
    for v in verdicts(w, ("acceptance", "run-start")).values():
        assert_passed(v)
    w.alert_shape(shape)
    vs = verdicts(w, ("acceptance", "run-start"))
    for v in vs.values():
        assert_refused(v, ALERT_MAPPING)
    assert_no_run(vs["run-start"])


@pytest.mark.parametrize("shape", _shape_params(
    ("directory", "unreadable", "non_utf8", "symlink", "hard_link", "fifo")))
def test_p058_alert_mapping_file_unreadable(tmp_path: Path, capsys: Any, shape: str) -> None:
    w = world(tmp_path, capsys)
    for v in verdicts(w, ("acceptance", "run-start")).values():
        assert_passed(v)
    try:
        w.alert_shape(shape)
        vs = verdicts(w, ("acceptance", "run-start"))
        for v in vs.values():
            assert_refused(v, ALERT_MAPPING)
        assert_no_run(vs["run-start"])
    finally:
        S.restore_modes(w.planted.root)


def test_p095_case_mapping_carries_source_and_an_alert_mapping(tmp_path: Path,
                                                              capsys: Any) -> None:
    """The source: section is named as refused; nothing silently wins."""
    w = world(tmp_path, capsys, alert_mapping={
        "signature": "rule.uuid", "event_time": "detected_at", "summary": "rule.description"})
    alert = S.generic_alert(rule={"id": "R-1001", "uuid": "U-7f3a", "name": "Generic outbound",
                                  "description": "Host contacted a rare destination."})
    w.case_text(S.case_mapping_text(source="source:\n  signature: rule.id\n"))
    vs = {"acceptance": at_acceptance(w), "run-start": at_run_start(w, alert=alert)}
    for v in vs.values():
        assert_refused(v, CASE_MAPPING)
        assert SOURCE_SECTION.search(v.text), f"{v.site} does not name the source section"
    # Nothing won: no run, so no record carries either signature.
    assert_no_run(vs["run-start"])
    # Positive control: `source:` dropped, the run starts and its record holds the alert
    # mapping's signature — the `rule.uuid` value, never `rule.id`.
    w.case_text(S.case_mapping_text())
    ok = at_run_start(w, alert=alert)
    assert_passed(ok)
    assert ok.detail.recorded("signature") == "U-7f3a"


P098_FAULTS: dict[str, tuple[str | None, str | None, str]] = {
    "alert-mapping-missing": ("missing_file", None, ALERT_MAPPING),
    "alert-mapping-malformed": ("null_entry", None, ALERT_MAPPING),
    "alert-mapping-unknown-key": ("unknown_key", None, ALERT_MAPPING),
    "case-mapping-top-level-source": (None, "top_level_source_populated", CASE_MAPPING),
}


#: The fault shapes p102 runs through the run's own channels — one of each kind.
P102_SHAPES = ("missing_file", "empty_file", "unparseable_yaml", "non_utf8", "directory",
               "unknown_key", "null_entry", "empty_segment", "unreadable")


@pytest.mark.parametrize("shape", _shape_params(P102_SHAPES))
def test_p102_run_starts_with_a_faulted_alert_mapping(tmp_path: Path, capsys: Any,
                                                      shape: str) -> None:
    """A run never starts on a faulted mapping, and the refusal names the file."""
    w = world(tmp_path, capsys)
    enqueued: list[Any] = []

    def enqueue(*args: Any, **kw: Any) -> bool:
        enqueued.append((args, kw))
        return True

    # Positive control: a started run opens its case ticket, records into it and is enqueued
    # for curation — the channels a refused run must leave untouched.
    store = S.TicketStore()
    ok = at_run_start(w, tickets=S.ticket_writer(store), update_ticket=True, enqueue=enqueue)
    assert_passed(ok)
    assert store.opened(), "a started run opened no case ticket"
    assert enqueued, "a started run was not enqueued for curation"
    try:
        w.alert_shape(shape)
        store = S.TicketStore()
        enqueued.clear()
        v = at_run_start(w, tickets=S.ticket_writer(store), update_ticket=True, enqueue=enqueue)
        assert_refused(v, ALERT_MAPPING)
        assert_no_run(v)
        assert store.calls == [], f"a ticket leg ran for a refused run: {store.calls!r}"
        assert not enqueued, "a refused run was enqueued for curation"
        assert not v.detail.enqueued, "a refused run reached the curation enqueue"
    finally:
        S.restore_modes(w.planted.root)
