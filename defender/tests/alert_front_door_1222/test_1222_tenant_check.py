"""#1222 S03 tenant_check — ONE tenant check, the same verdict at every entry point (A5).

`settings/alert-mapping.yaml` becomes a REQUIRED tenant file. One tenant check refuses, with a
fixed reason naming the file, a missing / empty / unparseable / malformed alert mapping, an
unknown or misspelled key, and a case-history `mapping.yaml` still carrying a TOP-LEVEL
`source:` key (C45: whatever its value; `open.source` is ordinary ticket configuration). It is
the same check at acceptance, `tenant.py setup`, `check --folder`, run start — and, through the
shared acceptance frame (C46, PA-13), at branch launch, sibling resume and the policy CLI. It
reports every fault, one fixed reason each, in a fixed order (C50). The judge resolves no
tenant and is unaffected (PA-13).

THE SEVEN SITES, each driven through its real entry point and nothing else
--------------------------------------------------------------------------
* acceptance      — `_tenant.accept_tenant` (`Planted.accept`); its `TenantRefused` text.
* setup           — `scripts/tenant.py` `main(["setup", id])`; exit code + stderr.
* check-folder    — `main(["check", "--folder", knowledge])`; stderr. Its EXIT CODE is not the
                    mapping verdict on a planted tenant: the grant census against the running
                    checkout reports verbs `TABLE_ELASTIC` leaves undecided (observed at base),
                    so the verdict is the lines that name a mapping file.
* run start       — `run.main` through `S.run_alert`; `d.refusal`, and the lifecycle never runs.
* branch launch   — `learning/branch/cli.main` over a source run `T.runs_base` built while the
                    mapping was valid. Its role-preflight seam records and answers
                    `PAST_THE_CHECK`, so a launch that got past the tenant check stops right
                    there: "the preflight was called" is the positive control, the `[branch]`
                    exit text the refusal. Base order: the episode's tenant is resolved first.
* sibling resume  — `run.main(["--resume", family.yaml, "--world", "b", ...])` over a
                    `T.episode` naming that source run; the same preflight discriminator.
* policy CLI      — `scripts/policy_cli.py` `main(["show", "gather", ...])` (only gather
                    resolves a tenant); exit 0 with its report, or the `defender-policy:` exit.

THE REASONS ORACLE. The fixed sentences are not coined, so no literal is asserted. A site's
reasons are the lines of what it said that name a mapping file (`check --folder` prints each as
`[tenant.py] <reason>`, the tenant CLI's documented shape). "The same reasons in the same
order" is: every reason `check --folder` gives appears in every other site's text, verbatim and
in that order, and no site names a mapping file more often than the check's reasons do.
"Fixed": two different contents of one fault (two unparseable files, two undecodable ones) give
byte-identical refusals; "no parser text": what the UTF-8 decoder and the YAML parser
themselves say about the file (computed here, from the file's own bytes) is in no refusal.

Faults are real files planted at the mapping's name (`S.plant_mapping_shape`, tier 1); a link's
target lives in `mapping-scratch/` beside the test, never in the data root (setup's one-tenant
guard refuses a data root holding anything but the tenant). `unreadable` needs a non-root user
(root reads mode 000, RJ-02) and is marked so; CI runs non-root.

Base 301f196c: nothing reads `alert-mapping.yaml`, so every alert-mapping refusal below is red
— except symlink / hard link / FIFO, which acceptance's no-follow walk already refuses at ANY
name in the settings half (PR-25). A top-level `source:` is today's case-mapping format, so its
refusal is red; `check --folder` and run start disagree on the case mapping's content faults
today (PA-14, RJ-02, MP14).
"""
from __future__ import annotations

import contextlib
import os
import re
import shutil
import stat
import threading
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import yaml

from defender.tests import _data_root_1078 as D
from defender.tests import _judge_921 as J
from defender.tests import _tenants1106 as T6
from defender.tests import _triplet_947 as T
from defender.tests.alert_front_door_1222 import _spec1222 as S
from defender.tests.tenant_1120_piece1 import _spec1120 as G

# =================================================================================================
# Names
# =================================================================================================

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
#: A5's four operator sites (p098, p104, p162, p164).
OPERATOR_SITES = ("acceptance", "setup", "check-folder", "run-start")

#: `alert_mapping.domain.distinguished`'s faults, `unreadable` only where the kernel can say so.
FAULT_PARAMS = [pytest.param(s, marks=S.needs_non_root) if s in S.ROOT_BLIND_SHAPES else s
                for s in S.MAPPING_FAULT_SHAPES]


def _shape_params(shapes: Iterable[str]) -> list[Any]:
    return [pytest.param(s, marks=S.needs_non_root) if s in S.ROOT_BLIND_SHAPES else s
            for s in shapes]


#: A customised pre-change `source:` section (p094: a deployed tenant's own edit of it).
CUSTOM_SOURCE = "source:\n  signature: alert_id\n  summary: rule.name\n  event_time: detected_at\n"
#: p096: a partial `source:` section naming only `event_time`.
SOURCE_ONLY_EVENT_TIME = "source:\n  event_time: detected_at\n"

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

# =================================================================================================
# The tenant world: one planted tenant, and (for launch / resume) a source run and an episode
# built while its mapping was still valid
# =================================================================================================


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
        self.n += 1
        return f"{what}-{self.n}"

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
        _base, src = T.runs_base(w.tmp, tenant_id=w.planted.tenant_id)
        w.source_run = src
        w.episode = T.episode(w.tmp, root=Path(os.environ["DEFENDER_EPISODES_BASE"]),
                              doc=T.family_doc(source_run_dir=str(src)))
        with S.sym("_episode_handle", "Episode").open(w.episode) as episode:
            T.episode_view(episode, tenant=w.planted.accept())
    return w


# =================================================================================================
# The sites
# =================================================================================================


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
    refused_cls = S.sym("_tenant", "TenantRefused")
    try:
        w.planted.accept()
    except refused_cls as refused:
        return Verdict("acceptance", True, str(refused), False)
    return Verdict("acceptance", False, "", True)


def tenant_py(capsys: Any, *argv: str) -> tuple[int, str]:
    """`scripts/tenant.py`'s `main(argv)` in this process: its exit code and what it printed
    on stderr (its refusals and findings, `[tenant.py] <message>` each)."""
    capsys.readouterr()
    rc = S.mod("scripts.tenant").main(list(argv))
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
    d = S.run_alert(w.tmp / run_id, tenant=w.planted, run_id=run_id, **run)
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
             str(T.BRANCH_MESSAGE_ID), "--continuation-prompt", "go"],
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
        rc = S.mod("scripts.policy_cli").main(
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


# =================================================================================================
# The oracles
# =================================================================================================


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


def evt_labels(store: S.TicketStore) -> list[str]:
    return [label for label in store.only_open().get("labels", [])
            if isinstance(label, str) and label.startswith("evt:")]


def judge_grade(tmp: Path, label: str) -> Any:
    """`learning.judge.grade_episode` over an archived episode of its own, holding the copies
    of the source run's alert and record a launch leaves in it (A1) — the judge's whole input,
    which names no tenant."""
    root = tmp / f"judge-{label}"
    ep = J.accepted_episode(root)
    S.plant_episode_copy(ep, alert=S.generic_alert(), facts={"signature": "R-1001"})
    from defender.tests._data_root_1078 import set_up_tenant
    repository = set_up_tenant(root / "judge-data", "acme").runs_repository()
    return J.grade(ep, runs=repository)


def judged(grade: Any) -> tuple[str, dict[str, Any]]:
    return grade.validity, {w: row.get("bucket") for w, row in J.rows(grade).items()}


# =================================================================================================
# bad_alert_mapping_refused_by_tenant_check
# =================================================================================================


@pytest.mark.parametrize("shape", FAULT_PARAMS)
def test_bad_alert_mapping_is_refused_by_the_tenant_check(tmp_path: Path, capsys: Any,
                                                          shape: str) -> None:
    """A missing, empty, comment-only, null, unparseable, non-UTF-8, non-regular (directory,
    symlink, hard link, FIFO) or unreadable alert mapping, an unknown or misspelled key, and
    an entry that is null, empty, a number, a list or a path with an empty segment are each
    refused by the tenant check with a fixed reason naming the file, with no parser text or
    host path; no run starts on it, and every fault is reported, one fixed reason each, in a
    fixed order."""
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


# =================================================================================================
# case_mapping_top_level_source_refused
# =================================================================================================


@pytest.mark.parametrize("shape", sorted(S.CASE_SOURCE_SHAPES))
def test_case_mapping_carrying_a_top_level_source_is_refused(tmp_path: Path, capsys: Any,
                                                             shape: str) -> None:
    """A case-history mapping.yaml carrying a top-level source key — populated, empty or
    null — is refused by the tenant check with a fixed reason naming the section and its
    move to the alert mapping; a source field inside open: is not refused."""
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


# =================================================================================================
# a5_one_tenant_check_at_every_entry_point
# =================================================================================================

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
    """For one tenant folder read by one user, acceptance, tenant.py setup, check --folder,
    run start, branch launch, sibling resume and the policy CLI reach the same verdict on
    the alert mapping and the case mapping, with the same fixed reasons in the same order."""
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


# =================================================================================================
# tenants_ship_alert_mapping
# =================================================================================================


def _committed_fixture_tenant(tenant_id: str = "playground") -> S.Planted:
    """The committed fixture tenant, set up under this test's data root as every replay that
    names no tenant runs it (`_tenants1106.fixture_tenant`: the real `create_tenant`, whose
    one-tenant guard wants it FIRST in the root — planted tenants are written by hand after)."""
    T6.fixture_tenant(tenant_id)
    root = D.current_data_root()
    return S.Planted(root=root, tenant_id=tenant_id, knowledge=root / tenant_id / "knowledge")


def _carrying(knowledge: Path, tenant_id: str) -> S.Planted:
    """A runnable planted tenant carrying `knowledge`'s OWN two mapping files, verbatim (the
    template's grants refuse every run, so its mapping is run through a tenant that grants)."""
    alert_mapping = knowledge / "settings" / ALERT_MAPPING
    assert alert_mapping.is_file(), f"{knowledge.name} ships no settings/{ALERT_MAPPING}"
    return S.plant_tenant(
        tenant_id,
        alert_mapping=alert_mapping.read_text(encoding="utf-8"),
        case_mapping=(knowledge / "settings" / S.CASE_MAPPING_REL).read_text(encoding="utf-8"))


# =================================================================================================
# r7_run_start_never_carries_a_faulted_case_mapping
# =================================================================================================


@pytest.mark.parametrize("shape", _shape_params(CASE_FAULTS))
def test_r7_run_start_never_carries_a_faulted_case_mapping_into_a_started_run(
        tmp_path: Path, capsys: Any, shape: str) -> None:
    """For each case-history mapping the one tenant check refuses -- non-UTF-8 bytes, an
    unreadable file, unparseable or non-mapping YAML, a top-level source: key (populated,
    empty or null) -- run start, branch launch and sibling resume, each driven over that
    tenant, stop at the check with its fixed reason naming the file; none starts a run, or
    opens a sibling, with ticket_mapping carried as a kept fault (which is what base does,
    MP14). Positive control: a mapping with a source: field inside open: loads and the run
    starts."""
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


# =================================================================================================
# The settled alert-mapping premises
# =================================================================================================

ENTRY_SHAPES = ("null_entry", "empty_entry", "number_entry", "list_entry", "empty_segment")


@pytest.mark.parametrize("shape", ENTRY_SHAPES)
def test_p051_mapping_entry_is_not_a_dotted_path(tmp_path: Path, capsys: Any, shape: str) -> None:
    """A mapping entry that is null, empty, a number, a list or a path with an empty segment
    makes the mapping malformed. The tenant check refuses it with a fixed reason naming the
    file, and no run starts. A fact's absence is expressed by omitting its key (p054)."""
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


@pytest.mark.parametrize("shape", ["misspelled_key", "unknown_key"])
def test_p052_mapping_has_a_misspelled_or_extra_key(tmp_path: Path, capsys: Any,
                                                    shape: str) -> None:
    """A misspelled or unknown key is refused like any malformed mapping."""
    w = world(tmp_path, capsys)
    sites = ("acceptance", "setup", "run-start")
    for v in verdicts(w, sites).values():
        assert_passed(v)
    # Like any malformed mapping: refused at the same sites a malformed entry is.
    w.alert_shape("null_entry")
    for v in verdicts(w, sites).values():
        assert_refused(v, ALERT_MAPPING)
    w.alert_shape(shape)
    vs = verdicts(w, sites)
    for v in vs.values():
        assert_refused(v, ALERT_MAPPING)
    assert_no_run(vs["run-start"])


@pytest.mark.parametrize("shape", ["empty_file", "comment_only", "explicit_null"])
def test_p053_mapping_file_is_empty_comment_only_or_null(tmp_path: Path, capsys: Any,
                                                         shape: str) -> None:
    """An empty, comment-only or null mapping file is refused, naming the file."""
    w = world(tmp_path, capsys)
    for v in verdicts(w, ("acceptance", "run-start")).values():
        assert_passed(v)
    w.alert_shape(shape)
    vs = verdicts(w, ("acceptance", "run-start"))
    for v in vs.values():
        assert_refused(v, ALERT_MAPPING)
    assert_no_run(vs["run-start"])


#: Two different contents of each content fault: a FIXED reason is the same for both.
UNPARSEABLE_PAIR = (b"signature: [rule.id\nevent_time: {\n", b"summary: {rule.description\n")
UNDECODABLE_PAIR = (b"signature: rule.\xff\xfeid\n", b"event_time: \xc3\x28detected_at\n")


@pytest.mark.parametrize("shape", _shape_params(
    ("directory", "unreadable", "non_utf8", "symlink", "hard_link", "fifo")))
def test_p058_alert_mapping_file_unreadable(tmp_path: Path, capsys: Any, shape: str) -> None:
    """The tenant check refuses, naming the file, any of these at the mapping's name: a
    directory, a file the reading site cannot read, non-UTF-8 bytes, a symlink, a hard link,
    a FIFO. No run starts."""
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


@pytest.mark.parametrize("source", [SOURCE_ONLY_EVENT_TIME,
                                    S.CASE_SOURCE_SHAPES["top_level_source_empty"],
                                    S.CASE_SOURCE_SHAPES["top_level_source_null"]],
                         ids=("only-event-time", "empty", "null"))
def test_p096_case_mapping_carries_source_with_only_event_time(tmp_path: Path, capsys: Any,
                                                               source: str) -> None:
    """A top-level source key is refused whatever its value, so a source: section naming
    only event_time is refused, naming the section; a partial source: section never leaves a
    vendor-default signature."""
    w = world(tmp_path, capsys)
    for v in verdicts(w, ("acceptance", "run-start")).values():
        assert_passed(v)
    w.case_text(S.case_mapping_text(source=source))
    vs = verdicts(w, ("acceptance", "run-start"))
    for v in vs.values():
        assert_refused(v, CASE_MAPPING)
        assert SOURCE_SECTION.search(v.text), f"{v.site} does not name the source section"
    # No run, so no record — no signature, vendor default or other, is left behind.
    assert_no_run(vs["run-start"])
    # As the situation has it, with no alert mapping either: both are named, still no run.
    w.alert_shape("missing_file")
    vs = verdicts(w, ("acceptance", "run-start"))
    for v in vs.values():
        assert_refused(v, CASE_MAPPING, ALERT_MAPPING)
    assert_no_run(vs["run-start"])


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


#: p162's tenants with two faults at once: an alert-mapping fault and a top-level `source:`.
P162_ALERT_FAULTS = ("missing_file", "misspelled_key", "non_utf8")


P163_CASES = [
    *[pytest.param("alert", s, marks=S.needs_non_root) if s in S.ROOT_BLIND_SHAPES
      else ("alert", s) for s in ("valid", *S.MAPPING_FAULT_SHAPES)],
    *[pytest.param("case", s, marks=S.needs_non_root) if s in S.ROOT_BLIND_SHAPES
      else ("case", s) for s in ("open_source_field", *CASE_FAULTS)],
]


@S.needs_non_root
def test_p164_mapping_readable_to_the_operator_but_not_the_run(tmp_path: Path,
                                                              capsys: Any) -> None:
    """Each site refuses what it cannot read, with the same fixed reason."""
    w = world(tmp_path, capsys)
    for v in verdicts(w, OPERATOR_SITES).values():
        assert_passed(v)
    try:
        for name, unreadable in ((ALERT_MAPPING, w.planted.alert_mapping),
                                 (CASE_MAPPING, w.planted.case_mapping)):
            unreadable.chmod(0)
            vs = verdicts(w, OPERATOR_SITES)
            for v in vs.values():
                assert_refused(v, name)
            assert_same_reasons(vs)
            assert_no_run(vs["run-start"])
            unreadable.chmod(0o644)
            # Readable again, every site passes it again.
            for v in verdicts(w, OPERATOR_SITES).values():
                assert_passed(v)
    finally:
        S.restore_modes(w.planted.root)
