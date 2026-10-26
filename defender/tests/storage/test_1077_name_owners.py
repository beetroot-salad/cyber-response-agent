"""#1077 — the name owners: `RunPaths`, `EpisodePaths`, and the one rule every composing accessor
inherits."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path, fixture_runs_base

from defender.tests.support.shared.contracts._spec1077 import fixture_run as _writer_run_1165

from pathlib import Path

import pytest

from defender.tests.support.shared.contracts import _spec1077 as S
from defender.tests.support.shared.contracts._by_path import DEFENDER
from defender.tests.support.tenancy import _tenants1106 as T1106
from defender.records import SessionPaths


@pytest.fixture
def base(tmp_path: Path) -> Path:
    return S.make_runs_base(tmp_path)


@pytest.fixture
def run_dir(base: Path) -> Path:
    return S.seed_run_tree(S.make_run_dir(base))


@pytest.fixture
def episode_dir(tmp_path: Path) -> Path:
    return S.make_episode_dir(tmp_path)


def _expected(kind: str) -> str:
    """The kind's own `path` cell, read off the kinds table the gate reads."""
    rows = {r["kind"]: r for r in S.kinds_rows()}
    return rows[kind]["path"]


def _concrete(template: str, acc: S.Accessor) -> str:
    """The TSV's path template with this suite's own component values substituted in."""
    subs = {
        "<lead>": S.LEAD_ID, "<seq>": str(S.SEQ), "<turn>": str(S.TURN), "<role>": S.ROLE,
        "<world UUID>": S.WORLD_ID, "<n>": "1",
        "<stage>": S.STAGE, "<episode_id>": S.EPISODE_ID,
    }
    out = template.split(",")[0].strip()
    for k, v in subs.items():
        out = out.replace(k, v)
    return out.rstrip("/")


# D1 — the enumerated names, walked off the kinds table

def test_run_paths_resolves_every_name_d1_enumerates(base, run_dir):
    """`RunPaths` resolves every run-level name the design enumerates, the three sidecars beside
    the run dir, the sessions directory and the session database."""
    missing = []
    for acc in S.ACCESSOR_FOR_KIND:
        if acc.owner != "run":
            continue
        try:
            got = S.resolve(acc, run_dir=run_dir, runs_base=base)
        except AttributeError:
            missing.append(f"{acc.kind} -> RunPaths.{acc.attr}")
            continue
        if acc.attr in S.UPWARD_ACCESSORS:
            assert got.parent in (base, base.parent / "sessions"), acc.kind
            continue
        want = _concrete(_expected(acc.kind), acc)
        assert got == run_dir / want, (
            f"{acc.kind}: RunPaths.{acc.attr} resolved {got.relative_to(run_dir)}, and the "
            f"kinds table says {want}")
    assert missing == [], (
        "claim G5: the owner owns exactly 7 accessors today and D1 takes it to roughly twenty; "
        f"these names have no accessor: {missing}")
    # The sessions directory and the database, whose root is a SIBLING of the runs base (C10/C15).
    assert location_path(S.RunPaths(run_dir).sessions_dir(fixture_runs_base(base))) == base.parent / "sessions"
    assert S.RunPaths(run_dir).session_db(fixture_runs_base(base), S.LINEAGE_ID).name == f"{S.LINEAGE_ID}.db"


# O8 — the two model-facing payload forms


def test_gathers_note_carries_the_owners_absolute_payload_path_and_the_gate_admits_it(run_dir):
    """The absolute payload path gather puts in its note is the owner's, and gather's own read
    gate admits it under the raw-payload shape."""
    from defender.runtime import permission
    from defender.runtime.agent_definition import compile_policy_for
    from defender.runtime import record_query

    rel = record_query.persist_payload(_writer_run_1165(run_dir), S.LEAD_ID, S.SEQ, '{"rows": []}')
    absolute = S.RunPaths(run_dir).payload(S.LEAD_ID, S.SEQ)
    assert run_dir / rel == absolute, (
        "gather's note composes `run_dir / record['payload_path']` (tools_gather.py:70); O8 "
        "names BOTH forms and requires both to be the owner's")

    policy = compile_policy_for(T1106.fixture_gather_def(), run_dir=run_dir, defender_dir=DEFENDER)
    decision = permission.decide_read(
        absolute, run_dir=run_dir, defender_dir=DEFENDER, policy=policy)
    assert decision.allow, (
        f"gather's own read gate refused the path it is told to `cat`: {decision.reason} — the "
        "GATHER_RAW_SHAPE admits it, and that admission is what makes O8's note usable")


# Decision 2 — one rule for every composing accessor


def test_no_composed_accessor_resolves_outside_its_root(base, run_dir, episode_dir):
    """No accessor taking a caller-supplied component — lead id, turn, role, token, sequence, label
    — resolves to a path outside its own root."""
    outside = base.parent / "outside"
    outside.mkdir(exist_ok=True)
    (outside / "planted").write_text("reachable?\n", encoding="utf-8")
    roots = {"run": run_dir, "episode": episode_dir}

    for acc in S.COMPOSING:
        root = S.upward_root(acc.attr, base) if acc.attr in S.UPWARD_ACCESSORS else roots[acc.owner]
        ordinary = S.resolve(acc, run_dir=run_dir, runs_base=base, episode_dir=episode_dir)
        ordinary_abs = Path(ordinary) if Path(ordinary).is_absolute() else root / ordinary
        assert ordinary_abs.resolve().is_relative_to(root.resolve()), (
            f"positive control failed: {acc.attr} does not even resolve inside {root}")
        for reach in ("../outside/planted", "../../outside/planted",
                      f"{outside}/planted", "..%2f..%2foutside"):
            args = tuple(reach if isinstance(a, str) else a for a in acc.args)
            try:
                got = S.resolve(acc, run_dir=run_dir, runs_base=base, episode_dir=episode_dir,
                                args=args)
            except Exception:  # noqa: BLE001
                continue
            got_abs = Path(got) if Path(got).is_absolute() else root / got
            assert got_abs.resolve().is_relative_to(root.resolve()), (
                f"{acc.owner}.{acc.attr}({reach!r}) resolved to {got_abs} — outside its root")


def test_lead_id_containing_path_traversal_segment(run_dir):
    """Security dive universal (1) at the lead-id component: a traversal-shaped lead_id must not
    resolve to a path outside the run dir."""
    owner = S.RunPaths(run_dir)
    assert owner.payload(S.LEAD_ID, S.SEQ).is_relative_to(run_dir / "gather_raw")
    assert owner.lead_claim(S.LEAD_ID).is_relative_to(run_dir / "gather_raw")
    assert owner.gather_summary(S.LEAD_ID).is_relative_to(run_dir)

    for hostile in ("../../etc", "..", "a/../../b", "/etc/passwd"):
        for call in (lambda x: owner.payload(x, S.SEQ), owner.lead_claim, owner.gather_summary):
            with pytest.raises(Exception):  # noqa: B017,PT011
                call(hostile)


def test_run_paths_plain_name_screens_non_plain_files(run_dir):
    """`RunPaths.access[plain_name]`'s plain-file-screen constraint refuses a non-plain-file
    target (a symlink, a directory, a device) the way its declared constraint promises."""
    from defender.records import plain_file
    real = run_dir / "report.md"
    real.write_text("# real\n", encoding="utf-8")
    assert plain_file(real), "positive control: an ordinary regular file passes the screen"

    link = run_dir / "linked.md"
    link.symlink_to(real)
    a_dir = run_dir / "a_dir"
    a_dir.mkdir()
    hard = run_dir / "hardlink.md"
    hard.hardlink_to(real)
    for non_plain, why in ((link, "a symlink"), (a_dir, "a directory"),
                           (hard, "a second link to one inode"),
                           (run_dir / "absent.md", "an absent entry")):
        assert not plain_file(non_plain), f"the plain-file screen admitted {why}"
    assert not plain_file(Path("/dev/null")), "the screen admitted a device"

    from defender._paths import PATHS
    from defender.tests.support.shared.contracts._import_blocker import run_blocked

    body = (
        "import sys\n"
        "from defender.records import plain_file\n"
        "import pathlib\n"
        "assert plain_file(pathlib.Path(sys.argv[1])) is True\n"
        "assert plain_file(pathlib.Path('/dev/null')) is False\n"
        "print('OK')\n")
    # `real` acquired a second name above (`hard`), so it is no longer plain — by the screen's
    # own rule. The closure probe gets it back as ONE name.
    hard.unlink()
    assert plain_file(real), "with the second name gone, the file is plain again"
    # `pydantic*`, not the three names the sibling probes list: five installed distributions
    # start with it, and the screen must not need any of them.
    done = run_blocked(body, block=("pydantic*",), argv=(str(real),), cwd=PATHS.repo_root)
    unreachable = (
        f"the plain-file screen is not reachable without a third-party package:\n{done.stderr!r}")
    assert done.returncode == 0, unreachable
    assert b"OK" in done.stdout, unreachable


# The session database — RG-4: pin the pattern BY REFERENCE, never re-spell it

def _refuses(run_dir: Path, base: Path, lineage) -> BaseException:
    from defender.runtime.session_store._write import InvalidCaseId
    with pytest.raises(InvalidCaseId) as excinfo:
        S.RunPaths(run_dir).session_db(fixture_runs_base(base), lineage)
    return excinfo.value


def test_session_db_refuses_a_lineage_id_the_case_id_pattern_rejects(base, run_dir):
    """`session_db` refuses a lineage id the case-id pattern rejects, exactly as `store_path_for`
    does today."""
    from defender.runtime.session_store._write import CASE_ID_RE, InvalidCaseId, store_path_for
    for lineage in ("-leading-dash", "has space", "a/b", "héllo", "..", "_under"):
        assert not CASE_ID_RE.match(lineage), (
            "the pattern is pinned BY REFERENCE at defender/records/_run_id.py (`CASE_ID_RE`) (RG-4); "
            "this test reads it, it does not re-spell it")
        _refuses(run_dir, base, lineage)
        with pytest.raises(InvalidCaseId):
            store_path_for(lineage, sessions=SessionPaths(fixture_runs_base(base)))
    # Positive control: the id today's resolver admits resolves to today's path.
    assert S.RunPaths(run_dir).session_db(fixture_runs_base(base), S.LINEAGE_ID) == store_path_for(
        S.LINEAGE_ID, sessions=SessionPaths(fixture_runs_base(base)))


# Decision 12 — composed-identifier collisions

def test_a_component_containing_the_delimiter_is_refused_at_mint_time(episode_dir):
    from defender.episodes._world_label import world_label_fault

    assert world_label_fault("plain") is None, "positive control: a delimiter-free label passes"
    for label in ("has-dash", "a-b"):
        fault = world_label_fault(label)
        assert fault is not None, (
            f"the label rule admitted {label!r}: N8 keeps the view-name rule's `-` refusal")
        assert "-" in fault, f"the label rule's refusal does not name the delimiter: {fault!r}"
    owner = S.EpisodePaths(episode_dir)
    assert owner.served_world(S.WORLD_ID).name == f"{S.WORLD_ID}.jsonl"
    for label in ("has.dot", "a.b"):
        fault = world_label_fault(label)
        assert fault is not None
        assert "." in fault



def test_the_composed_identifiers_and_the_session_db_path_carry_the_case_stability_refusal(
        base, run_dir, episode_dir):
    from defender.records._run_id import is_case_stable_id
    owner = S.EpisodePaths(episode_dir)
    by_reference = "the rule is today's `_run_id.is_case_stable_id`, reached by reference"
    assert is_case_stable_id("plain"), by_reference
    assert not is_case_stable_id("Plain"), by_reference

    assert owner.world_dir(S.WORLD_ID).name == S.WORLD_ID
    for label in ("Overlay", "OVERLAY", "oVerlay", S.WORLD_ID.upper()):
        with pytest.raises(Exception):  # noqa: B017,PT011
            owner.world_dir(label)
    with pytest.raises(Exception):  # noqa: B017,PT011
        owner.served_world(f"{S.EPISODE_ID}.Overlay")
    # The session-database path gains the check BESIDE its existing CASE_ID_RE format check.
    from defender.runtime.session_store._write import CASE_ID_RE, InvalidCaseId
    mixed = "Case-0011223344556677"
    assert CASE_ID_RE.match(mixed), (
        "the format check admits a mixed-case id today (`_run_id.CASE_ID_RE`) — the case-"
        "stability refusal is the NEW check beside it, not a re-spelling of the old one")
    with pytest.raises(InvalidCaseId):
        S.RunPaths(run_dir).session_db(fixture_runs_base(base), mixed)
    assert S.RunPaths(run_dir).session_db(fixture_runs_base(base), S.LINEAGE_ID).name.endswith(".db"), (
        "positive control: a case-stable lineage id still resolves")


# What the move must NOT change
