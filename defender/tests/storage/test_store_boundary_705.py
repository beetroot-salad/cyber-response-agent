"""#705 store boundary: R1 placement (the store sits beside runs/, not under it; case-id resolver rejects non-conforming ids; unreachable from the box; host readers do not follow a planted symlink) and R2 read authorization (role-scoped projection)."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_runs_base

from defender.tests.support.shared.contracts._spec1077 import fixture_run as _run_handle_1165
from defender.tests.support.shared._fixture_uuid import fixture_uuid

import errno as errno_mod
import json
import os
from pathlib import Path

from defender.records import RunPaths

import pytest

from defender.tests.support.integrations._defender_sql import EXIT_OK, assert_query_error, run_sql_py
from defender.tests.support.storage._session_store_705 import (
    complete_pair,
    make_store,
    runs_base,
    sql,
    store_mod,
    text_response,
    tool_call_response,
    tool_return_request,
    user_request,
)
from defender.tests.support.sandbox._docker import daemon_reachable, is_dood
from defender.records import SessionPaths
from defender.tests.support.storage._store_owner import owned_store

DEFENDER = Path(__file__).resolve().parents[2]
REPO_ROOT = DEFENDER.parent
SECRET = "STORE-BYTES-DEFENDER-GOALS-4242"


# R1 — placement, and the pointer file's own domain

def test_store_path_is_not_under_the_runs_base(tmp_path):
    """The resolved store path is a SIBLING of the runs base, not a descendant of it, for
    every case_id — including ones that look like run ids."""
    ss = store_mod()
    base = runs_base(tmp_path)

    # The run-id-shaped id is spelled the way the host mints run ids since #1077 — casefolded
    # (`records/_run_id.py`); the store now refuses an id that is not case-stable (#1077, O2).
    for case_id in ("case-alpha", "20260718t101500z-boxspec", "runs", "case.with.dots"):
        path = Path(ss.store_path_for(case_id, sessions=SessionPaths(fixture_runs_base(base))))
        assert base.resolve() not in path.resolve().parents, (
            f"{case_id}: the store landed UNDER the runs base at {path}")
        assert path.resolve().parent.parent == base.resolve().parent, (
            f"{case_id}: the store must be a sibling of the runs base; got {path}")
        assert path.name.endswith(".db")

    store = owned_store(case_id="case-alpha", sessions=SessionPaths(fixture_runs_base(base)))
    # #1187 (declared change 1): a run id is a canonical UUID — the folder is fixture_uuid(<label>)
    run_dir = base / fixture_uuid("20260718t101500z-alpha")
    run_dir.mkdir(parents=True)
    ss.write_case_pointer(_run_handle_1165(run_dir), case_id="case-alpha", store_path=store.path)
    resolved = Path(ss.resolve_store_path(_run_handle_1165(run_dir)))
    assert base.resolve() not in resolved.resolve().parents
    pointer = RunPaths(run_dir).session_pointer()
    assert pointer.name == f"{run_dir.name}.session-pointer.json", pointer
    assert sorted(base.iterdir()) == sorted([run_dir, pointer]), (
        "the runs base must contain only run dirs and their own host sidecars — no store file "
        "for held_out/trace_lesson to skip")


def test_the_resolver_rejects_a_non_conforming_case_id(tmp_path):
    ss = store_mod()
    base = runs_base(tmp_path)

    assert Path(ss.store_path_for("case-alpha", sessions=SessionPaths(fixture_runs_base(base)))).name == "case-alpha.db", (
        "positive control: a conforming slug resolves")

    hostile = [
        "../../etc/passwd", "/etc/passwd", "case\x00id", "case id", "case;rm -rf /",
        "case`id`", "case$(id)", "case|id", "..", ".", "", "case\n", "case-abc\n",
        "caseature\uff0fescape", "C:\\case",
    ]
    for value in hostile:
        with pytest.raises(ss.InvalidCaseId):
            ss.store_path_for(value, sessions=SessionPaths(fixture_runs_base(base)))
        with pytest.raises(ss.InvalidCaseId), ss.open_store(
                case_id=value, sessions=SessionPaths(fixture_runs_base(base))):
            pass

    assert ss.CASE_ID_RE.pattern.endswith("\\Z"), (
        f"anchor with \\Z, not $: {ss.CASE_ID_RE.pattern!r} admits a trailing newline "
        "(adv:PO7's one hole, reproduced here rather than re-learned)")

    leaked = [p.name for p in base.parent.rglob("*") if "passwd" in p.name or "\n" in p.name]
    assert leaked == [], f"a rejected case_id composed a path anyway: {leaked}"


# R1's corollary — the box, and the host-side leg adv:PO5b opened

_NO_DAEMON = not daemon_reachable()
_DOOD = (not _NO_DAEMON) and is_dood()
requires_box = pytest.mark.skipif(
    _NO_DAEMON or _DOOD,
    reason=("no reachable Docker daemon" if _NO_DAEMON else
            "docker-outside-of-Docker: bind sources resolve on the real daemon host and "
            "are invisible from this process, so a bind assertion would assert against a "
            "filesystem it cannot see (adv:PO5's own deviation note). Run on a native "
            "daemon."))

_READ_PATH = '''
import json, sys
p = sys.argv[1]
try:
    data = open(p, "rb").read()
    print(json.dumps({"read": data.decode("utf-8", "replace"), "exc": None, "errno": None}))
except OSError as e:
    print(json.dumps({"read": None, "exc": type(e).__name__, "errno": e.errno}))
'''


@requires_box
@pytest.mark.box
def test_the_store_is_unreachable_from_inside_the_box(tmp_path):
    """Neither the bash lane nor `defender-sql` can open or read the store from inside the
    box, while the run dir remains readable AND writable from there."""
    from defender.execution.bash_exec import parse
    from defender.box import start_box, stop_box

    base = runs_base(tmp_path)
    store = owned_store(case_id="case-alpha", sessions=SessionPaths(fixture_runs_base(base)))
    session_id = store.new_session(agent_id="main")
    store.append(session_id, [user_request(SECRET)], agent_id="main")
    store.close()

    run_dir = base / "20260718t101500z-boxed"
    (run_dir / "gather_raw").mkdir(parents=True)
    (run_dir / "alert.json").write_text('{"id": "boxed"}', encoding="utf-8")
    (run_dir / "sentinel.txt").write_text("RUN-DIR-IS-READABLE", encoding="utf-8")

    from defender.tests.support.storage._alert_plant import plant_alert
    plant_alert(run_dir)
    box = start_box(run_dir, DEFENDER)
    try:
        probe = run_dir / "_probe_store.py"
        probe.write_text(_READ_PATH, encoding="utf-8")
        cmd = f"python3 /runs/current/{probe.name} {store.path}"
        res = box.run_parsed(parse(cmd), command=cmd, cwd=Path("/runs/current"), timeout=60)
        assert res.rc == 0, res.err
        got = json.loads(res.out.decode("utf-8"))
        assert got["read"] is None, f"the box read the store: {got}"
        assert got["errno"] == errno_mod.ENOENT, (
            f"expected ABSENT (ENOENT), got errno={got['errno']} ({got['exc']}) — a DENIED "
            "path means something mounted it and a matcher refused, which is not the "
            "boundary")

        cat = f"cat {store.path}"
        out = box.run_parsed(parse(cat), command=cat, cwd=Path("/runs/current"), timeout=60)
        assert SECRET not in out.out.decode("utf-8", "replace")

        # positive control: the run dir IS reachable and writable from inside the box
        ctl = "cat /runs/current/sentinel.txt"
        control = box.run_parsed(parse(ctl), command=ctl, cwd=Path("/runs/current"), timeout=60)
        assert "RUN-DIR-IS-READABLE" in control.out.decode("utf-8")
    finally:
        stop_box(box)


def test_host_readers_do_not_dereference_a_symlink_out_of_the_run_dir(tmp_path):
    from defender.learning import lead_repository

    base = runs_base(tmp_path)
    store = owned_store(case_id="case-alpha", sessions=SessionPaths(fixture_runs_base(base)))
    session_id = store.new_session(agent_id="main")
    store.append(session_id, [user_request(SECRET)], agent_id="main")
    store.close()

    run_dir = base / "20260718t101500z-leak"
    gather_raw = run_dir / "gather_raw"
    gather_raw.mkdir(parents=True)
    (gather_raw / "l-001.lead.json").write_text("ORDINARY-ARTIFACT", encoding="utf-8")
    (run_dir / "executed_queries.jsonl").write_text("", encoding="utf-8")
    os.symlink(store.path, gather_raw / "leak.db")
    os.symlink(base.parent / "does-not-exist.db", gather_raw / "dangling.db")

    dest = tmp_path / "staged"
    lead_repository.stage_tables(run_dir, dest)

    staged = dest / "gather_raw"
    assert (staged / "l-001.lead.json").read_text() == "ORDINARY-ARTIFACT", (
        "positive control: an ordinary artifact must still stage")
    copied = "".join(p.read_bytes().decode("utf-8", "replace")
                     for p in staged.rglob("*") if p.is_file() and not p.is_symlink())
    assert SECRET not in copied, (
        "the collector dereferenced a box-authored symlink out of run_dir (adv:PO5b)")
    assert not (staged / "leak.db").is_file() or (staged / "leak.db").is_symlink(), (
        "a symlink out of run_dir must be refused or preserved as a link, never resolved")


# R2 — the leak test, its positive control, and the parity

def _actor_fixture(tmp_path):
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    store.append(session_id, [
        user_request(f"the defender's goal: {SECRET}"),
        tool_call_response("query", {"system": "elastic", "lead_id": "l-001"},
                           tool_call_id="q1"),
        tool_return_request("query", f"raw hits containing {SECRET}", tool_call_id="q1"),
        text_response(f"hypothesis: {SECRET}"),
    ], agent_id="main")
    store.write_config({"models": {"main": SECRET}, "corpus": {"git_sha": "abc"},
                        "prompts": {"main": SECRET}, "versions": {"pydantic_ai": "1.107.0"}})
    return store, session_id


def test_the_actor_projection_excludes_payloads(tmp_path):
    ss = store_mod()
    store, session_id = _actor_fixture(tmp_path)

    rows = ss.hydrate(store, session_id, role="actor")
    assert rows, "the projection returned nothing — the leak assertion would be vacuous"
    flat = json.dumps([dict(r) for r in rows], default=str)
    assert SECRET not in flat, f"the actor read leaked the payload: {flat[:400]}"

    for surface in ("message_payload", "config", "session"):
        reached = getattr(ss, f"actor_view_{surface}", None)
        assert reached is None, (
            f"the actor role must have no reader path to {surface}; found {reached}")

    assert set(dict(rows[0])) == {"coord", "agent_id", "kind", "tool_name"}
    assert any(r["tool_name"] == "query" for r in rows), (
        "the actor DOES see tool-call coordinates — that is what makes it a projection")


def test_the_analysis_role_reaches_the_payloads_through_the_same_reader(tmp_path):
    """An analysis-role read through the SAME reader returns the full payloads, so the
    actor's exclusion is a projection and not an empty store."""
    ss = store_mod()
    store, session_id = _actor_fixture(tmp_path)

    messages = ss.hydrate(store, session_id, role="analysis")
    flat = " ".join(str(getattr(p, "content", "")) for m in messages
                    for p in getattr(m, "parts", []))
    assert SECRET in flat, "the analysis role must reach what the actor role cannot"
    assert len(messages) == 4


def test_every_via_reaching_store_rows_goes_through_the_role_scoped_projection(tmp_path):
    ss = store_mod()
    store, session_id = _actor_fixture(tmp_path)

    actor_flat = json.dumps([dict(r) for r in ss.hydrate(store, session_id, role="actor")],
                            default=str)
    analysis_flat = " ".join(str(getattr(p, "content", ""))
                             for m in ss.hydrate(store, session_id, role="analysis")
                             for p in getattr(m, "parts", []))
    assert SECRET not in actor_flat, actor_flat[:300]
    assert SECRET in analysis_flat, "the analysis via must still reach the payloads"

    with pytest.raises(TypeError):
        ss.hydrate(store, session_id)

    query = f"SELECT * FROM sqlite_scan('{store.path}', 'message')"
    proc = run_sql_py(query, stdin='{"a": 1}\n', cwd=REPO_ROOT)
    assert_query_error(proc, "the defender-sql lane resolved a reference to the store file")
    assert SECRET not in proc.stdout

    control = run_sql_py("SELECT a FROM data", stdin='{"a": 1}\n', cwd=REPO_ROOT)
    assert control.returncode == EXIT_OK, (
        f"positive control: the lane must still work at all; got {control.stderr!r}")


def test_two_investigations_of_the_same_case_land_in_one_per_case_database(tmp_path):
    """Two executions of one investigation land in ONE per-case file with two sessions, and
    the run dir's own slug is not what selects the file."""
    ss = store_mod()
    base = runs_base(tmp_path)
    sessions = []
    for slug in ("20260718t101500z-one", "20260718t101501z-two"):
        # #1187 (declared change 1): a run id is a canonical UUID — the folder is fixture_uuid(<label>)
        run_dir = base / fixture_uuid(slug)
        run_dir.mkdir(parents=True)
        store = owned_store(case_id="case-alpha", sessions=SessionPaths(fixture_runs_base(base)))
        ss.write_case_pointer(_run_handle_1165(run_dir), case_id="case-alpha", store_path=store.path)
        session_id = store.new_session(agent_id="main")
        store.append(session_id, [user_request(slug), *complete_pair()], agent_id="main")
        sessions.append(session_id)
        store.close()

    final = owned_store(case_id="case-alpha", sessions=SessionPaths(fixture_runs_base(base)))
    assert {row[0] for row in sql(final, "SELECT session_id FROM session")} == set(sessions)
    files = sorted(p.name for p in Path(final.path).parent.glob("*.db"))
    assert files == ["case-alpha.db"], f"two executions produced {files}"
