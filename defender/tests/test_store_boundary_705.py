"""#705 — R1 (placement) and R2 (read authorization): where the store sits and who reaches it.

R1 puts the store OUTSIDE the runs base — a sibling `sessions/<case_id>.db` alongside
`runs/`, never a child — and R2 makes every read go through the role-scoped projection.

The probes that govern this file, and what they corrected:

  * **adv:PO5** (executed break-attempt, UNREFUTED) — the box cannot read the store, and it
    holds on the MOUNT SET, by construction, not on obscurity: `mkdir` of the store parent
    is EROFS, `mount --bind` is EPERM, `/proc/1/root` is the same namespace, a hardlink
    cannot resolve the source. `DEFENDER_RUNS_BASE` is in the box env allowlist, so the
    path is NAMEABLE from inside. The test copies `test_540_box_boundary.py:405`'s shape —
    pin `errno == ENOENT` — and NOT `:709`'s, whose `read is None` passes on a path that
    EXISTS as a directory (IsADirectoryError, errno 21).
  * **adv:PO5b** (executed, REFUTED the corollary's completeness) — the mount set stops the
    box READING the store; it does not stop the box WRITING a symlink into the shared
    `run_dir` that a HOST reader follows. `shutil.copytree(..., symlinks=False)` — the exact
    call at `lead_repository.py:203` — and `tarfile.open(..., dereference=True)` both copied
    the store's bytes out. `the_store_is_unreachable_from_inside_the_box` is TRUE and is not
    the demand that covers this.
  * **adv:PO7** (executed, UNREFUTED) — `LEAD_ID_RE = ^l-[A-Za-z0-9]+$` is ONE shared
    compiled validator at all three composition sites and rejects `../`, NUL and every shell
    metacharacter, which REFUTES FK17's "nobody asserts a sanitizer exists". So the
    `case_id` demand below is written in that precedent's shape — reject, do not sanitise —
    and its one known hole (`$` vs `\\Z`, where `l-abc\\n` passes) is pinned explicitly.
  * **X1** — `lead_repository.actor_view` projects `executed_queries.jsonl`, never message
    history, so the reader sits BESIDE it rather than subsuming it (U6 was misframed).
"""
from __future__ import annotations

import errno as errno_mod
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from defender.tests._session_store_705 import (
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

DEFENDER = Path(__file__).resolve().parents[1]
REPO_ROOT = DEFENDER.parent
SECRET = "STORE-BYTES-DEFENDER-GOALS-4242"


# ==========================================================================
# R1 — placement, and the pointer file's own domain
# ==========================================================================

def test_store_path_is_not_under_the_runs_base(tmp_path):
    """The resolved store path is a SIBLING of the runs base, not a descendant of it, for
    every case_id — including ones that look like run ids.

    R1 is binding and supersedes the issue body's `$DEFENDER_RUNS_BASE/<store-dir>` wording.
    The assertion is taken against the RESOLVED pointer value (R6), not against a
    convention: two consumers `iterdir()` the runs base treating every child as a candidate
    run (C24/G10), and under a sibling store there is nothing for them to skip — which is
    why no demand is minted on their skip behaviour."""
    ss = store_mod()
    base = runs_base(tmp_path)

    for case_id in ("case-alpha", "20260718T101500Z-boxspec", "runs", "case.with.dots"):
        path = Path(ss.store_path_for(case_id, runs_base=base))
        assert base.resolve() not in path.resolve().parents, (
            f"{case_id}: the store landed UNDER the runs base at {path}")
        assert path.resolve().parent.parent == base.resolve().parent, (
            f"{case_id}: the store must be a sibling of the runs base; got {path}")
        assert path.name.endswith(".db")

    store = ss.open_store(case_id="case-alpha", runs_base=base)
    run_dir = base / "20260718T101500Z-alpha"
    run_dir.mkdir(parents=True)
    ss.write_case_pointer(run_dir, case_id="case-alpha", store_path=store.path)
    resolved = Path(ss.resolve_store_path(run_dir))
    assert base.resolve() not in resolved.resolve().parents
    assert [p for p in base.iterdir()] == [run_dir], (
        "the runs base must contain only run dirs — nothing for held_out/trace_lesson to skip")


def test_the_resolver_rejects_a_non_conforming_case_id(tmp_path):
    """A `case_id` that is not a conforming slug is REJECTED at the resolver — not
    sanitised, not escaped — before it is interpolated into a filesystem path; a conforming
    one resolves normally.

    R16 chose reject-over-sanitise, in the precedent adv:PO7 established for `lead_id`
    (`LEAD_ID_RE` is one shared compiled object at all three composition sites). Its one
    known hole is pinned here too: the pattern must anchor with `\\Z`, not `$`, or
    `case-abc\\n` passes `.match()` and creates a file whose name ends in a newline."""
    ss = store_mod()
    base = runs_base(tmp_path)

    assert Path(ss.store_path_for("case-alpha", runs_base=base)).name == "case-alpha.db", (
        "positive control: a conforming slug resolves")

    hostile = [
        "../../etc/passwd", "/etc/passwd", "case\x00id", "case id", "case;rm -rf /",
        "case`id`", "case$(id)", "case|id", "..", ".", "", "case\n", "case-abc\n",
        "caseature\uff0fescape", "C:\\case",
    ]
    for value in hostile:
        with pytest.raises(ss.InvalidCaseId):
            ss.store_path_for(value, runs_base=base)
        with pytest.raises(ss.InvalidCaseId):
            ss.open_store(case_id=value, runs_base=base)

    assert ss.CASE_ID_RE.pattern.endswith("\\Z"), (
        f"anchor with \\Z, not $: {ss.CASE_ID_RE.pattern!r} admits a trailing newline "
        "(adv:PO7's one hole, reproduced here rather than re-learned)")

    leaked = [p.name for p in base.parent.rglob("*") if "passwd" in p.name or "\n" in p.name]
    assert leaked == [], f"a rejected case_id composed a path anyway: {leaked}"


# ==========================================================================
# R1's corollary — the box, and the host-side leg adv:PO5b opened
# ==========================================================================

def _daemon_reachable() -> bool:
    try:
        return subprocess.run(["docker", "version", "--format", "{{.Server.Version}}"],
                              capture_output=True, timeout=30).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _is_dood() -> bool:
    if not Path("/.dockerenv").exists():
        return False
    probe = subprocess.run(["docker", "info", "--format", "{{.DockerRootDir}}"],
                           capture_output=True, text=True, encoding="utf-8", timeout=30)
    root = probe.stdout.strip()
    return probe.returncode == 0 and bool(root) and not Path(root).exists()


_NO_DAEMON = not _daemon_reachable()
_DOOD = (not _NO_DAEMON) and _is_dood()
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
    box, while the run dir remains readable AND writable from there.

    The failure must be ENOENT — the errno of a path that has no name inside the box —
    because the enforcement is the MOUNT SET, not a matcher: `DEFENDER_RUNS_BASE` is in the
    box env allowlist (`box.py:231`), so the box is TOLD where the store lives. This copies
    `test_540_box_boundary.py:405`'s shape deliberately; `:709`'s `read is None` passes on a
    path that EXISTS as a directory (adv:PO5 red flag 2)."""
    from defender.runtime.bash_exec import parse
    from defender.runtime.box import start_box, stop_box

    ss = store_mod()
    base = runs_base(tmp_path)
    store = ss.open_store(case_id="case-alpha", runs_base=base)
    session_id = store.new_session(agent_id="main")
    store.append(session_id, [user_request(SECRET)], agent_id="main")
    store.close()

    run_dir = base / "20260718T101500Z-boxed"
    (run_dir / "gather_raw").mkdir(parents=True)
    (run_dir / "alert.json").write_text('{"id": "boxed"}', encoding="utf-8")
    (run_dir / "sentinel.txt").write_text("RUN-DIR-IS-READABLE", encoding="utf-8")

    box = start_box(run_dir, DEFENDER)
    try:
        probe = run_dir / "_probe_store.py"
        probe.write_text(_READ_PATH, encoding="utf-8")
        cmd = f"python3 {probe} {store.path}"
        res = box.run_parsed(parse(cmd), command=cmd, cwd=run_dir, timeout=60)
        assert res.rc == 0, res.err
        got = json.loads(res.out.decode("utf-8"))
        assert got["read"] is None, f"the box read the store: {got}"
        assert got["errno"] == errno_mod.ENOENT, (
            f"expected ABSENT (ENOENT), got errno={got['errno']} ({got['exc']}) — a DENIED "
            "path means something mounted it and a matcher refused, which is not the "
            "boundary")

        cat = f"cat {store.path}"
        out = box.run_parsed(parse(cat), command=cat, cwd=run_dir, timeout=60)
        assert SECRET not in out.out.decode("utf-8", "replace")

        # positive control: the run dir IS reachable and writable from inside the box
        ctl = f"cat {run_dir / 'sentinel.txt'}"
        control = box.run_parsed(parse(ctl), command=ctl, cwd=run_dir, timeout=60)
        assert "RUN-DIR-IS-READABLE" in control.out.decode("utf-8")
    finally:
        stop_box(box)


def test_host_readers_do_not_dereference_a_symlink_out_of_the_run_dir(tmp_path):
    """The real host collector — `lead_repository.stage_tables` — does not follow a symlink out
    of the run dir: the store's bytes do not enter the staged tree, and a merely DANGLING
    symlink does not abort the collection. (Since #648 the collector goes further and refuses
    to stage a link at all, rather than preserving it as one; either satisfies this demand.)

    adv:PO5b (executed): the box CAN write `run_dir/gather_raw/leak.db ->
    <sibling>/sessions/<case>.db` — creating it succeeds even though reading the target is
    ENOENT — and a HOST reader follows it; the exact `copytree` call above copied the
    store's bytes OUT of `run_dir`, and `tarfile(dereference=True)` additionally ABORTS with
    `FileNotFoundError` on a dangling one. `the_store_is_unreachable_from_inside_the_box` is
    TRUE and is not the demand that covers this. Positive control: an ordinary (non-symlink)
    artifact still stages."""
    from defender.learning import lead_repository

    ss = store_mod()
    base = runs_base(tmp_path)
    store = ss.open_store(case_id="case-alpha", runs_base=base)
    session_id = store.new_session(agent_id="main")
    store.append(session_id, [user_request(SECRET)], agent_id="main")
    store.close()

    run_dir = base / "20260718T101500Z-leak"
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


# ==========================================================================
# R2 — the leak test, its positive control, and the parity
# ==========================================================================

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
    """An actor-role read returns tool-call coordinates only: no `message_payload` body, no
    `config` row, no `session` row, and nothing carrying the defender's goals — on EVERY
    out-edge the projected content could reach, not merely on the message table.

    Positive control: `test_the_analysis_role_reaches_the_payloads_through_the_same_reader`
    — the exclusion is a PROJECTION and not an empty store. R2 owes one leak test per
    gray-box boundary and G16 found THREE (the malicious/benign actor, the curator, the
    boxed runtime agent); this demand writes the actor's, `the_store_is_unreachable_from_
    inside_the_box` writes the box's, and the CURATOR's is unwritten (FK14, scope)."""
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
    """Every path that reaches store rows applies the same role-scoped projection: the
    actor via is payload-free, the analysis via is not, the `defender-sql` lane cannot
    resolve a reference to the store file at all, and the reader's direct handle refuses to
    return rows without a role.

    "By convention" is not an acceptable answer in this repo — the parity IS the answer, and
    it is asserted per access cell rather than facet-wide (O32)."""
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

    sql_path = DEFENDER / "scripts" / "gather_tools" / "sql.py"
    query = f"SELECT * FROM sqlite_scan('{store.path}', 'message')"
    proc = subprocess.run([sys.executable, str(sql_path), query],
                          input=b'{"a": 1}\n', capture_output=True, timeout=120,
                          cwd=str(REPO_ROOT))
    assert proc.returncode != 0, (
        "the defender-sql lane resolved a reference to the store file")
    assert SECRET.encode() not in proc.stdout

    control = subprocess.run([sys.executable, str(sql_path), "SELECT a FROM data"],
                             input=b'{"a": 1}\n', capture_output=True, timeout=120,
                             cwd=str(REPO_ROOT))
    assert control.returncode == 0, (
        f"positive control: the lane must still work at all; got {control.stderr!r}")


def test_the_reader_sits_beside_actor_view_and_takes_nothing_away_from_it(tmp_path):
    """`lead_repository.actor_view` keeps projecting the QUERIES table (`{case_id, alert_ref,
    leads:[{lead_id, queries:[{query_id, params}]}]}`), unchanged by the store's arrival: the
    store reader sits beside it rather than subsuming it.

    X1 REFUTED U6 as framed — `actor_view` never read the message history, so "can a
    role-scoped projection express actor_view without loss" is malformed as posed. This
    demand pins the survival of the surface the actor actually consumes."""
    from defender.learning import lead_repository

    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    (run_dir / "executed_queries.jsonl").write_text(json.dumps({
        "lead_id": "l-001", "seq": 0, "query_id": "elastic.auth-failures",
        "params": {"user": "root"}, "exit_code": 0,
    }) + "\n", encoding="utf-8")
    (run_dir / "alert.json").write_text('{"id": "a1"}', encoding="utf-8")

    view = lead_repository.actor_view(run_dir)
    assert "leads" in view, view
    leads = {lead["lead_id"] for lead in view["leads"]}
    assert "l-001" in leads, view
    assert SECRET not in json.dumps(view, default=str)


def test_two_investigations_of_the_same_case_land_in_one_per_case_database(tmp_path):
    """Two executions of one investigation land in ONE per-case file with two sessions, and
    the run dir's own slug is not what selects the file.

    Consensus (O1/M1), conditional on FK1 and now settled by R6: aliasing
    `case_id := run_dir.name` would give two executions two case ids and hence two FILES,
    making O13's inheritance and O11's single-file claim unsatisfiable — every fork demand
    would pass vacuously while forking is silently impossible."""
    ss = store_mod()
    base = runs_base(tmp_path)
    sessions = []
    for slug in ("20260718T101500Z-one", "20260718T101501Z-two"):
        run_dir = base / slug
        run_dir.mkdir(parents=True)
        store = ss.open_store(case_id="case-alpha", runs_base=base)
        ss.write_case_pointer(run_dir, case_id="case-alpha", store_path=store.path)
        session_id = store.new_session(agent_id="main")
        store.append(session_id, [user_request(slug), *complete_pair()], agent_id="main")
        sessions.append(session_id)
        store.close()

    final = ss.open_store(case_id="case-alpha", runs_base=base)
    assert {row[0] for row in sql(final, "SELECT session_id FROM session")} == set(sessions)
    files = sorted(p.name for p in Path(final.path).parent.glob("*.db"))
    assert files == ["case-alpha.db"], f"two executions produced {files}"


def test_run_dir_case_id_and_session_id_deliberately_diverge(tmp_path):
    """`case_id` is the investigation, `session_id` is this execution, and `run_dir` is a
    path and not an identity: each consumer reaches for its own, and a coincidental equality
    between any two is not a licence to substitute one for another.

    The eval join key — the dir-name slug at `held_out.py:126` — is NOT inherited by a fork
    (O13). The discriminating fixture makes all three DIFFER, so a consumer that reached for
    the wrong one is caught rather than accidentally correct."""
    ss = store_mod()
    base = runs_base(tmp_path)
    run_dir = base / "20260718T101500Z-divergent"
    run_dir.mkdir(parents=True)
    store = ss.open_store(case_id="case-alpha", runs_base=base)
    ss.write_case_pointer(run_dir, case_id="case-alpha", store_path=store.path)
    session_id = store.new_session(agent_id="main")
    r1 = store.append(session_id, [user_request("root")], agent_id="main")[0]
    fork = store.fork(session_id, at_message_id=r1)

    assert len({"case-alpha", session_id, run_dir.name}) == 3, (
        "the fixture must make the three differ, or a wrong reach reads as correct")
    pointer = json.loads((run_dir / ss.POINTER_FILENAME).read_text())
    assert pointer["case_id"] == "case-alpha" != run_dir.name
    rows = dict(sql(store, "SELECT session_id, case_id FROM session"))
    assert rows[fork] == "case-alpha", "case_id is inherited by the fork"
    assert fork != session_id, "the eval dir-name join key does not follow the fork"
    assert run_dir.name not in rows, "run_dir is a path, not an identity"
