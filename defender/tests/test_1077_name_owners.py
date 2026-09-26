"""#1077 — the name owners: `RunPaths`, `EpisodePaths`, and the one rule every composing
accessor inherits.

Carries 28 demands of `spec-flow/specs/spec_graph_1077.yaml`, each test named after its
demand's `discharged_by` pointer. D1 takes `RunPaths` from seven accessors to roughly twenty
and mints `EpisodePaths` beside it; decision 2 puts ONE rule on every accessor that builds a
path from a caller-supplied component — an anchored shape check on the value, then a
containment check of the resolved path against that method's OWN root, refusing on either.

Every hostile component in `S.HOSTILE_COMPONENTS` is a REAL string handed to the REAL
accessor: the traversal segments, the embedded separators, the NUL and the newline are
re-probed on every run, so the taxonomy assumption ceases to exist rather than being pinned
once. Where a name is expected, it is read off `defender/docs/run-records-kinds.tsv` — the
gate's own data file — rather than re-spelled here, and `CASE_ID_RE` is pinned BY REFERENCE at
`defender/_run_id.py` per RG-4, never re-spelled into an assertion.
"""
from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest

from defender.tests import _spec1077 as S
from defender.tests import _triplet_947 as T
from defender.tests._by_path import DEFENDER, load_module
from defender.tests import _tenants1106 as T1106  # noqa: E402


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
        "<label>": S.LABEL, "<prefix>": S.PREFIX, "<stem>": S.STEM,
        "<n>": str(S.CHECK_INDEX) if acc.kind == "forward_check_trace" else "1",
        "<stage>": S.STAGE, "<token>": S.WORLD_TOKEN, "<episode_id>": S.EPISODE_ID,
    }
    out = template.split(",")[0].strip()
    for k, v in subs.items():
        out = out.replace(k, v)
    return out.rstrip("/")


# ---------------------------------------------------------------------------------------
# D1 — the enumerated names, walked off the kinds table
# ---------------------------------------------------------------------------------------

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
    assert S.RunPaths(run_dir).sessions_dir(base) == base.parent / "sessions"
    assert S.RunPaths(run_dir).session_db(base, S.LINEAGE_ID).name == f"{S.LINEAGE_ID}.db"


def test_episode_paths_resolves_every_name_d1_enumerates(episode_dir):
    """`EpisodePaths` resolves every episode-level name the design enumerates, including the
    run-dir pointer."""
    missing = []
    for acc in S.ACCESSOR_FOR_KIND:
        if acc.owner != "episode":
            continue
        try:
            got = S.resolve(acc, run_dir=episode_dir, episode_dir=episode_dir)
        except AttributeError:
            missing.append(f"{acc.kind} -> EpisodePaths.{acc.attr}")
            continue
        want = _concrete(_expected(acc.kind), acc)
        assert got == episode_dir / want, f"{acc.kind}: {got} vs {want}"
    assert missing == [], f"these episode names have no accessor on the owner: {missing}"

    owner = S.EpisodePaths(episode_dir)
    assert owner.run_dir_pointer(S.LABEL) == episode_dir / "worlds" / S.LABEL / "run_dir", (
        "the run-dir pointer (archive.py:82) was missed by the handoff and is D1's, not a "
        "constant left behind in archive.py")
    assert owner.served_world(S.WORLD_TOKEN) == (
        episode_dir / "served" / f"{S.WORLD_TOKEN}.jsonl")
    assert owner.served == episode_dir / "served"
    assert owner.runs == episode_dir / "runs"
    # Claim C17 is REFUTED-AS-STATED: four more archive.py constants belong to the enumeration.
    for extra, want in (("draws", "judge"), ("gather_summaries", "gather_summaries"),
                        ("lessons_loaded", "lessons_loaded.jsonl"), ("alert", "alert.json")):
        assert hasattr(owner, extra), (
            f"archive.py's {extra.upper()} constant is in the ArchivedWorld copied set, so "
            "D5's enumeration and this walk need it — claim C17 undercounted by four")
        assert want in str(getattr(owner, extra)(S.LABEL) if extra != "draws"
                           else owner.draws(S.LABEL))


def test_the_two_retired_names_still_resolve_on_the_owner(run_dir):
    """`source_refs` and `ticket_read(seq)` still resolve on the owner, because the answer-key
    set and the payload-cap shape key on those names."""
    from defender._run_paths import CASE_ANSWER_KEY_NAMES
    owner = S.RunPaths(run_dir)
    assert owner.source_refs == run_dir / "source_refs.yaml"
    assert owner.ticket_read(S.SEQ) == run_dir / "ticket_reads" / f"{S.SEQ}.json"
    assert owner.source_refs.name in CASE_ANSWER_KEY_NAMES, (
        "the answer-key set keys on this name, which is why a kind with no writer at all "
        "(claim R9: source_refs.yaml has readers only) still gets an accessor")
    from defender.runtime import permission
    assert permission.is_captured_payload(owner.ticket_read(S.SEQ)), (
        "the payload read cap keys on the ticket_reads name — D1's stated reason for keeping it")


def test_a_sub_collection_member_for_a_kind_nothing_writes(run_dir):
    """A kind with no writer still gets an accessor, for D1's stated reason: the gate's
    answer-key set and payload-cap shape key on `source_refs` and `ticket_reads`."""
    writers = [
        p for p in DEFENDER.rglob("*.py")
        if not p.relative_to(DEFENDER).as_posix().startswith("tests/")
        and "source_refs.yaml" in p.read_text(encoding="utf-8", errors="replace")
        and "write" in p.read_text(encoding="utf-8", errors="replace")]
    owner = S.RunPaths(run_dir)
    assert owner.source_refs.is_relative_to(run_dir), (
        f"the accessor exists whether or not anything writes the kind (writer candidates: "
        f"{[p.name for p in writers]}; claim R9 says there is no writer in the repo)")
    assert owner.ticket_read(0).is_relative_to(run_dir)


def test_every_composed_name_part_is_a_constant_on_the_owner(run_dir):
    """Every part a composed record name is built from is a named constant on the owner, and the
    gate reads its part set from those constants."""
    owner_mod = S.run_paths_mod()
    constants = {v for k, v in vars(owner_mod).items()
                 if k.isupper() and isinstance(v, str)}
    for part in S.DISCRIMINATING_PARTS:
        assert part in constants or any(part in c for c in constants), (
            f"{part!r} is composed into a record name but is not a named constant on the owner "
            "— D6 keys on those constants, so an unnamed part is a part the gate cannot see")
    assert set(S.gate().COMPOSED_PARTS) <= constants | {
        c for c in vars(S.episode_paths()).values() if isinstance(c, str)}, (
        "the gate re-spells a part rather than reading it from the owner's constants")


def test_a_composed_name_part_that_two_accessors_share(run_dir):
    """A composed-name part two accessors share is represented as one reused constant on the
    owner, because D6 keys on those constants."""
    owner_mod = S.run_paths_mod()
    trace_const = [k for k, v in vars(owner_mod).items()
                   if k.isupper() and v == ".trace.jsonl"]
    assert len(trace_const) == 1, (
        f"`.trace.jsonl` is shared by forward_check_trace and stage_trace and must be ONE "
        f"reused constant; the owner spells it under {trace_const}")
    name = trace_const[0]
    owner = S.RunPaths(run_dir)
    assert str(owner.forward_check_trace(S.PREFIX, S.STEM, S.CHECK_INDEX)).endswith(
        getattr(owner_mod, name))
    assert str(S.episode_paths().EpisodePaths(run_dir).stage_trace(S.STAGE)).endswith(
        getattr(owner_mod, name)), "the second accessor re-spells the shared part"


def test_no_episode_layout_constant_survives_outside_the_owner(episode_dir):
    """No episode-layout name is spelled outside the owner in any of the modules that spelled one
    before.

    NEGATIVE. Positive control inline (and demand d39): every one of those names still
    resolves — on the owner.
    """
    rehomed = {
        "learning/branch/archive.py", "learning/branch/ledger.py", "learning/branch/timing.py",
        "learning/branch/staging.py", "runtime/branch/_family.py",
        "scripts/visualize/visualize_episode.py", "learning/branch/cli.py"}
    names = ("family.yaml", "review.yaml", "samples.yaml", "judge.yaml", "timing.json",
             "staged.yaml", "base.jsonl", "learning.html", ".priming")
    offenders = []
    for rel in sorted(rehomed):
        text = (DEFENDER / rel).read_text(encoding="utf-8")
        for name in names:
            if f'"{name}"' in text or f"'{name}'" in text:
                offenders.append(f"{rel}: {name}")
    assert offenders == [], (
        f"D1 re-homes these constants onto EpisodePaths and they are still spelled at: "
        f"{offenders}")
    owner = S.EpisodePaths(episode_dir)
    assert owner.family.name == "family.yaml", "positive control: the name resolves on the owner"


def test_the_episodes_root_resolver_is_not_moved_into_the_owner(episode_dir):
    """The episodes root is still resolved by the launcher's own `episodes_root`, and the owner
    does not define one.

    NEGATIVE. Positive control inline: the launcher's resolver is still there and still refuses
    an unset `$DEFENDER_EPISODES_BASE` (claim S4).
    """
    owner_mod = S.episode_paths()
    for forbidden in ("episodes_root", "EPISODES_BASE_ENV", "episodes_base"):
        assert not hasattr(owner_mod, forbidden), (
            f"{forbidden} moved onto the episode-layout owner; D1 re-homes the LAYOUT constants "
            "and leaves the root's resolution in learning/branch/cli.py")
    cli = S.branch_cli()
    assert callable(cli.episodes_root), "positive control: the launcher still owns the resolver"
    assert "EPISODES_BASE" in inspect.getsource(cli.episodes_root), (
        "the resolver still reads the configured location, with no default derivation")


# ---------------------------------------------------------------------------------------
# O8 — the two model-facing payload forms
# ---------------------------------------------------------------------------------------

def test_the_queries_row_records_the_owners_relative_payload_path(run_dir):
    """The payload path recorded in the queries row is the owner's run-dir-relative string."""
    from defender.scripts.gather_tools import record_query
    recorded = record_query.persist_payload(run_dir, S.LEAD_ID, S.SEQ, '{"rows": []}')
    assert recorded == S.RunPaths(run_dir).payload_relpath(S.LEAD_ID, S.SEQ), (
        f"the row recorded {recorded!r}; O8 requires it to be the OWNER's relative form, not a "
        "second spelling composed at the call site (claims C11/R4, record_query.py:271)")
    assert not Path(recorded).is_absolute()
    assert (run_dir / recorded).is_file()


def test_gathers_note_carries_the_owners_absolute_payload_path_and_the_gate_admits_it(run_dir):
    """The absolute payload path gather puts in its note is the owner's, and gather's own read
    gate admits it under the raw-payload shape."""
    from defender.runtime import permission
    from defender.runtime.agent_definition import compile_policy_for
    from defender.scripts.gather_tools import record_query

    rel = record_query.persist_payload(run_dir, S.LEAD_ID, S.SEQ, '{"rows": []}')
    absolute = S.RunPaths(run_dir).payload(S.LEAD_ID, S.SEQ)
    assert run_dir / rel == absolute, (
        "gather's note composes `run_dir / record['payload_path']` (tools_gather.py:70); O8 "
        "names BOTH forms and requires both to be the owner's")

    policy = compile_policy_for(T1106.playground_gather_def(), run_dir=run_dir, defender_dir=DEFENDER)
    decision = permission.decide_read(
        absolute, run_dir=run_dir, defender_dir=DEFENDER, policy=policy)
    assert decision.allow, (
        f"gather's own read gate refused the path it is told to `cat`: {decision.reason} — the "
        "GATHER_RAW_SHAPE admits it, and that admission is what makes O8's note usable")


def test_payload_relpath_given_an_already_absolute_path(run_dir):
    """`payload_relpath` carries no shape detection and no refusal for the already-absolute
    case: O8 and D1 place the relative and absolute payload forms on two SEPARATE accessors, so
    choosing the right one is the caller's duty and the accessor composes and returns its
    run-dir-relative value unconditionally."""
    owner = S.RunPaths(run_dir)
    got = owner.payload_relpath(S.LEAD_ID, S.SEQ)
    assert not Path(got).is_absolute()
    assert Path(got) == owner.payload(S.LEAD_ID, S.SEQ).relative_to(run_dir)
    # No shape detection: the accessor does NOT notice it was reached under an absolute-path
    # assumption and does NOT switch form or refuse (§7 non-material item 8).
    again = owner.payload_relpath(S.LEAD_ID, S.SEQ)
    assert again == got, "the accessor's answer depends on nothing but its components"
    assert isinstance(got, str), "the run-dir-relative form is the string the row records"


# ---------------------------------------------------------------------------------------
# Decision 2 — one rule for every composing accessor
# ---------------------------------------------------------------------------------------

def test_every_composed_accessor_shape_checks_then_confines_against_its_own_root(
        base, run_dir, episode_dir):
    """Every accessor that builds a path from a caller-supplied component applies one rule — an
    anchored shape check on the value, then a containment check of the resolved path against
    that method's own root — and refuses on either."""
    for acc in S.COMPOSING:
        owner_root = S.upward_root(acc.attr, base) if acc.attr in S.UPWARD_ACCESSORS else (
            run_dir if acc.owner == "run" else episode_dir)
        # Positive control, per accessor: an ordinary component resolves, inside its own root.
        ok = S.resolve(acc, run_dir=run_dir, runs_base=base, episode_dir=episode_dir)
        assert Path(ok).is_absolute() is False or Path(ok).is_relative_to(owner_root), (
            f"{acc.owner}.{acc.attr} does not resolve inside its own root for an ordinary value")
        for hostile in S.HOSTILE_COMPONENTS:
            # ONE slot at a time, the numbered ones included: a `turn`/`seq`/`n` slot handed
            # `'../x'` formats straight into the name unless the shape rule refuses a
            # non-integer there, and probing every slot at once lets the FIRST slot's refusal
            # hide an unchecked later one (`forward_check_trace(prefix, stem, n)`).
            for slot in range(len(acc.args)):
                args = tuple(hostile if i == slot else a for i, a in enumerate(acc.args))
                with pytest.raises(Exception) as excinfo:  # noqa: PT011
                    S.resolve(acc, run_dir=run_dir, runs_base=base, episode_dir=episode_dir,
                              args=args)
                assert excinfo.value is not None, f"{acc.attr}({hostile!r} in slot {slot})"
            continue
            args = tuple(hostile for _ in acc.args)
            with pytest.raises(Exception) as excinfo:  # noqa: PT011
                S.resolve(acc, run_dir=run_dir, runs_base=base, episode_dir=episode_dir,
                          args=args)
            assert excinfo.value is not None, f"{acc.attr}({hostile!r})"


def test_every_composed_accessor_applies_the_shape_then_containment_pair_or_a_reachability_probe_shows_why_not(  # noqa: E501
        base, run_dir, episode_dir):
    """Every accessor on `RunPaths`/`EpisodePaths` that composes a name from a caller-supplied
    component (lead_id, turn, role, seq, label, token, episode_id) either applies the same
    shape-then-containment pair `payload` does, or a break-attempt probe shows the specific
    input it refuses instead — a census, not a single case.

    The enumeration picks the subjects; the assertion is what each one DOES when driven. A
    reachability claim here is a break-attempt, unrefuted only, never confirmed.

    A MISSING accessor is a census failure, not a refusal: without the first loop below, an
    owner that simply does not have the accessor would raise `AttributeError` at every hostile
    input and the census would certify a surface that does not exist.
    """
    absent = []
    for acc in S.COMPOSING:
        try:
            S.resolve(acc, run_dir=run_dir, runs_base=base, episode_dir=episode_dir)
        except AttributeError:
            absent.append(f"{acc.owner}.{acc.attr}")
        except Exception:  # noqa: BLE001 — a refusal of an ORDINARY value is its own failure
            absent.append(f"{acc.owner}.{acc.attr} refuses its own ordinary component")
    assert absent == [], f"these composing accessors do not exist to be censused: {absent}"

    escaped = []
    probes = [
        (acc, hostile, tuple(hostile if i == slot else a for i, a in enumerate(acc.args)))
        for acc in S.COMPOSING for hostile in S.HOSTILE_COMPONENTS
        for slot in range(len(acc.args))]  # one slot at a time — the sibling test says why
    for acc, hostile, args in probes:
        if True:
            try:
                got = S.resolve(acc, run_dir=run_dir, runs_base=base, episode_dir=episode_dir,
                                args=args)
            except AttributeError:
                escaped.append(f"{acc.owner}.{acc.attr} vanished between the two loops")
                continue
            except Exception:  # noqa: BLE001 — the refusal is the demanded outcome
                continue
            root = base if acc.attr in S.UPWARD_ACCESSORS else (
                run_dir if acc.owner == "run" else episode_dir)
            resolved = (root / got).resolve() if not Path(got).is_absolute() else Path(got).resolve()
            if not resolved.is_relative_to(root.resolve()):
                escaped.append(f"{acc.owner}.{acc.attr}({hostile!r}) -> {resolved}")
            else:
                escaped.append(
                    f"{acc.owner}.{acc.attr}({hostile!r}) was ADMITTED (resolved {resolved}) — "
                    "decision 2 makes the shape check one rule all ~20 accessors inherit, so an "
                    "accessor that admits it is one the rule did not reach")
    assert escaped == [], "\n".join(escaped)


def test_no_composed_accessor_resolves_outside_its_root(base, run_dir, episode_dir):
    """No accessor taking a caller-supplied component — lead id, turn, role, token, sequence,
    label — resolves to a path outside its own root.

    NEGATIVE, bound at every root the change touches: the run directory, the runs base (the
    sidecars) and the episode directory. Positive control inline and in demand d36: the same
    accessors DO resolve, inside their own roots, for ordinary components.
    """
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
    resolve to a path outside the run dir.

    NEGATIVE. Positive control inline: an ordinary `l-`-shaped lead id DOES resolve, under
    `gather_raw/` inside the run dir.
    """
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
    from defender._run_paths import plain_file
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

    # D1's own constraint on the cell: the screen lives in the owner module, which drops
    # pydantic for a stdlib dataclass so the box entrypoint closure can import it (claim C4).
    # A screen that pulls in a third-party package would take the sentinel's owner with it.
    from defender._paths import PATHS
    from defender.tests._import_blocker import run_blocked

    body = (
        "import sys\n"
        "from defender._run_paths import plain_file\n"
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


# ---------------------------------------------------------------------------------------
# The session database — RG-4: pin the pattern BY REFERENCE, never re-spell it
# ---------------------------------------------------------------------------------------

def _refuses(run_dir: Path, base: Path, lineage) -> BaseException:
    from defender.runtime.session_store import InvalidCaseId
    with pytest.raises(InvalidCaseId) as excinfo:
        S.RunPaths(run_dir).session_db(base, lineage)
    return excinfo.value


def test_session_db_refuses_a_lineage_id_the_case_id_pattern_rejects(base, run_dir):
    """`session_db` refuses a lineage id the case-id pattern rejects, exactly as `store_path_for`
    does today."""
    from defender.runtime.session_store import CASE_ID_RE, InvalidCaseId, store_path_for
    for lineage in ("-leading-dash", "has space", "a/b", "héllo", "..", "_under"):
        assert not CASE_ID_RE.match(lineage), (
            "the pattern is pinned BY REFERENCE at defender/_run_id.py (`CASE_ID_RE`) (RG-4); "
            "this test reads it, it does not re-spell it")
        _refuses(run_dir, base, lineage)
        with pytest.raises(InvalidCaseId):
            store_path_for(lineage, runs_base=base)
    # Positive control: the id today's resolver admits resolves to today's path.
    assert S.RunPaths(run_dir).session_db(base, S.LINEAGE_ID) == store_path_for(
        S.LINEAGE_ID, runs_base=base)


def test_session_db_lineage_id_failing_case_id_pattern(base, run_dir):
    """`session_db` refuses a lineage id failing the case-id pattern, matching `store_path_for`'s
    behaviour today."""
    from defender.runtime.session_store import CASE_ID_RE, store_path_for
    hostile = "case/../../escape"
    assert not CASE_ID_RE.match(hostile)
    refusal = _refuses(run_dir, base, hostile)
    assert repr(hostile) in str(refusal) or hostile in str(refusal), (
        "the refusal names the value it refused, as today's does")
    assert S.RunPaths(run_dir).session_db(base, S.LINEAGE_ID) == store_path_for(
        S.LINEAGE_ID, runs_base=base), "positive control: a valid lineage id still resolves"


def test_session_db_lineage_id_empty(base, run_dir):
    """An empty lineage id fails the case-id pattern (which requires at least one leading
    alphanumeric) and is refused per D1's stated inheritance of the refusal."""
    from defender.runtime.session_store import CASE_ID_RE
    assert not CASE_ID_RE.match(""), (
        "cite defender/_run_id.py (`CASE_ID_RE`) — the pattern's own leading-alphanumeric "
        "requirement is what refuses the empty id; it is not re-derived here")
    _refuses(run_dir, base, "")


def test_session_db_lineage_id_oversized(base, run_dir):
    """An oversized lineage id exceeds the case-id pattern's length cap and is refused per D1's
    stated inheritance of the refusal."""
    from defender.runtime.session_store import CASE_ID_RE
    oversized = "a" * 4096
    assert not CASE_ID_RE.match(oversized), (
        "the cap is the pattern's own, read at defender/_run_id.py (`CASE_ID_RE`) (RG-4)")
    _refuses(run_dir, base, oversized)
    just_inside = "a" * 128
    assert CASE_ID_RE.match(just_inside), "positive control: the pattern's own boundary value"
    assert S.RunPaths(run_dir).session_db(base, just_inside).name == f"{just_inside}.db"


def test_the_owner_carries_a_refusal_rule_that_lives_outside_the_box_closure(base, run_dir):
    """There is no conflict: `CASE_ID_RE` is a stdlib `re` pattern carrying no third-party
    dependency, and D1's pydantic-to-`@dataclass(frozen=True)` conversion applies to the whole
    owner module, so re-homing `store_path_for`'s refusal onto `session_db` leaves the owner
    importable with no third-party package present."""
    from defender._paths import PATHS
    from defender.tests._import_blocker import run_blocked

    body = (
        "import sys\n"
        "import defender._run_paths as rp\n"
        "import pathlib\n"
        "o = rp.RunPaths(pathlib.Path('/tmp/x'))\n"
        "print('ANSWERED', o.session_db(pathlib.Path('/tmp/runs'), 'good').name)\n"
        "try:\n"
        "    o.session_db(pathlib.Path('/tmp/runs'), '-bad')\n"
        "except Exception as e:\n"
        "    print('REFUSED', type(e).__name__)\n"
        "else:\n"
        "    print('ADMITTED')\n"
        "assert 'pydantic' not in sys.modules, sorted(m for m in sys.modules if 'pyd' in m)\n")
    done = run_blocked(body, block=("pydantic", "pydantic_ai", "pydantic_core"),
                       cwd=PATHS.repo_root)
    assert done.returncode == 0, done.stderr
    # Positive control first: an owner that cannot even answer a VALID id without pydantic
    # would print `REFUSED ModuleNotFoundError` below, and a bare `REFUSED` check would pass.
    assert b"ANSWERED good.db" in done.stdout, (
        f"the owner could not answer a valid lineage id with no third-party package "
        f"installed:\n{done.stdout!r}\n{done.stderr!r}")
    assert b"REFUSED InvalidCaseId" in done.stdout, (
        "the re-homed refusal did not fire as `InvalidCaseId` with no third-party package "
        "installed — D1's conversion applies to the whole owner module, as `_io.py:17-19` "
        f"already did:\n{done.stdout!r}")


# ---------------------------------------------------------------------------------------
# Decision 12 — composed-identifier collisions
# ---------------------------------------------------------------------------------------

def test_a_component_containing_the_delimiter_is_refused_at_mint_time(episode_dir):
    """The LABEL carrying the composition's own delimiter is refused at mint time, for
    `<episode_id>-<label>` and `<episode token>.<label>` alike.

    The label is the component held delimiter-free, and that alone makes both compositions
    recoverable: every real episode id carries `-` (`cli.episode_id_for` derives
    `<source run>-n<turn>`) and every real episode token carries `.` (`_family.
    episode_token_for` folds each `-` onto one), so refusing the delimiter in the LEFT half
    would refuse every production id — the positive control below is itself a dashed episode
    id. With the label delimiter-free, `ep-a-b` is `(ep-a, b)` and never `(ep, a-b)`.
    """
    owner = S.EpisodePaths(episode_dir)
    assert owner.sibling_run_dir(S.EPISODE_ID, "plain").name == f"{S.EPISODE_ID}-plain", (
        "positive control: a delimiter-free label composes, byte for byte as today (O3)")
    for label in ("has-dash", "a-b"):
        with pytest.raises(Exception) as excinfo:  # noqa: PT011
            owner.sibling_run_dir(S.EPISODE_ID, label)
        assert "-" in str(excinfo.value), (
            "the refusal names the delimiter the component carries; two distinct pairs "
            "composing to one sibling run id is what decision 12 closes")
    # The world token is minted by `_family.world_token_for`; the owner's `served_world` takes
    # the minted token, so the `.` refusal is asked of the label THERE.
    from defender.runtime.branch import _family
    assert owner.served_world(_family.world_token_for("ep.2026", "plain")).name == (
        "ep.2026.plain.jsonl"), "positive control: a dotted episode TOKEN is the normal case"
    for label in ("has.dot", "a.b"):
        with pytest.raises(_family.FamilyError) as excinfo:
            _family.world_token_for("ep.2026", label)
        assert "." in str(excinfo.value)


def test_the_composed_identifiers_and_the_session_db_path_carry_the_case_stability_refusal(
        base, run_dir, episode_dir):
    """The composed sibling run id, the composed world token and the session-database path each
    carry the same case-stability refusal the handle's own bare run-id admission carries — one
    rule reached by reference at four sites, not an old accident beside three new rules."""
    from defender._run_id import is_case_stable_id
    owner = S.EpisodePaths(episode_dir)
    by_reference = "the rule is today's `_run_id.is_case_stable_id`, reached by reference"
    assert is_case_stable_id("plain"), by_reference
    assert not is_case_stable_id("Plain"), by_reference
    # The FOURTH site is the bare run id, which h54 drives: before §7 decision 20 the rule ran
    # on the episode id alone (claim RC-3), so "the refusal a directly-offered run id already
    # clears" was false of this repo. These two demands are siblings, not one demand twice.

    for label in ("Overlay", "OVERLAY", "oVerlay"):
        with pytest.raises(Exception):  # noqa: B017,PT011
            owner.sibling_run_dir(S.EPISODE_ID, label)
        with pytest.raises(Exception):  # noqa: B017,PT011
            owner.world_dir(label)
    with pytest.raises(Exception):  # noqa: B017,PT011
        owner.served_world(f"{S.EPISODE_ID}.Overlay")
    # The session-database path gains the check BESIDE its existing CASE_ID_RE format check.
    from defender.runtime.session_store import CASE_ID_RE, InvalidCaseId
    mixed = "Case-0011223344556677"
    assert CASE_ID_RE.match(mixed), (
        "the format check admits a mixed-case id today (`_run_id.CASE_ID_RE`) — the case-"
        "stability refusal is the NEW check beside it, not a re-spelling of the old one")
    with pytest.raises(InvalidCaseId):
        S.RunPaths(run_dir).session_db(base, mixed)
    assert S.RunPaths(run_dir).session_db(base, S.LINEAGE_ID).name.endswith(".db"), (
        "positive control: a case-stable lineage id still resolves")


# ---------------------------------------------------------------------------------------
# What the move must NOT change
# ---------------------------------------------------------------------------------------

def test_a_public_name_function_that_other_modules_import_today(run_dir):
    """`challenge_gate.review_trace_path`/`review_record_path` and `observe`'s wire-log path
    function are re-homed onto the owner, and every module that imports one of them today is
    updated with them."""
    owner = S.RunPaths(run_dir)
    assert owner.review_trace(S.ROLE) == run_dir / "wire_logs" / f"review_{S.ROLE}_trace.jsonl"
    assert owner.review_record(S.TURN) == run_dir / f"review_record.{S.TURN}.json"
    gate_mod = S.mod("runtime.challenge_gate")
    for gone in ("review_trace_path", "review_record_path"):
        assert not hasattr(gate_mod, gone), (
            f"challenge_gate still owns {gone}; D1 re-homes it onto the owner (flagged fact F10)")
    stale = []
    for py in DEFENDER.rglob("*.py"):
        rel = py.relative_to(DEFENDER).as_posix()
        if rel.startswith("tests/"):
            continue
        text = py.read_text(encoding="utf-8", errors="replace")
        for gone in ("review_trace_path", "review_record_path"):
            if gone in text:
                stale.append(f"{rel}: {gone}")
    assert stale == [], f"a caller of a re-homed function was left behind: {stale}"


def test_one_writer_seam_asked_to_name_a_file_under_three_different_roots(
        run_dir, episode_dir, tmp_path: Path):
    """`observe.stage_trace_path` is one writer seam applied to three roots — the run dir, the
    episode dir and the learning run dir — and D1 places its accessor on the owner of the first
    two only: the third keeps today's shared function, unowned by this issue."""
    observe = S.mod("runtime.observe")
    learning_run = tmp_path / "state" / "runs" / "source-42"
    learning_run.mkdir(parents=True)

    assert S.RunPaths(run_dir).forward_check_trace(S.PREFIX, S.STEM, S.CHECK_INDEX) == (
        run_dir / "wire_logs" / f"{S.PREFIX}.{S.STEM}.{S.CHECK_INDEX}.trace.jsonl")
    assert S.EpisodePaths(episode_dir).stage_trace(S.STAGE) == (
        episode_dir / "wire_logs" / f"{S.STAGE}.trace.jsonl")
    # The third root keeps today's shared function — this issue leaves it unowned (C16 refuted).
    third = observe.stage_trace_path(learning_run, "forward.a-lesson.2.trace.jsonl")
    assert third == learning_run / "wire_logs" / "forward.a-lesson.2.trace.jsonl"
    assert not hasattr(S.RunPaths(learning_run), "learning_run_trace"), (
        "no accessor covers the learning run dir: D1 places the first two on their owners and "
        "the Resolution leaves the third where it is")


def test_the_priming_locks_raw_exclusive_open_is_not_converted_to_a_guarded_write(tmp_path: Path):
    """The priming lock's low-level exclusive `os.open` is preserved exactly and is not converted
    to a guarded write by the name move.

    NEGATIVE. Positive control: demand d19 — the tenant record, a NEW seam, DOES go through
    `write_guarded`; here the pre-existing seam must be untouched.
    """
    cli = S.branch_cli()
    source = inspect.getsource(cli)
    assert "os.O_CREAT | os.O_EXCL | os.O_WRONLY" in source, (
        "flagged fact F11: `served/.priming` is a RAW exclusive `os.open` today, and the "
        "security dive's universal (2) is scoped to NEW seams — the name move must not "
        "quietly convert it")
    assert "write_guarded(claim" not in source
    assert "write_guarded(served" not in source
    # The NAME moves to the owner; the SEAM does not.
    episode_dir = S.make_episode_dir(tmp_path)
    assert S.EpisodePaths(episode_dir).priming_lock == episode_dir / "served" / ".priming"


def test_corpus_load_ones_runpaths_construction_still_resolves_after_d1(tmp_path: Path):
    """`corpus_load_one`'s `RunPaths(run_dir).alert` construction (claim S10, outside the gate's
    sweep) still resolves identically after D1's RunPaths rewrite (7 -> ~20 accessors, pydantic
    dropped for stdlib dataclass)."""
    from defender.skills.invlang import corpus
    case = tmp_path / "corpus" / "case-1"
    case.mkdir(parents=True)
    # `RunPaths(run_dir).alert` is how the site names the alert (`corpus.py:124`), and the
    # signature id it reads off it is the observable that tells whether it still resolves.
    (case / "alert.json").write_text('{"rule": {"id": "sig-9"}}\n', encoding="utf-8")
    # The COMMITTED companion, not a stub: `load_corpus` only counts a document that PARSES
    # (three required top-level keys inside ```invlang fences), so a stub would make this
    # assertion read 0 == 0 and pass on the absence of the thing it measures.
    (case / "investigation.md").write_bytes(T.GOLDEN_INVESTIGATION.read_bytes())

    companions, report = corpus.load_corpus(tmp_path / "corpus")
    assert report.scanned == 1, f"the fixture was not scanned: {report}"
    assert S.RunPaths(case).alert == case / "alert.json", (
        "the unmoved reader outside the sweep composes the same path after the rewrite")
    assert [c.signature_id for c in companions] == ["sig-9"], (
        f"corpus_load_one no longer reads the alert through the owner: "
        f"{[(c.case_id, c.signature_id) for c in companions]}, skipped={report.skipped}")


def test_compaction_dryruns_wire_log_accessor_still_resolves_after_d1(tmp_path: Path):
    """`compaction_dryrun`'s `RunPaths(p).wire_log` construction (claim G1, outside both the
    gate's sweep and the reference resolver's floor) still resolves identically after D1's
    RunPaths rewrite, and its loader still reads a record carrying decision 18's new
    `writer_id`.

    The payload half is claim RG-9 (92-reconciliation.md finding 3): decision 18 changes the
    bytes of a file this tool parses, and an accessor-grain check alone would have let that
    through. `_load_main_records` (`scripts/testing/compaction_dryrun.py:49-60`) is a raw
    `json.loads(line)` followed by `.get(...)` on every field, so an added key is tolerated —
    observed here rather than assumed.
    """
    tool = load_module(
        DEFENDER.parent / "scripts" / "testing" / "compaction_dryrun.py", name="_cdr_1077")
    run_dir = S.seed_run_tree(tmp_path / "a-run")
    log = S.RunPaths(run_dir).wire_log
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text("{}\n", encoding="utf-8")

    assert tool._resolve_jsonl(str(run_dir)) == log, (
        "the repo-root tool outside the sweep still resolves the wire log through the owner; "
        "a rewrite that moved the name without moving this reader would resolve a file no run "
        "has")

    # RG-9. The same tool, at the PAYLOAD grain: post-decision-18 records, with the new field.
    post_d18 = [
        {"agent_id": "main", "seq": 1, "kind": "request", "writer_id": "MAIN"},
        {"agent_id": "main", "seq": 0, "kind": "request", "writer_id": "MAIN"},
        {"agent_id": "gather-l-aaa111", "seq": 2, "kind": "request",
         "writer_id": "gather-l-aaa111"},
    ]
    log.write_text("".join(json.dumps(r) + "\n" for r in post_d18), encoding="utf-8")
    loaded = tool._load_main_records(log, "main")
    assert [r["seq"] for r in loaded] == [0, 1], (
        "`_load_main_records` stopped selecting and ordering MAIN's records once they carried "
        f"`writer_id`: {loaded}")
    assert all(r["writer_id"] == "MAIN" for r in loaded), (
        "the added key did not survive the raw `json.loads` + `.get(...)` read")
