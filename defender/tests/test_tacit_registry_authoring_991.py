"""The authoring path for the tacit-knowledge registry: how a human gets an entry INTO it, and
what tells them when they got it wrong.

THE GAP THIS CLOSES. The registry is the one system of record in this tree with no service
behind it — a human edits YAML and commits, and the commit IS the sign-off. Every safety
property of that is deliberate. What was missing sat underneath it: the edit had no feedback of
any kind. A malformed entry is DROPPED rather than refused (one bad row must not sink every
sanction in the estate), the reason prints on stderr DURING AN INVESTIGATION RUN, and nobody is
watching that stream. So a typo produced exactly what an unwritten entry produces — the lookup
misses, the authorization contract falls through to `indeterminate`, and the run escalates a
case somebody had already sanctioned. Silent, and silent in the direction that looks like
ordinary operation.

The refusal text was already written for a human; `_read_entry`'s own docstring says so. It had
no reader. Three things now read it, and each is tested here:

  * `read_registry` — THE one walk, returning survivors and refusals together, so the tool a
    human runs and the verb a run dispatches cannot disagree about what loads.
  * `tacit_cli check` — the reader, exiting non-zero on any drop.
  * CI — running that command as a hard gate, which is where it belongs: the commit is the only
    review this file gets, so a dropped entry has to fail the PR that introduced it rather than
    an investigation weeks later.

Plus the human-facing surfaces that have to stay true: the file's own worked example must
actually load, and the connect skill's authoring route must keep the two properties that make
transcription safe (the human is the author; the agent never invents a scope).
"""
from __future__ import annotations

import datetime as dt
import io
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

from defender.scripts import tacit_cli
from defender.scripts.adapters import tacit_knowledge_adapter as tk

from defender.tests import _tacit983 as scene
from defender.tests._spec791 import (  # noqa: F401 — session-scoped autouse guard
    worktree_package_guard,
)

pytestmark = pytest.mark.gate

REPO_ROOT = Path(__file__).resolve().parents[2]
SHIPPED_REGISTRY = REPO_ROOT / "defender" / "skills" / "tacit-knowledge" / "registry.yaml"
CONNECT_ROUTE = REPO_ROOT / "defender" / "skills" / "connect" / "tacit.md"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"


def _tree(tmp_path: Path, *entries: dict) -> Path:
    """A throwaway defender tree holding a registry — what `--defender-dir` points at."""
    scene.write_registry(tmp_path, *entries)
    return tmp_path


def _run(*argv: str) -> tuple[int, str]:
    """`tacit_cli.main` with its stdout captured, as a human would see it."""
    buf = io.StringIO()
    with redirect_stdout(buf), redirect_stderr(buf):
        rc = tacit_cli.main(list(argv))
    return rc, buf.getvalue()


# ---------------------------------------------------------------------------------------
# One walk, two readers.
# ---------------------------------------------------------------------------------------

def test_the_validator_and_the_verb_read_the_same_walk(tmp_path) -> None:
    """`read_registry` is what BOTH the CLI and a live `lookup` consume, so a human cannot be
    told an entry loads while every lookup misses it.

    The rule `policy_cli` states for the gate, applied here: a validator that modelled the rules
    separately would be worse than none, because it would certify a file the runtime reads
    differently. Asserted as identity of RESULT — `load_entries`, the verb-side surface, returns
    exactly what the walk kept — rather than as a claim about the call graph."""
    tree = _tree(
        tmp_path,
        scene.registry_entry(),
        scene.registry_entry(id="tk-blanket", actor_scope="*"),
        scene.registry_entry(id="tk-stale", added_at="2026-01-01", review_by="2027-06-01"),
    )
    path = tk.registry_path(tree)

    read = tk.read_registry(path)
    assert [e["id"] for e in read.entries] == [scene.ENTRY_ID], (
        "the walk kept an entry the loader refuses, or dropped one it keeps"
    )
    assert len(read.refusals) == 2, "the walk did not report both drops"

    with redirect_stderr(io.StringIO()):
        served = tk.load_entries(path)
    assert served == list(read.entries), (
        "the verb a run dispatches and the walk a human validates against disagree about what "
        "loads — the validator would certify a file the runtime reads differently"
    )


def test_a_drop_names_the_field_and_the_rule(tmp_path) -> None:
    """Every refusal is actionable text, because the person who can repair the row is the human
    who committed it and this is the only thing that reaches them.

    One case per rule the loader enforces, asserted on WHAT THE MESSAGE NAMES rather than on its
    wording: a refusal that says "invalid entry" is a refusal nobody can act on, and that is the
    state this whole path was in when the message went only to stderr during a run."""
    for entry, must_name in (
        (scene.registry_entry(actor_scope="*"), "actor_scope"),
        (scene.registry_entry(host_scope="[!QQQQ]*"), "host_scope"),
        (scene.registry_entry(review_by="2027-06-01"), "review_by"),
        (scene.registry_entry(added_at="not-a-date"), "added_at"),
    ):
        read = tk.read_registry(tk.registry_path(_tree(tmp_path / must_name, entry)))
        assert len(read.refusals) == 1, f"{must_name}: expected exactly one drop"
        assert must_name in read.refusals[0], (
            f"the refusal does not name `{must_name}` — a human cannot repair a row from it: "
            f"{read.refusals[0]!r}"
        )


# ---------------------------------------------------------------------------------------
# The reader.
# ---------------------------------------------------------------------------------------

def test_check_fails_on_a_drop_and_says_what_a_drop_costs(tmp_path) -> None:
    """`check` exits non-zero on any dropped entry, and explains the consequence.

    The exit code is what makes it a gate. The explanation is what makes it useful: the reason a
    drop matters is not that the file is untidy, it is that a dropped entry is INDISTINGUISHABLE
    from one nobody wrote — so the author's mental model ("I sanctioned that") and the runtime's
    behaviour ("nobody sanctioned that") diverge with no signal anywhere."""
    tree = _tree(tmp_path, scene.registry_entry(), scene.registry_entry(
        id="tk-blanket", actor_scope="*"))

    rc, out = _run("check", "--defender-dir", str(tree))
    assert rc == 1, "a registry with a dropped entry passed the check"
    for named in ("DROPPED", "blanket scope"):
        assert named in out, f"the check does not say {named!r}: {out}"
    assert "indistinguishable" in out.lower(), (
        "the check reports a drop without saying what a drop costs — the consequence is the "
        "whole reason this runs at commit time rather than never"
    )

    clean = _tree(tmp_path / "clean", scene.registry_entry())
    rc, out = _run("check", "--defender-dir", str(clean))
    assert rc == 0, f"a well-formed registry failed the check: {out}"


def test_check_fails_loudly_on_a_file_whose_shape_is_wrong(tmp_path) -> None:
    """A typo in the `entries:` key fails the check, rather than reading as an empty registry.

    This is the drop that used to be completely silent, and the worst one: it disables EVERY
    sanction at once, and the resulting behaviour — every lookup a miss — is exactly what a
    correctly-empty registry produces."""
    path = tmp_path.joinpath(*scene.REGISTRY_RELPATH)
    path.parent.mkdir(parents=True)
    path.write_text("entires:\n  - id: tk-1\n", encoding="utf-8")

    rc, out = _run("check", "--defender-dir", str(tmp_path))
    assert rc == 1, "a registry that declares no `entries:` list passed the check"
    assert "no `entries:` list" in out, f"the check does not name the fault: {out}"


def test_check_warns_before_a_sanction_stops_answering_without_failing(tmp_path) -> None:
    """An entry near its review date is a NOTE, never a failure — and an expired one is still a
    note, because it loads.

    The separation is the point. `check`'s failures are exactly the loader's drops; everything
    advisory is labelled as advice. Folding "expiring soon" into the failure set would mint a
    second policy the runtime does not enforce, which is the thing this module's docstring
    refuses to do.

    Both matter to a human because expiry is otherwise invisible: past `review_by` an entry
    simply stops answering, with no event anywhere."""
    today = dt.date(2026, 5, 5)
    soon = _tree(tmp_path / "soon", scene.registry_entry(
        added_at="2026-04-01", review_by="2026-05-20"))
    rc, out = _run("check", "--defender-dir", str(soon), "--as-of", today.isoformat())
    assert rc == 0, "an entry inside its own window failed the check"
    assert "expires in 15 day(s)" in out, f"no warning before it stops answering: {out}"

    gone = _tree(tmp_path / "gone", scene.registry_entry(
        added_at="2025-11-01", review_by="2026-01-01"))
    rc, out = _run("check", "--defender-dir", str(gone), "--as-of", today.isoformat())
    assert rc == 0, "an expired entry FAILED the check — it loads, it just answers nothing"
    assert "EXPIRED" in out, f"an expired entry was reported as healthy: {out}"


def test_a_precise_short_actor_is_not_reported_as_broad(tmp_path) -> None:
    """`uid-0` is the design's own motivating actor and carries no wildcard, so it is not broad.

    A note that fires on the canonical entry is a note the reader learns to skip, which costs
    the notes that matter. Breadth comes from the wildcard: a scope with no metacharacter names
    ONE thing however short it is, and a mostly-star scope is broad however it is spelled."""
    precise = _tree(tmp_path / "precise", scene.registry_entry(
        actor_scope=scene.ACTOR, host_scope="build-runner-*.prod"))
    _rc, out = _run("check", "--defender-dir", str(precise))
    assert "broad" not in out, f"a wildcard-free actor scope was called broad: {out}"

    # `prod-*` is the SKILL's own stated limit — "mostly literal and still covers a fleet", the
    # case a character count cannot judge and a human can. It clears the loader's minimum, so
    # the note is the ONLY thing that will ever mention it.
    wide = _tree(tmp_path / "wide", scene.registry_entry(host_scope="prod-*"))
    rc, out = _run("check", "--defender-dir", str(wide))
    assert rc == 0, f"a legal fleet-wide scope was refused rather than noted: {out}"
    assert "broad" in out, (
        "a scope that clears the minimum and still covers a fleet drew no note at all — the "
        "loader cannot judge breadth, so nothing else will raise it with the author"
    )


def test_show_answers_what_is_in_force_rather_than_what_parses(tmp_path) -> None:
    """`show` reports the sanctions ANSWERING today, which is the question a reviewer asks.

    Distinct from `check` on purpose: a file can be perfectly well formed and cover nothing,
    every entry having quietly aged past its own review date — and a run only ever sees this
    answer."""
    tree = _tree(tmp_path, scene.registry_entry(
        added_at="2025-11-01", review_by="2026-01-01"))

    rc, out = _run("show", "--defender-dir", str(tree), "--as-of", "2026-05-05")
    assert rc == 0
    assert "No sanction is in force" in out, (
        f"a registry whose only entry has expired reported it as in force: {out}"
    )
    assert "1 entr" in out, "the reader is not told the file parses — only that it covers nothing"

    rc, out = _run("show", "--defender-dir", str(tree), "--as-of", "2025-12-01")
    for named in (scene.ENTRY_ID, scene.PATTERN):
        assert named in out, f"an in-force sanction did not report {named!r}: {out}"
    assert "sre-platform@example.invalid" in out, (
        "`show` omits who authored the sanction — the field a reviewer judges it by"
    )


# ---------------------------------------------------------------------------------------
# The surfaces a human actually meets.
# ---------------------------------------------------------------------------------------

def test_the_shipped_registry_passes_its_own_gate() -> None:
    """The file in this tree passes the command CI runs against it.

    The gate is only a gate if the committed file clears it; a registry that ships red teaches
    everyone to ignore the check."""
    rc, out = _run("check")
    assert rc == 0, f"the shipped registry fails its own CI gate: {out}"


def test_the_files_worked_example_actually_loads(tmp_path) -> None:
    """The commented-out example in `registry.yaml` loads clean when uncommented.

    The file ships with no entries, so that example is the only thing a first author has to
    copy. An example that would be DROPPED is worse than none: it teaches the exact mistake, and
    the mistake is invisible at run time.

    Uncommented mechanically — the example is written as ordinary YAML behind `# `, precisely so
    this test can strip the prefix rather than re-typing it and testing a different thing."""
    text = SHIPPED_REGISTRY.read_text(encoding="utf-8")
    lines = text.splitlines()
    start = next(i for i, ln in enumerate(lines) if ln.strip() == "# entries:")
    block = []
    for line in lines[start:]:
        if not line.startswith("#"):
            break
        block.append(line.removeprefix("# ").removeprefix("#"))

    path = tmp_path.joinpath(*scene.REGISTRY_RELPATH)
    path.parent.mkdir(parents=True)
    path.write_text("\n".join(block) + "\n", encoding="utf-8")

    read = tk.read_registry(path)
    assert read.fatal is None, f"the worked example is not loadable YAML: {read.fatal}"
    assert read.refusals == (), f"the worked example would be DROPPED: {read.refusals}"
    assert len(read.entries) == 1, "the worked example does not parse as one entry"
    assert tk.find_entry(
        list(read.entries), actor="uid-0", host="build-runner-07.prod",
        pattern="rewrite /etc/ssl/certs/ca-bundle.crt", now=dt.date(2026, 5, 5),
    ) is not None, (
        "the worked example loads and then does not answer the case it is an example OF"
    )


def test_ci_runs_the_check_as_a_blocking_gate() -> None:
    """CI runs `tacit_cli check`, and runs it where a failure blocks.

    The commit is the only review this file gets, so the check has to fail the PR that
    introduced a bad entry — not an investigation weeks later. Asserted on the workflow because
    a validator nothing invokes is the state the loader's own stderr messages were already in."""
    ci = CI_WORKFLOW.read_text(encoding="utf-8")
    assert "defender.scripts.tacit_cli check" in ci, (
        "CI does not run the registry check — the file's only review is the commit, and "
        "nothing checks the commit"
    )
    assert "continue-on-error" not in ci.split("tacit_cli check")[1][:200], (
        "the registry check is advisory; a drop has to fail the PR that introduced it"
    )


def test_the_connect_route_transcribes_and_never_authors() -> None:
    """The authoring route keeps the two properties that make agent transcription safe.

    A skill writing this file is fine BECAUSE the commit is still the sign-off and the human is
    still the author — it removes the hand-typed YAML, not the review. Both halves have to stay
    in the doc, because they are what someone reading it takes as licence: the moment the agent
    is the `added_by`, or infers a scope, the registry is the system vouching for itself, which
    is the exact failure its read-only design exists to prevent."""
    route = CONNECT_ROUTE.read_text(encoding="utf-8")

    for claim, why in (
        ("added_by", "the route does not say whose name goes on the entry"),
        ("transcription", "the route does not frame itself as transcription rather than approval"),
        ("commit is the sign-off", "the route does not preserve the commit as the sign-off"),
        ("never decide", "the route does not forbid the agent deciding something is sanctioned"),
        ("do not merge or push", "the route does not stop short of merging its own branch"),
    ):
        assert claim.lower() in route.lower(), why

    entry = CONNECT_ROUTE.parent / "SKILL.md"
    skill = entry.read_text(encoding="utf-8")
    assert "tacit.md" in skill, (
        "the route is unreachable — the connect entrypoint never points at it"
    )
    assert "tacit-knowledge sanction" in skill, (
        "the connect skill's own description does not mention the sanction-recording job, so a "
        "human asking for one never loads the skill that does it"
    )
