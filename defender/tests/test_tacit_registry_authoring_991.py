"""Authoring path for the tacit-knowledge registry: a dropped entry names its field and rule, `check` fails loudly on a drop or wrong shape and warns before a sanction expires, `show` reports what is in force, and the shipped file passes its own gate."""
from __future__ import annotations

import datetime as dt
import io
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from defender.scripts import tacit_cli
from defender.scripts.adapters import tacit_knowledge_adapter as tk

from defender.tests import _tacit983 as scene
from defender.tests._spec791 import (  # noqa: F401 — session-scoped autouse guard
    worktree_package_guard,
)


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


def test_the_validator_and_the_verb_read_the_same_walk(tmp_path) -> None:
    """`read_registry` is what BOTH the CLI and a live `lookup` consume, so a human cannot be
    told an entry loads while every lookup misses it."""
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
    who committed it and this is the only thing that reaches them."""
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


def test_check_fails_on_a_drop_and_says_what_a_drop_costs(tmp_path) -> None:
    """`check` exits non-zero on any dropped entry, and explains the consequence."""
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
    """A typo in the `entries:` key fails the check, rather than reading as an empty registry."""
    path = tmp_path.joinpath(*scene.REGISTRY_RELPATH)
    path.parent.mkdir(parents=True)
    path.write_text("entires:\n  - id: tk-1\n", encoding="utf-8")

    rc, out = _run("check", "--defender-dir", str(tmp_path))
    assert rc == 1, "a registry that declares no `entries:` list passed the check"
    assert "no `entries:` list" in out, f"the check does not name the fault: {out}"


def test_check_warns_before_a_sanction_stops_answering_without_failing(tmp_path) -> None:
    """An entry near its review date is a NOTE, never a failure — and an expired one is still a
    note, because it loads."""
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
    """`uid-0` is the design's own motivating actor and carries no wildcard, so it is not broad."""
    precise = _tree(tmp_path / "precise", scene.registry_entry(
        actor_scope=scene.ACTOR, host_scope="build-runner-*.prod"))
    _rc, out = _run("check", "--defender-dir", str(precise))
    assert "broad" not in out, f"a wildcard-free actor scope was called broad: {out}"

    wide = _tree(tmp_path / "wide", scene.registry_entry(host_scope="prod-*"))
    rc, out = _run("check", "--defender-dir", str(wide))
    assert rc == 0, f"a legal fleet-wide scope was refused rather than noted: {out}"
    assert "broad" in out, (
        "a scope that clears the minimum and still covers a fleet drew no note at all — the "
        "loader cannot judge breadth, so nothing else will raise it with the author"
    )


def test_show_answers_what_is_in_force_rather_than_what_parses(tmp_path) -> None:
    """`show` reports the sanctions ANSWERING today, which is the question a reviewer asks."""
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


def test_the_shipped_registry_passes_its_own_gate() -> None:
    rc, out = _run("check")
    assert rc == 0, f"the shipped registry fails its own CI gate: {out}"


def test_the_files_worked_example_actually_loads(tmp_path) -> None:
    """The commented-out example in `registry.yaml` loads clean when uncommented."""
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
