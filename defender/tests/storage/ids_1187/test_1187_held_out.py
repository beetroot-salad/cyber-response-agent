"""Held-out scoring reads the index of opaque run IDs (#1187); there is no launch command (#1279 rev 4, A10)."""
from __future__ import annotations


import json
import os
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from defender.tests.support.shared._fixture_uuid import fixture_uuid

from defender.tests.storage.ids_1187 import _spec1187 as S
from defender.tests.storage.tenant_1105_run_repository import _spec1105_pr2 as P
from itertools import takewhile

SLUG = "m05-lsass-access"
OTHER = "b01-benign-logon"
#: A tenant id scoring must refuse to take (§7 J50).
LAUNCH_TENANT = fixture_uuid("tenant:playground")
INDEX_NAME = "held-out-index.jsonl"
#: The failure bucket an absent or recordless indexed run lands in (recheck X2, quoted).
NO_RUN_RECORD = "launched, no run record"
# Inputs on the real filesystem

def _fixtures(root: Path, truths: dict[str, str]) -> Path:
    """A held-out fixture set: `<root>/<slug>/alert.json` plus a labelled `ground_truth.yaml` per slug, the shape `load_held_out_fixtures` admits."""
    for slug, disposition in truths.items():
        member = root / slug
        member.mkdir(parents=True)
        (member / "alert.json").write_text('{"alert": "held-out"}\n', encoding="utf-8")
        (member / "ground_truth.yaml").write_text(
            f"held_out: true\ndisposition: {disposition}\n", encoding="utf-8")
    return root


def _run(runs: Path, run_id: str | None = None, *, says: str | None,
         record: bool = True) -> Path:
    """Create a run with an alert record and an optional disposition report."""
    from defender.run_repository import RunPaths

    run_dir = S.make_run(runs, run_id)
    paths = RunPaths(run_dir)
    if not record:
        paths.alert_record.unlink()
    if says is not None:
        paths.report.write_text(P.T.report_text(says), encoding="utf-8")
    return run_dir


def _index(path: Path, *rows: tuple[str, str]) -> Path:
    """F holding `rows` (`(slug, run_id)`, oldest first) as the contract pins it: JSON Lines."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps({"slug": slug, "run_id": run_id}) + "\n"
                            for slug, run_id in rows), encoding="utf-8")
    return path


def _rows(text: str | None) -> list[tuple[str, str]]:
    """F's rows as `(slug, run_id)`, read by the TEST (plain JSON Lines). #1108 P4 OD10: F
    also records the knowledge commit resolved at its creation, in a shape not designed; a
    line that carries no `slug` is that record, not a launch row, and is skipped."""
    if not text:
        return []
    out = []
    for line in text.splitlines():
        if line.strip():
            row = json.loads(line)
            if "slug" not in row:
                continue
            out.append((row["slug"], row["run_id"]))
    return out
# The CLI, driven through `held_out.main`

@dataclass
class Outcome(P.CliResult):
    """What one `held_out.main` call did."""

    crashed: BaseException | None = None

    def verdicts(self) -> dict[str, str]:
        """`{slug: "OK" | "WRONG"}` from the report's per-fixture lines."""
        found: dict[str, str] = {}
        for line in self.out.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ("OK", "WRONG") and parts[1].endswith(":"):
                found[parts[1][:-1]] = parts[0]
        return found

    def line_for(self, slug: str) -> str:
        hits = [ln for ln in self.out.splitlines()
                if ln.split()[1:2] == [f"{slug}:"] and ln.split()[0] in ("OK", "WRONG")]
        return hits[0] if hits else ""

    def section(self, header: str) -> list[str]:
        body = self.out.partition(f"## {header}")[2].partition("\n")[2]
        return [line.strip() for line in takewhile(
            lambda line: bool(line.strip()) and not line.startswith("#"), body.splitlines())]

    def failures(self) -> dict[str, str]:
        """`{slug: reason}` from the failure bucket (` <slug>: <reason>`)."""
        out = {}
        for ln in self.section("Failure bucket"):
            slug, _, reason = ln.partition(":")
            out[slug.strip()] = reason.strip()
        return out

    def not_run(self) -> list[str]:
        return self.section("Not run")

    def accuracy(self) -> tuple[int, int] | None:
        for ln in self.out.splitlines():
            if ln.startswith("Aggregate accuracy:"):
                c, _, t = ln.split(":", 1)[1].split()[0].partition("/")
                if c.isdigit() and t.isdigit():
                    return int(c), int(t)
        return None

    def assert_score(self, verdicts: dict[str, str], accuracy: tuple[int, int], *, not_run=()):
        assert self.crashed is None, self.crashed
        assert self.rc == 0, self.said
        assert self.verdicts() == verdicts, self.out
        assert self.accuracy() == accuracy, self.out
        assert self.not_run() == list(not_run), self.out


def _cli(argv: Sequence[object], **seams: Any) -> Outcome:
    from evaluations import held_out

    crashed = None

    def invoke(args):
        nonlocal crashed
        try:
            return held_out.main(args, **seams)
        except SystemExit:
            raise
        except BaseException as exc:  # noqa: BLE001 — injected child failures are observations
            crashed = exc
            return None

    got = P.drive_cli(invoke, list(map(str, argv)))
    return Outcome(got.rc, got.out, got.err, got.raised, crashed)


def _score(runs: Path, index: Path, fixtures: Path, *extra: object) -> Outcome:
    """`held_out.py <runs> --index <index> --fixtures-dir <fixtures>`."""
    return _cli([runs, "--index", index, "--fixtures-dir", fixtures, *extra])


def _assert_refused(res: Outcome, index: Path, what: str) -> None:
    assert res.crashed is None, f"{what}: the command crashed instead of refusing: {res.crashed!r}"
    assert res.rc not in (0, None), f"{what}: exit {res.rc}, not a refusal:\n{res.out}\n{res.err}"
    assert "unrecognized arguments" not in res.err, (
        f"{what}: the argv was not understood, so nothing was judged:\n{res.err}")
    assert index.name in res.said, f"{what}: the refusal does not name the index:\n{res.said}"


@pytest.fixture
def scoring(tmp_path: Path) -> tuple[Path, Path, Path]:
    """`(runs dir, index path, ops folder)`: the runs dir scoring is handed, and F in the operator's own folder beside it (outside the runs dir)."""
    runs = tmp_path / "runs"
    runs.mkdir()
    ops = tmp_path / "ops"
    ops.mkdir()
    return runs, ops / INDEX_NAME, ops


@pytest.mark.parametrize(("latest", "verdict", "accuracy"), [
    ("wrong", "WRONG", (0, 1)), ("right", "OK", (1, 1)),
])
def test_scoring_uses_index_order_instead_of_folder_age(tmp_path, scoring, latest, verdict, accuracy):
    runs, index, _ = scoring
    fixtures = _fixtures(tmp_path / "fixtures", {SLUG: "malicious"})
    right, wrong = _run(runs, says="malicious"), _run(runs, says="benign")
    os.utime(wrong, (1_800_000_000, 1_800_000_000))
    os.utime(right, (1_800_000_600, 1_800_000_600))
    first, last = (right, wrong) if latest == "wrong" else (wrong, right)
    _index(index, (SLUG, first.name), (SLUG, last.name))
    res = _score(runs, index, fixtures)
    res.assert_score({SLUG: verdict}, accuracy)
    if latest == "wrong":
        assert "'benign'" in res.line_for(SLUG), res.out


def test_a_row_naming_an_absent_or_recordless_run_scores_wrong_not_not_run(tmp_path, scoring):
    runs, index, _ = scoring
    truths = {"absent-case": "malicious", "recordless-case": "benign",
              "no-report-case": "benign", "scored-case": "benign"}
    fixtures = _fixtures(tmp_path / "fixtures", truths)
    recordless = _run(runs, says="benign", record=False)
    no_report = _run(runs, says=None)
    scored = _run(runs, says="benign")
    _index(index, ("absent-case", S.new_id()), ("recordless-case", recordless.name),
           ("no-report-case", no_report.name), ("scored-case", scored.name))

    res = _score(runs, index, fixtures)
    res.assert_score({"absent-case": "WRONG", "recordless-case": "WRONG",
                      "no-report-case": "WRONG", "scored-case": "OK"}, (1, 4))
    failures = res.failures()
    for slug in ("absent-case", "recordless-case"):
        assert NO_RUN_RECORD in failures.get(slug, ""), (
            f"{slug} is not in the {NO_RUN_RECORD!r} bucket:\n{res.out}")
    assert "report.md" in failures.get("no-report-case", ""), res.out
    assert NO_RUN_RECORD not in failures.get("no-report-case", ""), res.out
    assert "scored-case" not in failures, res.out


def test_an_index_from_the_old_launcher_scores_past_its_knowledge_pin_line(tmp_path, scoring):
    """An index the #1108 P4 launcher wrote opens with a `{"knowledge_commit": …}` line; scoring
    skips that line and scores the rows after it."""
    runs, index, _ = scoring
    fixtures = _fixtures(tmp_path / "fixtures", {SLUG: "malicious"})
    run = _run(runs, says="malicious")
    _index(index, (SLUG, run.name))
    index.write_text(json.dumps({"knowledge_commit": "a" * 40}) + "\n"
                     + index.read_text(encoding="utf-8"), encoding="utf-8")
    _score(runs, index, fixtures).assert_score({SLUG: "OK"}, (1, 1))


def test_a_slug_with_no_row_is_not_run_whatever_folders_are_named_after_it(tmp_path, scoring):
    runs, index, _ = scoring
    fixtures = _fixtures(tmp_path / "fixtures", {SLUG: "benign", OTHER: "benign"})
    for name in (SLUG, f"{SLUG}-n5-a", f"20260718t101500z-{SLUG}", f"sec-eval-gen7-{SLUG}-ab12cd34"):
        _run(runs, name, says="malicious")
    indexed = _run(runs, says="benign")
    decoy = _run(runs, OTHER, says="malicious")
    os.utime(indexed, (1_800_000_000, 1_800_000_000))
    os.utime(decoy, (1_800_000_600, 1_800_000_600))
    _index(index, (OTHER, indexed.name))

    res = _score(runs, index, fixtures)
    res.assert_score({OTHER: "OK"}, (1, 1), not_run=[SLUG])


def test_scoring_without_an_index_scores_no_folder_by_its_name(tmp_path, scoring):
    runs, index, _ = scoring
    fixtures = _fixtures(tmp_path / "fixtures", {SLUG: "benign"})
    _run(runs, SLUG, says="benign")
    res = _cli([runs, "--fixtures-dir", fixtures])
    assert res.crashed is None, f"scoring crashed: {res.crashed!r}\n{res.err}"
    assert res.verdicts() == {}, f"a folder was scored by its name with no index:\n{res.out}"

    indexed = _run(runs, says="benign")
    _index(index, (SLUG, indexed.name))
    res = _score(runs, index, fixtures)
    assert res.verdicts() == {SLUG: "OK"}, f"control: the indexed run was not scored:\n{res.out}"


def test_the_folder_name_matcher_is_gone():
    from evaluations import held_out

    assert not hasattr(held_out, "_claimed_slug"), "the folder-name matcher is still defined"
# Scoring: where F may not be, and what scoring never reads (recheck X3, J50)

@pytest.mark.parametrize("place", ["runs-root", "run-folder", "linked-index-parent", "linked-runs-root"])
def test_scoring_refuses_an_index_inside_its_runs_dir(tmp_path, scoring, place):
    runs, ops_index, _ = scoring
    fixtures = _fixtures(tmp_path / "fixtures", {SLUG: "benign"})
    good = _run(runs, says="benign")
    handed, index = runs, runs / INDEX_NAME
    if place == "run-folder":
        index = S.make_run(runs) / INDEX_NAME
    elif place == "linked-index-parent":
        link = tmp_path / "ops-link"
        link.symlink_to(S.make_run(runs))
        index = link / INDEX_NAME
    elif place == "linked-runs-root":
        handed = tmp_path / "runs-link"
        handed.symlink_to(runs)
    _index(index, (SLUG, good.name))
    held = index.read_bytes()

    res = _score(handed, index, fixtures)
    _assert_refused(res, index, "an index inside the runs dir")
    assert res.verdicts() == {}, f"scoring went ahead with an index inside its runs dir:\n{res.out}"
    assert res.accuracy() is None, res.out
    assert index.read_bytes() == held

    _index(ops_index, (SLUG, good.name))
    res = _score(runs, ops_index, fixtures)
    assert res.verdicts() == {SLUG: "OK"}, f"control: an index outside was not scored:\n{res.out}"


@pytest.mark.parametrize("scope", ["root-unset", "root-relative", "tenant-argument", "links-from-run"])
def test_scoring_depends_only_on_the_index_and_given_runs(tmp_path, scoring, monkeypatch, scope):
    from defender.tenancy._tenant import resolve_data_root

    runs, index, ops = scoring
    fixtures = _fixtures(tmp_path / "fixtures", {SLUG: "benign"})
    good = _run(runs, says="benign")
    _index(index, (SLUG, good.name))
    if scope.startswith("root-"):
        if scope == "root-unset":
            monkeypatch.delenv(S.DATA_ROOT_ENV, raising=False)
        else:
            monkeypatch.setenv(S.DATA_ROOT_ENV, "relative/garbage")
        assert S.raised(resolve_data_root) is not None, "control root unexpectedly resolves"
    elif scope == "links-from-run":
        planted = S.make_run(runs)
        (planted / "points-at-the-index").symlink_to(index)
        (planted / "points-at-its-folder").symlink_to(ops)
    else:
        refused = _score(runs, index, fixtures, "--tenant", LAUNCH_TENANT)
        assert refused.rc == 2, refused.err
        assert "--tenant" in refused.err
        assert refused.verdicts() == {}
    _score(runs, index, fixtures).assert_score({SLUG: "OK"}, (1, 1))
