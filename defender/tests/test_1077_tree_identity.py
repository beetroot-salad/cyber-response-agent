"""#1077 — O3's tree observer, and the writers that share a run directory.

Carries 11 demands of `spec-flow/specs/spec_graph_1077.yaml`. O3 says a run built through the
handle produces today's directory tree, and claim C8 established that the EXISTING goldens are
not that observer: they compare one normalised investigation text and three `iterdir()` entry
names. This file is the new observer.

DECISION 21 REDESIGNED IT, SUPERSEDING DECISION 14 IN FULL. An executed probe — two `_replay()`
calls against `main`, same run id, diffed — proved the "byte-identical, two exemptions" promise
false independently of this issue's own code: eight files differ for reasons that predate the
refactor entirely (wall-clock timestamps in `budget.json` and `tool_trace.jsonl`; a per-run
random security salt inside `review_record.<turn>.json` and the three
`wire_logs/review_*_trace.jsonl`; random per-run session/case identifiers in
`session_store_pointer.json` and `tool_trace.jsonl`). So the observer is two checks:

* STRUCTURAL, strict and load-bearing — the run directory produces the SAME SET OF NAMES, with
  nothing added, removed, renamed or moved, compared AFTER the run ends so the sandbox alias
  probe's transient entries are never in scope. Directories and symlinks carry their kind and
  link target; NO entry carries bytes.
* CONTENT, narrow — bytes are compared for `investigation.md` and `report.md` only: the two
  artifacts the model generates from the same fixed replay input and that a human reads.

THERE IS NO EXEMPTION LIST. Everything else in the tree — budget, tool trace, session pointer,
the wire logs, the review records and traces — gets no byte assertion at all: not exempted with
a reason, not normalised, simply not compared, because it was never stable to begin with. That
also subsumes decision 18's wire-log amendment: the wire log was never byte-compared here, so
its new writer id needs no carve-out. These tests assert THAT contract, never the superseded
one, and `_spec1077.snapshot` deliberately takes no `exclude` argument so the widening lever
`O3_EXEMPT` handed a red-test implementer is gone rather than lengthened.

RED AGAINST BASE by construction twice over: `defender/tests/_tree_baseline_1077.json` does not
exist (D7 step 1 captures it, and the observer must ship green on `main` before step 3), and
the handle the comparison run is driven through does not exist either.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from defender.tests import _spec1077 as S

pytest.importorskip("pydantic_ai")

from defender.tests.e2e._replay_harness import (  # noqa: E402
    GOLDEN,
    ReplayFn,
    Turn,
    drive,
    materialize,
)

pytestmark = pytest.mark.e2e


def _replay(tmp_path: Path, run_id: str = "tree-1077") -> Path:
    """One whole replayed fixture run, driven through the real driver, ended normally."""
    run_dir = materialize(tmp_path, GOLDEN)
    replay = ReplayFn([
        Turn(tool_calls=[("append_block", {"text": (GOLDEN / "investigation.md").read_text()})]),
        Turn(tool_calls=[("close_investigation", {"disposition": "inconclusive"})]),
        Turn(text="Investigation complete."),
    ])
    drive(run_dir, run_id=run_id, main=replay)
    return run_dir


def _baseline_exists() -> None:
    assert S.TREE_BASELINE.is_file(), (
        "the O3 baseline does not exist. D7 step 1 captures it BEFORE step 3, on `main`, with "
        "no implementation behind it — the existing goldens are not this observer (claim C8: "
        "they compare one normalised investigation text and three iterdir() names)")


# ---------------------------------------------------------------------------------------
# d13 / d14 — the structural check, and the narrow content check beside it
# ---------------------------------------------------------------------------------------

def test_a_replayed_fixture_run_tree_carries_the_same_set_of_names(tmp_path: Path):
    """Replaying a fixture run through the handle produces a run directory whose SET OF NAMES
    is the pre-migration one exactly — no entry added, removed, renamed or moved — with no
    exemption and no entry excused."""
    _baseline_exists()
    run_dir = _replay(tmp_path)
    doc = S.load_baseline()
    assert S.structural_findings(run_dir, doc) == [], (
        "\n".join(S.structural_findings(run_dir, doc)))

    # The check is over the WHOLE tree: no name is excused, and the machinery offers no lever
    # to excuse one. Decision 21 removed `O3_EXEMPT` rather than lengthening it.
    assert not hasattr(S, "O3_EXEMPT"), (
        "an exemption list came back. Decision 21 removed it: eight files differ between two "
        "replays of UNCHANGED code, so an exemption list is a widening lever, not a contract")
    assert "exclude" not in S.snapshot.__code__.co_varnames, (
        "`snapshot` grew an `exclude` argument — the structural check admits no exemption, "
        "which is the only thing that makes 'the same set of names' worth asserting")
    # And the per-run-unstable files ARE in the compared name set: their names are pinned even
    # though their bytes are not.
    names = set(S.snapshot(run_dir))
    for unstable in ("budget.json", "tool_trace.jsonl", "session_store_pointer.json"):
        assert unstable in names, (
            f"{unstable} is outside the structural check. Its BYTES are not compared (it "
            "carries a clock or a per-run uuid); its NAME is, and that is the whole point of "
            "splitting the two checks rather than exempting the file")


def test_bytes_are_compared_for_the_investigation_and_the_report_and_nothing_else(
        tmp_path: Path):
    """Byte comparison applies to the investigation write-up and the final report and to no
    other entry in the tree: everything else carries no byte assertion at all."""
    _baseline_exists()
    run_dir = _replay(tmp_path)
    doc = S.load_baseline()
    assert tuple(S.O3_CONTENT) == ("investigation.md", "report.md"), (
        "the content check is these two documents — the artifacts the model generates from "
        "the SAME fixed replay input and that a human actually reads")
    assert sorted(doc["content"]) == sorted(S.O3_CONTENT), (
        f"the baseline carries byte digests for {sorted(doc['content'])}; the content check "
        "is two names long and the baseline must not quietly carry more")
    assert S.content_findings(run_dir, doc) == []

    # NEGATIVE, and the heart of decision 21: rewriting any other file's bytes is NOT a
    # finding. Named here are the files the executed two-replay probe measured as differing on
    # UNCHANGED `main` — a clock, a per-run security salt, a per-run uuid — plus the wire log,
    # whose bytes decision 18's writer id changes on every run and which under decision 14
    # would have needed the second exemption decision 21 makes unnecessary.
    for unstable, payload in (
            ("budget.json", '{"spent_usd": 0.99}\n'),
            ("tool_trace.jsonl", '{"tool": "tampered"}\n'),
            ("session_store_pointer.json", '{"case_id": "deadbeef"}\n'),
            ("wire_logs/llm_requests.jsonl", '{"writer_id": "main"}\n'),
            ("review_record.0.json", '{"verdict": "tampered"}\n'),
            ("wire_logs/review_support_trace.jsonl", '{"role": "support"}\n')):
        path = run_dir / unstable
        if not path.is_file():
            continue
        path.write_text(payload, encoding="utf-8")
        assert S.compare_to_baseline(run_dir) == [], (
            f"{unstable}'s BYTES were compared. Two replays of unchanged code already differ "
            "there — a clock, a per-run salt or a per-run uuid — so asserting them buys no "
            "regression guarantee and buys a red test whose only repair is widening")
    # POSITIVE CONTROL: the two documents' bytes ARE compared, and each one on its own.
    for document in S.O3_CONTENT:
        path = run_dir / document
        kept = path.read_bytes()
        path.write_bytes(b"tampered\n")
        findings = S.content_findings(run_dir, doc)
        assert any(document in f for f in findings), (
            f"{document}'s bytes changed and the content check said nothing: {findings}")
        path.write_bytes(kept)
        assert S.content_findings(run_dir, doc) == [], (
            f"{document} did not read back clean after its bytes were restored — the content "
            "check is over bytes, and nothing else")


def test_a_file_present_in_one_tree_and_absent_in_the_other(tmp_path: Path):
    """An entry present in one tree and absent in the other violates O3's 'same names' directly
    and is a finding of the tree-diff observer."""
    _baseline_exists()
    run_dir = _replay(tmp_path)
    assert S.compare_to_baseline(run_dir) == []

    extra = run_dir / "an_unexpected_record.jsonl"
    extra.write_text("{}\n", encoding="utf-8")
    findings = S.compare_to_baseline(run_dir)
    assert any("an_unexpected_record.jsonl" in f for f in findings), findings
    extra.unlink()

    (run_dir / "investigation.md").unlink()
    findings = S.compare_to_baseline(run_dir)
    assert any("investigation.md" in f for f in findings), (
        f"a name in the baseline and not in the comparison is 'same names' violated: {findings}")
    # And the structural half sees it on its own — an absent name is a NAME finding, not a
    # content one, so the strict check catches a deleted record even for a file whose bytes
    # nobody compares.
    (run_dir / "tool_trace.jsonl").unlink(missing_ok=True)
    assert any("tool_trace.jsonl" in f for f in S.structural_findings(run_dir, S.load_baseline()))


def test_the_tree_comparison_covers_the_run_directory_and_nothing_above_it(tmp_path: Path):
    """The tree comparison covers the run directory and nothing above it."""
    _baseline_exists()
    run_dir = _replay(tmp_path)
    doc = S.load_baseline()
    for rel in doc["entries"]:
        outside = f"the baseline carries {rel}, which is not inside the run directory"
        assert not rel.startswith("../"), outside
        assert not Path(rel).is_absolute(), outside
    # A record BESIDE the run dir is out of the compared tree — h41 asserts it separately.
    sidecar = run_dir.parent / f"{run_dir.name}.run-end.json"
    sidecar.write_text('{"exit_class": "ok"}\n', encoding="utf-8")
    assert S.compare_to_baseline(run_dir) == [], (
        "the comparison reached above the run directory; decision 21 keeps decision 14 rule "
        "1's scope — the run directory ONLY")


def test_the_records_beside_the_run_directory_get_their_own_separate_assertion(tmp_path: Path):
    """The three sidecars and the tenant record, which live beside the run directory rather than
    inside it, are asserted by their own separate check."""
    run_dir = _replay(tmp_path)
    base = run_dir.parent
    owner = S.RunPaths(run_dir)
    beside = {name: getattr(owner, name)(base) for name in S.SIDECAR_ACCESSORS}
    beside["tenant"] = S.tenant().record_path(base)

    for name, path in beside.items():
        assert path.parent == base, f"{name} is not beside the run directory"
        assert not path.is_relative_to(run_dir), (
            f"{name} is inside the run dir, where the tree comparison would already cover it")
    # The separate check: each is named, and each is either present with its expected shape or
    # deliberately absent — never silently outside every observer.
    for name, path in beside.items():
        if path.exists():
            assert path.is_file(), f"{name} is not a regular file"
            json.loads(path.read_text(encoding="utf-8"))
    assert S.tenant().record_path(base).name == S.TENANT_RECORD_NAME


def test_the_tree_snapshot_is_taken_after_the_run_ends_so_probe_files_are_never_in_scope(
        tmp_path: Path):
    """The tree snapshot is taken after the run ends, so the sandbox probe's transient entries
    are never in its scope."""
    _baseline_exists()
    run_dir = _replay(tmp_path)
    leftovers = [p.name for p in run_dir.iterdir() if p.name.startswith(".alias-probe-")]
    assert leftovers == [], (
        f"the alias probe creates and SWEEPS up to eight `.alias-probe-<uuid4hex>-*` entries "
        f"inside the run's own lifecycle (claim C14, `box/_alias.py`), so a post-run snapshot "
        f"never observes them: {leftovers}")
    assert S.compare_to_baseline(run_dir) == [], (
        "no per-run-minted-name exclusion is needed for them, which is what makes premise s33 "
        "true and what decision 14 rule 2, kept by decision 21, buys — and it has to be the "
        "sweep that keeps them out, because the structural check has no exemption list to "
        "put them on")


def test_the_tree_contains_entries_whose_names_are_minted_per_run(tmp_path: Path):
    """The per-run random-named entries are transient, not persistent: the alias probe creates
    and sweeps its up-to-eight `.alias-probe-<uuid4hex>-*` files inside the run's own lifecycle,
    so O3's post-run tree snapshot never observes them and 'the same set of names' needs no
    per-run-minted-name exclusion for them."""
    run_dir = _replay(tmp_path)
    after = S.snapshot(run_dir)
    assert not any("alias-probe" in rel for rel in after), (
        f"a probe entry survived the run: {[r for r in after if 'alias-probe' in r]}")
    # Positive control for the channel: a per-run-minted name DOES show up if it persists.
    (run_dir / ".alias-probe-deadbeef-symlink").write_text("", encoding="utf-8")
    assert any("alias-probe" in rel for rel in S.snapshot(run_dir))
    assert S.compare_to_baseline(run_dir), (
        "the observer would report a persistent per-run-minted entry — it is the SWEEP, not an "
        "exclusion, that keeps the probe out of the comparison")


def test_directories_and_symlinks_compare_by_name_and_link_target(tmp_path: Path):
    """Directories and symlinks compare by name and link target, and the structural check
    carries no file's bytes at all."""
    _baseline_exists()
    run_dir = _replay(tmp_path)
    assert S.compare_to_baseline(run_dir) == []

    # A directory compares by NAME: its mtime and its own listing entry do not enter the check.
    d = run_dir / "gather_raw"
    assert d.is_dir()
    snap = S.snapshot(run_dir)
    assert snap["gather_raw"].kind == "dir"
    assert snap["gather_raw"].target is None

    # A regular file carries NO payload in the structural check either — decision 21's change
    # from decision 14 rule 3, which compared every regular file by bytes.
    assert snap["investigation.md"].kind == "file"
    assert snap["investigation.md"].target is None, (
        "a regular file carried a byte digest into the structural check — bytes belong to the "
        "content check, over `investigation.md` and `report.md` only")

    # A symlink compares by its LINK TARGET, never by the bytes it points at.
    target = run_dir / "investigation.md"
    link = run_dir / "linked.md"
    link.symlink_to(target)
    first = S.snapshot(run_dir)["linked.md"]
    assert first.kind == "symlink"
    assert first.target == str(target)
    target.write_text("different bytes behind the same link\n", encoding="utf-8")
    assert S.snapshot(run_dir)["linked.md"] == first, (
        "the symlink's entry changed when the bytes behind it did — a symlink compares by name "
        "and link target, and following it would compare one file twice")
    # And the entry for the file itself did not change either: it never carried bytes.
    assert S.snapshot(run_dir)["investigation.md"] == snap["investigation.md"]
    # Positive control that the bytes ARE observed, by the other check, for this one name.
    assert any("investigation.md" in f
               for f in S.content_findings(run_dir, S.load_baseline()))


def test_the_baseline_is_a_golden_compared_on_every_commit(tmp_path: Path):
    """The baseline is a golden: it records the commit it was captured on for the reader, and
    the comparison never keys on that field — a committed file cannot carry the sha of the
    commit that contains it, so a comparison that did would be red on every commit after the
    capture (or vacuous, re-captured inside CI). A tree that moved is the finding, on
    whichever commit moved it."""
    _baseline_exists()
    doc = S.load_baseline()
    assert doc.get("commit"), "the baseline does not record the commit it was captured on"
    assert set(doc) == {"commit", "entries", "content"}, (
        f"the baseline's shape is the commit, the structural name set and the two documents' "
        f"digests — decision 21 changed it from 'every file's bytes minus two exemptions': "
        f"{sorted(doc)}")

    # Driven: a baseline captured elsewhere is COMPARED, not reported as stale.
    elsewhere = tmp_path / "elsewhere-baseline.json"
    elsewhere.write_text(json.dumps({**doc, "commit": "0" * 40}), encoding="utf-8")
    run_dir = _replay(tmp_path)
    assert S.compare_to_baseline(run_dir, path=elsewhere) == S.compare_to_baseline(run_dir), (
        "the commit field changed the comparison's answer")
    # And a re-capture covers BOTH halves: the fresh document carries the name set and the two
    # digests, and compares clean against the run it was taken from.
    fresh = S.capture_baseline(run_dir, path=elsewhere)
    assert set(fresh) == {"commit", "entries", "content"}
    assert fresh["commit"] == S.head_commit()
    assert S.compare_to_baseline(run_dir, path=elsewhere) == []


# ---------------------------------------------------------------------------------------
# g04 — the writers that share one run directory
# ---------------------------------------------------------------------------------------

def test_every_run_dir_writer_stays_key_disjoint_at_the_composition_frame(tmp_path: Path):
    """Driven from the composition frame (`materialize_run_dir`/`run_main`), every writer under
    one run dir (`Run`, `_alias`, `challenge_gate`, `model_bash`, `record_query`) writes into its
    own reserved key space — lead claims by lead_id+seq (d29), review records by turn, the box's
    own `bash`/`docker-exec` writes by their fixed names — with no two writers' keys able to
    collide."""
    from defender.scripts.gather_tools import record_query
    run_dir = S.seed_run_tree(S.make_run_dir(S.make_runs_base(tmp_path)))
    owner = S.RunPaths(run_dir)

    produced: dict[str, str] = {}

    def claim(writer: str, path: Path) -> None:
        rel = str(Path(path).relative_to(run_dir))
        assert rel not in produced, (
            f"{writer} and {produced[rel]} both write {rel} — two writers' keys collided")
        produced[rel] = writer

    for lead in ("l-aaa111", "l-bbb222"):
        for seq in (0, 1):
            claim("record_query", run_dir / record_query.persist_payload(
                run_dir, lead, seq, "{}"))
        claim("Run(leads)", owner.lead_claim(lead))
    for turn in (0, 1, 2):
        claim("challenge_gate", owner.review_record(turn))
    for role in ("support", "ablation", "composer"):
        claim("challenge_gate", owner.review_trace(role))
    claim("_alias", run_dir / ".alias-probe-deadbeefdeadbeef-symlink")
    claim("box", owner.box_sentinel)
    for fixed in ("tool_trace", "executed_queries", "policy_denials", "budget",
                  "circuit_breaker", "lessons_loaded", "wire_log", "provenance"):
        claim("Run", getattr(owner, fixed))

    # No key is a PREFIX of another either: a writer whose reserved space is a directory must
    # not have a second writer's file land at that directory's own name.
    for a in produced:
        for b in produced:
            if a != b:
                assert not a.startswith(f"{b}/"), f"{a} lands inside {b}, another writer's key"


# ---------------------------------------------------------------------------------------
# h26 — the sandbox probe fails closed
# ---------------------------------------------------------------------------------------

def test_the_alias_ban_probe_fails_closed_on_a_timeout_or_a_malformed_result(tmp_path: Path):
    """The sandbox alias-ban probe fails closed — a timeout or a malformed result refuses,
    exactly as a found alias would."""
    alias = S.mod("runtime.box._alias")
    run_dir = S.seed_run_tree(S.make_run_dir(S.make_runs_base(tmp_path)))

    for mode in ("timeout", "malformed"):
        docker = S.ProbeDocker(S.ProbeFault(mode=mode))
        with pytest.raises(alias.AliasBanNotInForce) as excinfo:
            alias._probe_alias_ban(docker, "box-1077", run_dir, "runc")
        assert docker.argv, f"the {mode} arm never reached the probe"
        assert not issubclass(type(excinfo.value), S.mod("runtime.box._docker").BoxFault), (
            "O7 is a security obligation, so the refusal must not be a `BoxFault` the generic "
            "`except BoxFault: degrade` startup handler can swallow")

    # Positive control: a clean probe does NOT refuse, so the two faults above are the refusal
    # and not the probe refusing unconditionally.
    clean = S.ProbeDocker(S.ProbeFault(mode="clean"))
    alias._probe_alias_ban(clean, "box-1077", run_dir, "runc")
    assert clean.argv, "the clean arm never reached the probe either"
