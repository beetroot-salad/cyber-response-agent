"""#996 — the clerk's injection seam, and the ONE hole the graph gate called blocking.

Mechanism 5 says `run_investigation(clerk=…)` "mirrors `review_stages=`", and the two candidate
seams in this harness behave OPPOSITELY: the review bundle is ALWAYS defaulted to stages that
answer without a provider, while the store factory is left `None`. Which shape the clerk seam
takes is not a test-ergonomics question — if it took the second, every existing replay scenario
would start making live provider calls the moment `record` is registered, and there are 221 of
them.

The human took that decision at the §7 seam: MIRROR THE REVIEW BUNDLE. The harness defaults a
scripted clerk, and only a production `run_investigation` called with none builds the live
caller. Both halves are demands here, because either one alone is satisfiable by a shape that
breaks the other.

RED against `7fa49f04`: `run_investigation` does not accept the parameter, so `drive` passes it
through only when supplied — the same posture the two most recent seams took while they were
red. The default becomes unconditional in the same change that makes the entry point accept it,
and the second test below is what forces that.

PLACED TOP-LEVEL RATHER THAN UNDER `tests/e2e/`, and marked `e2e` so the marker
selection is unchanged: `check_binds` scans ONE directory non-recursively (`_suite.suite_files`
globs `*.py`), and this graph names `defender/tests` — a demand whose test sat one level down
would be reported as a dangling pointer and its prose would never be scanned. The same reason
the #836, #869, #870 and #954 graphs all record "top-level files only".
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.models import override_allow_model_requests  # noqa: E402
from pydantic_ai.models.function import FunctionModel  # noqa: E402

from defender.runtime.providers import BuiltModel  # noqa: E402
from defender.tests import _clerk_996 as C  # noqa: E402
from defender.tests import _review_bundle  # noqa: E402
from defender.tests.e2e import _replay_harness as H  # noqa: E402
from defender.tests.e2e._replay_harness import GOLDEN_AB3, Turn  # noqa: E402

pytestmark = pytest.mark.e2e


def test_996_run_investigation_accepts_a_scripted_clerk(tmp_path: Path) -> None:
    """SEAM: the driver's composition root takes a clerk as a VALUE the run is handed, and the
    run's `record` calls go through it.

    The seam is the demand, not a convenience: without a value the run is handed, a hermetic
    scenario cannot drive a single arm of the round loop, and reaching the caller any other way
    means the attribute patching this project ratchets in CI. It mirrors the review bundle's
    shape exactly — one callable, handed the rendered turn, answering with text — because the
    review stages are the seam mechanism 5 names.

    Asserted by driving it: the scripted clerk RECEIVED a turn and its answer reached the
    document. A signature that accepted the parameter and dropped it would satisfy an
    inspection and nothing else."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    clerk = C.ScriptedClerk(C.clerk_reply(C.CLEAN_ROWS))
    C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    assert clerk.calls == 1, "the injected clerk was never called"
    assert "attrs.owner" in C.document(run_dir), "the injected clerk's answer never landed"


def test_996_a_replay_that_records_with_no_injected_clerk_never_reaches_a_live_call(
    tmp_path: Path,
) -> None:
    """The harness DEFAULTS a scripted clerk, at the same layer and in the same shape as its
    review-bundle default — so a replay that records and injects nothing still compiles without
    a provider.

    This is the hole the graph gate called the one blocking the suite rather than a test. Every
    existing replay scenario writes to the investigation, and under D14 those writes become
    `record` calls; if the seam took the store factory's shape instead, every one of them would
    build a live clerk the moment the verb is registered — 221 scenarios, all hermetic today.

    `override_allow_model_requests(False)` makes any real provider call raise, so the
    observable is exactly right: the run completes, MAIN gets a receipt, and nothing raised.
    A default that is merely *declared* but passed through only when supplied cannot satisfy
    this — which is the point."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir)

    assert main.receipts, (
        "a replay that records with no injected clerk got no receipt — either the verb is "
        "absent, or the run tried to reach a provider and the hermetic guard raised"
    )
    assert not main.retries, main.retries


def test_996_a_production_run_with_no_clerk_builds_the_live_caller(tmp_path: Path) -> None:
    """A PRODUCTION `run_investigation` called with no clerk builds the live caller, and builds
    it through the run's own model seam.

    The other half of the same decision, and it is what keeps the harness default from becoming
    the production default: a driver that fell back to a scripted clerk would ship a runtime
    whose `record` compiles nothing. The observable is the model seam being asked for the
    clerk's own model at the clerk's own effort — the caller is built at the composition root,
    which is the only frame holding the run dir, the operator's model choice and the run's
    logger at once.

    The discriminator is the complementary condition: with a clerk supplied, the seam is NOT
    asked for the clerk's model at all."""
    driver = C.mod("runtime.driver")
    stages = _review_bundle.bundle(composer=_review_bundle.composer_reply("holds"))

    def _run(run_dir: Path, **seams):
        asked: list[tuple] = []
        built = BuiltModel(
            FunctionModel(C.MainWithReceipts([C.record_turn(C.PROSE), Turn(text="done")])), None)

        def make_model(name, effort):
            asked.append((name, effort))
            return built

        with override_allow_model_requests(False):
            asyncio.run(driver.run_investigation(
                alert_path=run_dir / "alert.json", run_dir=run_dir, run_id=C.RUN_ID,
                defender_dir=C.DEFENDER, make_model=make_model, review_stages=stages, **seams,
            ))
        return asked

    live_dir = C.new_run_dir(tmp_path, name="live")
    C.seed(live_dir, C.PROLOGUE)
    live = _run(live_dir)
    assert any(C.DEFAULT_CLERK_MODEL in str(name) for name, _ in live), (
        f"a production run with no clerk never built one through the run's model seam: {live}"
    )

    scripted_dir = C.new_run_dir(tmp_path, name="scripted")
    C.seed(scripted_dir, C.PROLOGUE)
    scripted = _run(scripted_dir, clerk=C.ScriptedClerk(C.clerk_reply("")))
    assert not any(C.DEFAULT_CLERK_MODEL in str(name) for name, _ in scripted), (
        f"an injected clerk still built the live one beside it: {scripted}"
    )


def test_996_the_harness_treats_record_as_the_pathless_investigation_write(
    tmp_path: Path,
) -> None:
    """The harness's pathless-write name table becomes `record`, and the golden re-split
    produces `record` turns.

    The name IS the whole predicate here: `record` carries no path, like the two verbs it
    replaces, so a table that still names only those two makes every recorded investigation
    write in a golden invisible to the re-split — and the replay then drives a golden with no
    document writes at all while asserting byte-identity against a document that has them.

    Driven through the real re-split over the real golden rather than asserted on the table, so
    a table edited without the re-split following it is still red."""
    turns = H.load_turns_from_trace(
        GOLDEN_AB3 / "tool_trace.jsonl",
        old_run_dir=H.AB3_ORIG_RUN_DIR, new_run_dir=str(tmp_path / "run"),
        as_appends=True,
    )
    names = [name for turn in turns for name, _ in turn.tool_calls]
    assert "record" in names, (
        "the golden's investigation writes were not re-expressed as `record` calls — the "
        f"pathless-write table still names only the retired verbs: {sorted(set(names))}"
    )
    assert "append_block" not in names, (
        "the re-split still produces `append_block` turns, which MAIN can no longer call"
    )
