"""#1025 — the episode page's entry-point contract: `render_episode`, the CLI, the launcher hook,
the guarded write, and location independence.

The spec's demand #0 (§7 Q1): `render_episode(episode_dir) -> Path` in
`scripts/visualize/visualize_episode.py` writes the WHOLE page through `write_guarded`'s replace
lane at `<episode_dir>/learning.html`; `main(argv)` exits 0 with the path on stdout, 1 with one
stderr line and no page when there is no argument, the argument is not a directory, or the
directory holds no readable `family.yaml`; the launcher (`cli._run_episode`, through
`_render_page`) calls it after the `clock.step(Step.JUDGE)` frame closes, under its own
`except Exception` boundary (Q2 / J1) — a graded episode always gets its page, and the exit
before any sibling starts (an outcome other than `accepted`) renders nothing.

Every fault here is a real input through the real primitive: a symlink at the page's name, a
read-only directory, a manifest that is a directory / empty / a list / unparseable, an interrupt
landing INSIDE the render (a signal handler that fires only when the page module's frame is on
the stack — `E.when_inside` — because the renderer has no seam of its own, d40). The launcher is
driven through `test_1025_stage_timing._launch` with every seam faked (`FakeSibling`,
`FakeJudge`, the question-writer and pre-flight's oracle/verifier doubles) and `DEFENDER_EPISODES_BASE` / `DEFENDER_RUNS_BASE` / the
learning state root under `tmp_path`.

RED AGAINST HEAD by construction: the page module does not exist, and every test imports it per
call through `E.mod` so the failure is the missing module, once per test.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import pathlib
from pathlib import Path

import pytest

from defender import _episode_handle as EH
from defender.tests import _episode_1025 as E
from defender.tests import _judge_921 as J
from defender.tests import _triplet_947 as T
from defender.tests import test_1025_stage_timing as ST
from defender.tests import _state1135

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")

NOT_ROOT = pytest.mark.skipif(
    os.geteuid() == 0, reason="root ignores permission bits — CI runs non-root (defender/CLAUDE.md)")


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    """Every configured root inside `tmp_path` — the launcher's episodes root, the runs base and
    the learning state root the judge's enqueue appends to."""
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")


def visualize_episode():
    """The target module, `defender.scripts.visualize.visualize_episode`, imported at call time
    (it does not exist at the spec's base — one failure per test, never a collection error)."""
    return E.page_module()


def render(ep) -> E.Page:
    """`visualize_episode().render_episode(runs, <episode id>)` — the real entry point — then
    the page it wrote, parsed."""
    return E.render(ep, module=visualize_episode())


def cli(argv, capsys, *, episodes_base=None):
    """`visualize_episode().main(argv)` with its stdout / stderr captured, under the episodes
    base `episodes_base` when given."""
    return E.cli(argv, capsys, module=visualize_episode(), episodes_base=episodes_base)


def cli_on(episode_dir, capsys):
    """`visualize_episode().main(["--tenant", T, <episode id>])` for the episode at
    `episode_dir`, under the episodes base holding it (#1105 PR 2, declared change 4: the CLI
    names the episode by id, no longer by folder path)."""
    return E.cli_on(episode_dir, capsys, module=visualize_episode())


def hook_page(episode_dir) -> E.Page:
    """The page the launcher's hook wrote, parsed — after checking it is byte-identical to a
    standalone `visualize_episode().render_episode` over the same directory: the hook is a
    plain call to the same function (d40) and the page is a pure function of the directory."""
    page = pathlib.Path(episode_dir) / E.PAGE_NAME
    assert page.is_file(), f"the launcher did not write {E.PAGE_NAME}"
    written = page.read_bytes()
    render(episode_dir)
    assert page.read_bytes() == written, "the hook's page differs from a standalone render"
    return E.Page.parse(written.decode("utf-8"))


def _cli():
    return E.mod("learning.branch.cli")


def _err_lines(err: str) -> list[str]:
    return [line for line in err.splitlines() if line.strip()]


# ---------------------------------------------------------------------------------------
# d00 / d01 / d04 / d36 — the function, the CLI, the write
# ---------------------------------------------------------------------------------------


def test_1025_render_episode_writes_learning_html_beside_judge_yaml_and_returns_its_path(tmp_path):
    """Driving `render_episode` on a sample-shaped episode returns `<dir>/learning.html`; that
    file exists beside `judge.yaml`, is the page (carries `<title>` with the episode id and
    `id="sec-verdict"`), and a second call replaces it whole — mtime advances, content equal —
    whichever of the two serial drivers (the launcher hook, the standalone CLI) made the call.
    """
    ep = E.sample_episode(tmp_path)
    out = E.render_episode(ep.dir, module=visualize_episode())
    assert Path(out) == ep.page, f"render_episode returned {out!r}, not the page's path"
    assert ep.page.is_file()
    assert (ep.dir / "judge.yaml").is_file()
    first = ep.page.read_bytes()
    page = E.Page.parse(first.decode("utf-8"))
    titles = page.elements("title")
    assert titles, "the <title> does not carry the episode id"
    assert E.EPISODE_ID in titles[0].text(), "the <title> does not carry the episode id"
    assert "sec-verdict" in page.by_id
    before = ep.page.stat().st_mtime_ns
    os.utime(ep.page, ns=(before - 2_000_000_000, before - 2_000_000_000))
    again = E.render_episode(ep.dir, module=visualize_episode())
    assert Path(again) == ep.page
    assert ep.page.stat().st_mtime_ns > before - 2_000_000_000, "the second call did not replace"
    assert ep.page.read_bytes() == first, "a re-render of the same records changed the bytes"


def test_1025_visualize_episode_cli_exits_zero_on_an_episode_dir_and_one_with_no_page_otherwise(
        tmp_path, capsys):
    """`main(["--tenant", T, <id>])` returns 0 and prints the page path; `main([])`, an id
    naming a file, an id naming a dir with no family.yaml return 1, print one reason line to
    stderr, and leave no `learning.html`. Rejected: an index over all episodes (issue fork 1) —
    a second argument is refused the same way. (#1105 PR 2, declared change 4: the episode is
    named by id under the episodes base, no longer by folder path.)
    """
    ep = E.sample_episode(tmp_path)
    rc, out, err = cli_on(ep.dir, capsys)
    assert rc == 0, (rc, out, err)
    assert str(ep.page) in out, (rc, out, err)
    assert ep.page.is_file()

    base = ep.dir.parent
    a_file = base / "just-a-file"
    a_file.write_text("x", encoding="utf-8")
    bare = base / "no-manifest"
    bare.mkdir()
    ep.page.unlink()
    for argv in ([], E.cli_argv(a_file), E.cli_argv(bare), [*E.cli_argv(ep.dir), bare.name]):
        rc, out, err = cli(argv, capsys, episodes_base=base)
        assert rc == 1, f"main({argv}) returned {rc}: out={out!r} err={err!r}"
        assert len(_err_lines(err)) == 1, f"main({argv}) wrote {err!r} to stderr, not one line"
        assert not (bare / E.PAGE_NAME).exists()
        assert not (base / E.PAGE_NAME).exists()
        assert not ep.page.exists(), f"main({argv}) wrote the page"


def test_1025_a_link_planted_at_learning_html_is_refused_not_written_through(tmp_path):
    """`render_episode` on an episode whose `learning.html` is a symlink to an outside file
    refuses — it raises the guarded write's `OSError` (p1: errno ELOOP, `.write_guarded_alias`
    True) — the target file's bytes are unchanged, the link is still a link and no regular
    `learning.html` replaced it; positive control: without the link the page is written.
    """
    ep = E.sample_episode(tmp_path)
    outside = tmp_path / "outside.html"
    outside.write_text("OUTSIDE", encoding="utf-8")
    E.plant_link(ep.page, outside)
    with pytest.raises(OSError, match="non-plain or aliased") as refused:
        E.render_episode(ep.dir, module=visualize_episode())
    assert getattr(refused.value, "write_guarded_alias", None) is True, refused.value
    assert ep.page.is_symlink(), "the planted link was replaced"
    assert outside.read_text(encoding="utf-8") == "OUTSIDE", "the page was written THROUGH the link"
    ep.page.unlink()
    render(ep)
    assert ep.page.is_file()
    assert not ep.page.is_symlink()


def test_1025_a_render_creates_or_changes_exactly_one_file_learning_html_and_touches_no_run_visualizations_mirror(
        tmp_path, run_visualizations_dir):
    """A tree snapshot (paths + sizes + mtimes) of the episode before and after `render_episode`
    differs in exactly `learning.html`, and `<mirror root>/<episode>/` is not created.
    Rejected: the mirror into `run-visualizations/` the run pages do. Positive control: the one
    changed file parses as the page (it carries `sec-verdict`).

    The mirror root is where the run pages' mirror resolves under test: the per-test override
    the conftest sets (#1084 D4 — `test_1084_mirror` pins that `mirror_root()` answers with
    it). The old `defender/run-visualizations/` is no longer written by anything.
    """
    ep = E.sample_episode(tmp_path)
    mirror = run_visualizations_dir / E.EPISODE_ID
    assert not mirror.exists(), "precondition: a stale mirror from another run"
    # #1105 PR 2 (declared change 4): the container carries the record the launcher leaves.
    E.plant_container_record(ep.dir)
    before = E.snapshot(ep.dir)
    page = render(ep)
    after = E.snapshot(ep.dir)
    changed = {k for k in set(before) | set(after) if before.get(k) != after.get(k)}
    assert changed == {E.PAGE_NAME}, f"the render touched {sorted(changed)}"
    assert not mirror.exists(), "the page was mirrored into run-visualizations/"
    assert "sec-verdict" in page.by_id, "positive control: the one changed file is the page"


# ---------------------------------------------------------------------------------------
# d02 / d03 / J1 / J2 — the launcher hook
# ---------------------------------------------------------------------------------------


def test_1025_the_launcher_renders_the_page_after_the_judge_frame_with_every_step_on_it(tmp_path):
    """After `cli.main` returns 0 on a full fake-seamed episode, `learning.html` sits beside
    `judge.yaml` and its stage table carries every `Step` row on the record — none reads
    "not on the record", the `judge` row included — which is only possible if the render ran
    after the JUDGE clock frame closed.
    """
    launch = ST._launch(tmp_path)
    assert launch.rc == 0
    ep = launch.episode_dir
    assert (ep / "judge.yaml").is_file(), "the control failed: the grade did not land"
    page = hook_page(ep)
    timing = page.text_of("stage-timing")
    for step in ST.EXPECTED_STEPS:
        assert step in timing, f"no row for {step}"
    assert "not on the record" not in timing, timing


class _PlantingJudge(J.FakeJudge):
    """`FakeJudge` that plants a real symlink at the page's name the first time the judge seam
    is reached — the episode dir does not exist before the launch (`prepare_episode` refuses an
    existing one), so the plant happens from inside the one seam that runs after it does. The
    fault itself is the guarded write meeting the link (p1); the fake decides nothing."""

    def __init__(self, episode_dir: Path, target: Path, **kw):
        super().__init__(**kw)
        self.episode_dir, self.target = Path(episode_dir), Path(target)

    def __call__(self, prompt, **kw):
        page = self.episode_dir / E.PAGE_NAME
        if not page.is_symlink():
            E.plant_link(page, self.target)
        return super().__call__(prompt, **kw)


def test_1025_a_render_fault_is_printed_and_changes_neither_the_exit_status_nor_judge_yaml(
        tmp_path, monkeypatch, capsys):
    """With a symlink planted at `<episode_dir>/learning.html` before the render, `cli.main`
    still returns 0, `judge.yaml` is written, stderr carries a "could not be rendered" line and
    the link's target is untouched; the control launch without the link writes the page.
    """
    outside = tmp_path / "outside.html"
    outside.write_text("OUTSIDE", encoding="utf-8")
    episode_dir = EH.episode_dir(ST._tenant_paths().data_root, T.EPISODE_ID)
    judge = _PlantingJudge(episode_dir, outside, default=J.as_reply_text(J.reply_doc()))
    launch = ST._launch(tmp_path, judge=judge)
    err = capsys.readouterr().err
    assert launch.rc == 0, "a render fault changed the launch's exit status"
    assert (launch.episode_dir / "judge.yaml").is_file()
    assert "could not be rendered" in err, err
    assert outside.read_text(encoding="utf-8") == "OUTSIDE"
    assert (launch.episode_dir / E.PAGE_NAME).is_symlink()

    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-control"))
    control = ST._launch(tmp_path)
    assert control.rc == 0
    assert hook_page(control.episode_dir).by_id, "the control launch did not write a real page"


def test_1025_preflight_refused_episode_and_the_page(tmp_path, capsys):
    """The pre-flight-refused path returns 1 before RUNS with no `judge.yaml` and no `runs/`,
    and the launcher writes no `learning.html` there — there is no second hook on that exit
    (J1). The standalone CLI still accepts that directory (only `family.yaml` refuses, d01):
    exit 0, the band says there is no grade record, the records section carries the outcome
    record's `refused` word, the stage table carries the two recorded steps' rows and "not on
    the record" for the other three, and no world section exists.
    """
    launch = ST._launch(tmp_path, **ST._refusing_seams())
    assert launch.rc == 1, "the control failed: pre-flight did not refuse"
    ep = launch.episode_dir
    assert not (ep / "judge.yaml").exists()
    assert not (ep / "runs").exists()
    assert not (ep / E.PAGE_NAME).exists(), "the launcher rendered on the refused exit"

    rc, out, err = cli_on(ep, capsys)
    assert rc == 0, (out, err)
    page = E.read_page(ep)
    assert "no grade record" in page.text_of("sec-verdict")
    assert "outcome: refused" in page.text_of("sec-records"), page.text_of("sec-records")
    timing = page.text_of("stage-timing")
    assert timing.count("not on the record") == len(ST.EXPECTED_STEPS) - 2, timing
    for step in ("questioner", "preflight"):
        assert step in timing
    assert page.ids_with("world-") == [], page.ids_with("world-")


# ---------------------------------------------------------------------------------------
# settled — the CLI's refusals and argument spellings
# ---------------------------------------------------------------------------------------


def test_1025_cli_invoked_with_no_positional_argument(tmp_path, capsys):
    """`main([])` returns 1, prints one reason line to stderr, writes no page (d01)."""
    ep = E.sample_episode(tmp_path)
    rc, out, err = cli([], capsys)
    assert rc == 1, (rc, out, err)
    assert len(_err_lines(err)) == 1, (rc, out, err)
    assert not ep.page.exists()
    assert not list(tmp_path.glob("*.html"))


def _refused_manifest(tmp_path, capsys, plant) -> tuple[int, str, str, E.Episode]:
    ep = E.sample_episode(tmp_path)
    plant(ep.dir / "family.yaml")
    rc, out, err = cli_on(ep.dir, capsys)
    assert not ep.page.exists(), "a page was written from an unreadable manifest"
    return rc, out, err, ep


def test_1025_family_yaml_has_invalid_yaml_syntax(tmp_path, capsys):
    """No page, exit 1, one reason line on stderr naming the manifest as unreadable — not
    "missing" — `raw_manifest`'s refusal (F25/x16) takes d01's refusal arm with a
    distinguishing reason.
    """
    rc, _out, err, _ep = _refused_manifest(
        tmp_path, capsys, lambda p: E.plant_raw(p, "worlds: [\n  {world_id: b"))
    lines = _err_lines(err)
    assert rc == 1, (rc, err)
    assert len(lines) == 1, (rc, err)
    assert "family.yaml" in lines[0], lines[0]
    assert "could not be read" in lines[0], lines[0]
    assert "nothing is at that name" not in lines[0], lines[0]
    assert "missing" not in lines[0], lines[0]


# ---------------------------------------------------------------------------------------
# d05 / J3 / J4 — location and process independence; concurrency
# ---------------------------------------------------------------------------------------


def _live996_shaped(tmp_path: Path, root: Path) -> E.Episode:
    """The second archive's shape: no family draw, no `samples.yaml`, a grade with an
    ungradable row, no family row (the family call never ran) and no questioner counts."""
    ep = E.sample_episode(tmp_path, root=root, family_draw=False, samples=False, judge=False)
    doc = E.sample_grade(family=False)
    doc["worlds"] = [E.ungradable_row(E.PASSTHROUGH_WORLD, declared="benign"),
                     E.world_row(E.GRADED_WORLD, declared="malicious")]
    E.drop_lanes(doc, E.PASSTHROUGH_WORLD)
    for key in ("world_enqueued_rows", "world_enqueued_to"):
        del doc[key]
    E.write_judge(ep.dir, doc)
    return ep


def test_1025_episode_dir_given_through_a_symlink(tmp_path, capsys):
    """`episodes/latest -> <id>` as the CLI argument is accepted (J4): exit 0, the page written
    inside the TARGET beside `judge.yaml`, and every world link composed from names
    (`runs/<episode>-<world>/runtime.html`) — identical whether computed against the link or
    its target. (#1105 PR 2, declared change 4: `latest` is named as an id under the episodes
    base that holds the link.)
    """
    ep = E.sample_episode(tmp_path)
    latest = ep.dir.parent / "latest"
    latest.symlink_to(ep.dir, target_is_directory=True)
    E.plant_container_record(ep.dir)
    rc, out, err = cli(E.cli_argv(latest), capsys, episodes_base=ep.dir.parent)
    assert rc == 0, (out, err)
    assert ep.page.is_file()
    assert not ep.page.is_symlink()
    page = E.read_page(ep.dir)
    for label in E.WORLDS:
        assert f"runs/{E.EPISODE_ID}-{label}/runtime.html" in page.hrefs, page.hrefs
    assert "latest" not in page.raw


# ---------------------------------------------------------------------------------------
# settled — the launch's partial states, the interrupt, the write discipline
# ---------------------------------------------------------------------------------------


def test_1025_questioner_or_preflight_abort_leaves_a_partial_directory(tmp_path, monkeypatch, capsys):
    """The launcher writes no page on an abort (the hook is after JUDGE). The standalone CLI
    renders when `family.yaml` exists — a pre-flight abort (its oracle interrupted mid-replay):
    no-grade band, a stage row per `STEPS` member with a wall for the recorded step
    (`questioner`) and "not on the record" for the other four, no world sections (no `runs/`),
    the outcome record's "no record" state (pre-flight never wrote it), "absent" for the family
    stamp nothing wrote, and the samples the questioner step recorded. When the abort preceded `write_family` (the questioner interrupted)
    there is no `family.yaml` and d01's exit-1 / no-page arm applies.
    """
    launcher = _cli()
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-preflight"))
    oracle_seam = ST._Interrupting(EH.episode_dir(ST._tenant_paths().data_root, T.EPISODE_ID))
    ep, _b, _a = ST._abort(tmp_path, launcher.LauncherRefused,
                           oracle=ST.S.oracle(then=ST.S.Move(None, raises=oracle_seam)))
    assert oracle_seam.calls > 0, "the control failed: pre-flight's oracle was never reached"
    assert not (ep / E.PAGE_NAME).exists(), "the launcher rendered on an abort"
    assert (ep / "family.yaml").is_file()
    assert not (ep / "outcome.yaml").exists()
    assert not (ep / "runs").exists()
    rc, out, err = cli_on(ep, capsys)
    assert rc == 0, (out, err)
    page = E.read_page(ep)
    assert "no grade record" in page.text_of("sec-verdict")
    timing = page.text_of("stage-timing")
    assert timing.count("not on the record") == len(ST.EXPECTED_STEPS) - 1, timing
    assert page.ids_with("world-") == []
    records = page.text_of("sec-records")
    assert "no record: outcome.yaml is absent" in records, records
    # the outcome's and the family stamp's (written only by `verify`); the samples record is
    # the questioner step's own, so it is present
    assert records.count("absent") == 2, records
    assert page.elements(cls="rc-sample-system"), records

    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-questioner"))
    questioner = ST._Interrupting(EH.episode_dir(ST._tenant_paths().data_root, T.EPISODE_ID))
    ep2, _b, _a = ST._abort(tmp_path, launcher.LauncherRefused, questioner=questioner)
    assert not (ep2 / "family.yaml").exists(), "the control failed: the manifest was written"
    # The abort above still primes the capture before the interrupt lands (priming precedes the
    # questioner in the launcher's own order) and that print is real launcher stderr, not the
    # standalone CLI's — drained here so the assertion below is about the CLI's OWN report,
    # not noise the launcher run left sitting in the shared capsys buffer.
    capsys.readouterr()
    rc, out, err = cli_on(ep2, capsys)
    assert rc == 1, (out, err)
    assert len(_err_lines(err)) == 1, (out, err)
    assert not (ep2 / E.PAGE_NAME).exists(), (out, err)


def test_1025_an_interrupt_during_the_render(tmp_path):
    """`learning.html` after an interrupt that lands INSIDE the render is either the previous
    page whole or absent — never a partial page — and NO staged temporary is left in the
    episode dir (p1: `write_guarded`'s `except BaseException` removes it and re-raises). The
    launch exits by the interrupt: `KeyboardInterrupt` passes the hook's `except Exception`
    boundary and `cli.main` raises it, distinct from a clean completion; `judge.yaml` — written
    before the render — is on disk.
    """
    ep = E.sample_episode(tmp_path)
    render(ep)
    previous = ep.page.read_bytes()
    listing = sorted(p.name for p in ep.dir.iterdir())
    with pytest.raises(KeyboardInterrupt), \
            E.when_inside(E.raise_now(KeyboardInterrupt("mid-render"))) as seen:
        E.render_episode(ep.dir, module=visualize_episode())
    assert seen["hit"], "the interrupt never landed inside the render"
    assert ep.page.read_bytes() == previous, "a partial page replaced the previous one"
    assert sorted(p.name for p in ep.dir.iterdir()) == listing, "a staged temporary was left"

    with pytest.raises(KeyboardInterrupt), \
            E.when_inside(E.raise_now(KeyboardInterrupt("mid-render"))) as seen:
        ST._launch(tmp_path)
    assert seen["hit"], "the interrupt never landed inside the launcher's render"
    launched = EH.episode_dir(ST._tenant_paths().data_root, T.EPISODE_ID)
    assert (launched / "judge.yaml").is_file(), "the grade was not on disk before the render"
    assert not (launched / E.PAGE_NAME).exists(), "a partial page was left by the interrupt"
    assert not [p for p in launched.iterdir() if p.name.startswith(".")], "a staged temp is left"


def test_1025_a_refused_write_leaves_no_residue(tmp_path):
    """A refused replace (an alias at `learning.html`) leaves no staged temporary in the episode
    dir: `write_guarded` refuses on the lstat screen before it stages (p1: zero `os.open`
    calls), so the directory listing is unchanged and the planted entry left in place; positive
    control: without the alias the page is written.
    """
    ep = E.sample_episode(tmp_path)
    E.plant_link(ep.page, tmp_path / "nowhere")
    listing = sorted(p.name for p in ep.dir.iterdir())
    with pytest.raises(OSError, match="non-plain or aliased"):
        E.render_episode(ep.dir, module=visualize_episode())
    assert sorted(p.name for p in ep.dir.iterdir()) == listing, "a staged temporary was left"
    assert ep.page.is_symlink()
    ep.page.unlink()
    render(ep)
    assert ep.page.is_file()


def test_1025_a_render_that_raises_midway_keeps_the_previous_page(tmp_path):
    """The whole document is built before the single guarded replace, so a raise mid-build
    (an `Exception` injected inside the page module's frame) propagates out of `render_episode`
    and leaves the previous `learning.html` intact — or none, when there was none — with no
    staged temporary; a partial page is never observable at that path.
    """
    ep = E.sample_episode(tmp_path)
    listing = sorted(p.name for p in ep.dir.iterdir())
    with pytest.raises(RuntimeError, match="mid-build"), \
            E.when_inside(E.raise_now(RuntimeError("mid-build"))) as seen:
        E.render_episode(ep.dir, module=visualize_episode())
    assert seen["hit"]
    assert not ep.page.exists(), "a partial page was written"
    assert sorted(p.name for p in ep.dir.iterdir()) == listing

    render(ep)
    previous = ep.page.read_bytes()
    with pytest.raises(RuntimeError, match="mid-build"), \
            E.when_inside(E.raise_now(RuntimeError("mid-build"))) as seen:
        E.render_episode(ep.dir, module=visualize_episode())
    assert seen["hit"]
    assert ep.page.read_bytes() == previous


@NOT_ROOT
def test_1025_a_read_only_episode_directory(tmp_path, capsys):
    """The CLI exits 1 with the write failure on stderr and no page when the episode dir is
    read-only; the launcher path prints the failure under the render boundary and its exit
    status is unchanged (d03) — the directory made read-only from inside the judge seam, the
    one seam that runs after the launcher creates it.
    """
    ep = E.sample_episode(tmp_path)
    ep.dir.chmod(0o555)
    try:
        rc, out, err = cli_on(ep.dir, capsys)
    finally:
        ep.dir.chmod(0o755)
    assert rc == 1, (rc, out, err)
    assert _err_lines(err), (rc, out, err)
    assert not ep.page.exists(), (rc, out, err)

    class _ReadOnlyJudge(J.FakeJudge):
        def __init__(self, episode_dir, **kw):
            super().__init__(**kw)
            self.episode_dir = Path(episode_dir)

        def __call__(self, prompt, **kw):
            reply = super().__call__(prompt, **kw)
            self.episode_dir.chmod(0o555)
            return reply

    launched = EH.episode_dir(ST._tenant_paths().data_root, T.EPISODE_ID)
    judge = _ReadOnlyJudge(launched, default=J.as_reply_text(J.reply_doc()))
    try:
        launch = ST._launch(tmp_path, judge=judge)
        err = capsys.readouterr().err
    finally:
        launched.chmod(0o755)
    assert launch.rc == 0, "a refused page write changed the exit status"
    assert "could not be rendered" in err, err
    assert not (launched / E.PAGE_NAME).exists()


# ---------------------------------------------------------------------------------------
# The review of PR #1042 — the page's own stylesheet, the standalone script, and location
# independence for an UNHEALTHY episode
# ---------------------------------------------------------------------------------------


def _css_classes(css: str) -> set[str]:
    """Every `.name` a stylesheet's selectors mention."""
    return set(re.findall(r"\.([A-Za-z_][\w-]*)", re.sub(r"\{[^}]*\}", "", css)))


def _page_classes(page: E.Page) -> set[str]:
    out: set[str] = set()
    for node in page.root.descendants():
        out |= node.classes
    return out


def test_1025_the_standalone_script_runs_with_no_pythonpath_from_any_cwd(tmp_path):
    """The docstring's promise — `python defender/scripts/visualize/visualize_episode.py <dir>`
    — with `PYTHONPATH` unset and the cwd elsewhere: the script puts its own package on the
    path (the bootstrap `visualize_run.py` carries), writes the page and exits 0.

    It is also the suite's one real-subprocess run, so it is what sees the `if __name__ ==
    "__main__"` line pass the process's own `sys.argv[1:]` to `main`: every other CLI test here
    calls `main(argv)` in-process, and a hardcoded `main([])` left behind by a smoke-test paste
    would exit 1 here as if no argument were given (spec adversary finding 3, PR #1042)."""
    ep = E.sample_episode(tmp_path)
    script = Path(visualize_episode().__file__)
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    # #1105 PR 2 (declared change 4): `--tenant T <episode id>` under the episodes base.
    env[T.EPISODES_BASE_ENV] = str(ep.dir.parent)
    E.plant_container_record(ep.dir)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    proc = subprocess.run([sys.executable, str(script), *E.cli_argv(ep.dir)], env=env,
                          capture_output=True, text=True, cwd=str(elsewhere))
    assert proc.returncode == 0, proc.stderr
    assert "ModuleNotFoundError" not in proc.stderr, proc.stderr
    assert proc.stdout.strip() == str(ep.page), proc.stdout
    assert E.read_page(ep).text_of("sec-case")


def _unhealthy(ep: E.Episode) -> None:
    """Every refusal sentence the page can render, planted at once: undecodable bytes at the
    episode-root records, a link at a world's report, a torn document at another's
    investigation, the served ledger gone for a third, a bad timing document."""
    for name in ("outcome.yaml", "samples.yaml", "provenance.json"):
        E.plant_raw(ep.dir / name, b"\xff\xfe\x00 not text")
    E.plant_raw(ep.dir / "timing.json", b"[not the record")
    E.plant_link(ep.world(E.GRADED_WORLD) / "report.md", ep.dir / "family.yaml")
    E.plant_raw(ep.world(E.PASSTHROUGH_WORLD) / "investigation.md", b"\xff\xfe\x00 not text")
    (ep.dir / "served" / f"{T.world_token(E.CONTROL)}.jsonl").unlink()
    E.plant_link(ep.dir / "served" / f"{T.world_token(E.GRADED_WORLD)}.jsonl",
                 ep.dir / "family.yaml")


def test_1025_an_unhealthy_episode_renders_no_absolute_path_and_byte_identically_from_two_roots(
        tmp_path, monkeypatch):
    """d05/x24 for the shape it never held on: every reader's refusal sentence embeds the
    absolute path (`read_guarded`'s alias sentence, an errno's `'/abs/…'`, `<name> at <path>`),
    so a page with one refused slot named the operator's root and two copies of one unhealthy
    archive rendered byte-different. The loader takes the episode directory's spelling out of
    every refusal at ONE boundary; each refusal is still on the page, in its own slot."""
    for var in (T.RUNS_BASE_ENV, T.EPISODES_BASE_ENV):
        monkeypatch.delenv(var, raising=False)
    built = E.sample_episode(tmp_path, root=tmp_path / "build")
    _unhealthy(built)
    one = E.copy_episode(built, tmp_path / "root-one" / "copy-one")
    two = E.copy_episode(built, tmp_path / "root-two" / "nested" / "renamed-two")
    page = render(one)
    render(two)
    text = one.page.read_text(encoding="utf-8")
    for absent in (str(tmp_path), "root-one", "copy-one", "renamed-two"):
        assert absent not in text, f"{absent!r} leaked into the page"
    assert one.page.read_bytes() == two.page.read_bytes(), "the two copies rendered differently"
    # positive control: every refusal is still said, in its slot
    records = page.text_of("sec-records")
    for slot in ("no record: outcome.yaml is refused", "samples record unreadable",
                 "provenance record unreadable"):
        assert slot in records, records
    assert "timing record unreadable" in page.text_of("sec-stages")
    assert "could not be read" in page.section(f"world-{E.GRADED_WORLD}").find_all(
        cls="w-report")[0].text()
    assert "investigation record unavailable" in page.text_of(f"leads-{E.PASSTHROUGH_WORLD}")
    assert "served ledger: absent" in page.text_of(f"leads-{E.CONTROL}")
    assert "served ledger unreadable" in page.text_of(f"leads-{E.GRADED_WORLD}")


@NOT_ROOT
def test_1025_a_link_into_an_unreadable_directory_at_a_records_name_is_that_slots_refusal(tmp_path):
    """`Path.exists()` follows a link and, on 3.11, re-raises a permission fault from the
    directory above — which is why `_io.entry_present` exists. The readers this page borrows
    (`read_outcome`, `read_family_stamp`, `read_stage_timings`, the YAML screens) must not ask
    `exists() or is_symlink()`, or a link planted at a record's name into a mode-000 directory
    escapes as a bare `PermissionError` past the page's per-record boundary and takes the whole
    render down. Each is its own slot's refusal, and the page renders."""
    ep = E.sample_episode(tmp_path, timing=True)
    vault = tmp_path / "vault"
    vault.mkdir()
    for name in ("outcome.yaml", "provenance.json", "timing.json", "samples.yaml"):
        (ep.dir / name).unlink()
        (vault / name).write_text("planted", encoding="utf-8")
        E.plant_link(ep.dir / name, vault / name)
    vault.chmod(0)
    try:
        page = render(ep)
    finally:
        vault.chmod(0o700)
    records = page.text_of("sec-records")
    for slot in ("no record: outcome.yaml is refused", "provenance record unreadable",
                 "samples record unreadable"):
        assert slot in records, records
    assert "timing record unreadable" in page.text_of("sec-stages")
    assert str(tmp_path) not in page.raw
