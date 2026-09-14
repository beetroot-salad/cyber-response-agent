"""#1025 — the episode page's entry-point contract: `render_episode`, the CLI, the launcher hook,
the guarded write, and location independence.

The spec's demand #0 (§7 Q1): `render_episode(episode_dir) -> Path` in
`scripts/visualize/visualize_episode.py` writes the WHOLE page through `write_guarded`'s replace
lane at `<episode_dir>/learning.html`; `main(argv)` exits 0 with the path on stdout, 1 with one
stderr line and no page when there is no argument, the argument is not a directory, or the
directory holds no readable `family.yaml`; the launcher (`cli._run_episode`) calls it INSIDE
`_cluster_released`'s body after the `clock.step(Step.JUDGE)` frame closes, under its own
`except Exception` boundary (Q2 / J1) — a graded episode always gets its page, a held teardown
fault is still raised afterwards unchanged, the review-rejected exit renders nothing.

Every fault here is a real input through the real primitive: a symlink at the page's name, a
read-only directory, a manifest that is a directory / empty / a list / unparseable, an interrupt
landing INSIDE the render (a signal handler that fires only when the page module's frame is on
the stack — `E.when_inside` — because the renderer has no seam of its own, d40). The launcher is
driven through `test_1025_stage_timing._launch` with every seam faked (`FakeSibling`,
`FakeJudge`, `FakeDoor`, `FakeAgent`) and `DEFENDER_EPISODES_BASE` / `DEFENDER_RUNS_BASE` / the
learning state root under `tmp_path`.

RED AGAINST HEAD by construction: the page module does not exist, and every test imports it per
call through `E.mod` so the failure is the missing module, once per test.
"""
from __future__ import annotations

import os
import subprocess
import sys
import threading
from datetime import date
import pathlib
from pathlib import Path

import pytest

from defender.tests import _episode_1025 as E
from defender.tests import _judge_921 as J
from defender.tests import _triplet_947 as T
from defender.tests import test_1025_stage_timing as ST

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")

NOT_ROOT = pytest.mark.skipif(
    os.geteuid() == 0, reason="root ignores permission bits — CI runs non-root (defender/CLAUDE.md)")


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    """Every configured root inside `tmp_path` — the launcher's episodes root, the runs base and
    the learning state root the judge's enqueue appends to."""
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    monkeypatch.setenv(J.STATE_DIR_ENV, str(tmp_path / "learning-state"))


def visualize_episode():
    """The target module, `defender.scripts.visualize.visualize_episode`, imported at call time
    (it does not exist at the spec's base — one failure per test, never a collection error)."""
    return E.page_module()


def render(ep) -> E.Page:
    """`visualize_episode().render_episode(<dir>)` — the real entry point — then the page it
    wrote, parsed."""
    return E.render(ep, module=visualize_episode())


def cli(argv, capsys):
    """`visualize_episode().main(argv)` with its stdout / stderr captured."""
    return E.cli(argv, capsys, module=visualize_episode())


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
    out = visualize_episode().render_episode(ep.dir)
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
    again = visualize_episode().render_episode(ep.dir)
    assert Path(again) == ep.page
    assert ep.page.stat().st_mtime_ns > before - 2_000_000_000, "the second call did not replace"
    assert ep.page.read_bytes() == first, "a re-render of the same records changed the bytes"


def test_1025_visualize_episode_cli_exits_zero_on_an_episode_dir_and_one_with_no_page_otherwise(
        tmp_path, capsys):
    """`main([dir])` returns 0 and prints the page path; `main([])`, `main([a file])`,
    `main([a dir with no family.yaml])` return 1, print one reason line to stderr, and leave no
    `learning.html`. Rejected: an index over all episodes (issue fork 1) — a second argument is
    refused the same way.
    """
    ep = E.sample_episode(tmp_path)
    rc, out, err = cli([str(ep.dir)], capsys)
    assert rc == 0, (rc, out, err)
    assert str(ep.page) in out, (rc, out, err)
    assert ep.page.is_file()

    a_file = tmp_path / "just-a-file"
    a_file.write_text("x", encoding="utf-8")
    bare = tmp_path / "no-manifest"
    bare.mkdir()
    ep.page.unlink()
    for argv in ([], [str(a_file)], [str(bare)], [str(ep.dir), str(bare)]):
        rc, out, err = cli(argv, capsys)
        assert rc == 1, f"main({argv}) returned {rc}: out={out!r} err={err!r}"
        assert len(_err_lines(err)) == 1, f"main({argv}) wrote {err!r} to stderr, not one line"
        assert not (bare / E.PAGE_NAME).exists()
        assert not (tmp_path / E.PAGE_NAME).exists()
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
        visualize_episode().render_episode(ep.dir)
    assert getattr(refused.value, "write_guarded_alias", None) is True, refused.value
    assert ep.page.is_symlink(), "the planted link was replaced"
    assert outside.read_text(encoding="utf-8") == "OUTSIDE", "the page was written THROUGH the link"
    ep.page.unlink()
    render(ep)
    assert ep.page.is_file()
    assert not ep.page.is_symlink()


def test_1025_a_render_creates_or_changes_exactly_one_file_learning_html_and_touches_no_run_visualizations_mirror(
        tmp_path):
    """A tree snapshot (paths + sizes + mtimes) of the episode before and after `render_episode`
    differs in exactly `learning.html`, and `defender/run-visualizations/<episode>/` is not
    created. Rejected: the mirror into `run-visualizations/` the run pages do. Positive
    control: the one changed file parses as the page (it carries `sec-verdict`).
    """
    ep = E.sample_episode(tmp_path)
    mirror = T.DEFENDER / "run-visualizations" / E.EPISODE_ID
    assert not mirror.exists(), "precondition: a stale mirror from another run"
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


def test_1025_the_launcher_renders_the_page_after_the_judge_frame_with_all_six_steps_on_it(tmp_path):
    """After `cli.main` returns 0 on a full fake-seamed episode, `learning.html` sits beside
    `judge.yaml` and its stage table carries all six `Step` rows on the record — none reads
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
    launcher = _cli()
    outside = tmp_path / "outside.html"
    outside.write_text("OUTSIDE", encoding="utf-8")
    episode_dir = launcher.episode_dir_for(T.EPISODE_ID)
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


def test_1025_review_rejected_episode_and_the_page(tmp_path, capsys):
    """The review-rejected path returns 1 before RUNS with no `judge.yaml` and no `runs/`, and
    the launcher writes no `learning.html` there — there is no second hook on that exit (J1).
    The standalone CLI still accepts that directory (only `family.yaml` refuses, d01): exit 0,
    the band says there is no grade record, the stage table carries the three recorded steps'
    rows and "not on the record" for the other three, and no world section exists.
    """
    launch = ST._launch(tmp_path, **ST._rejecting_seams())
    assert launch.rc == 1, "the control failed: the review did not reject"
    ep = launch.episode_dir
    assert not (ep / "judge.yaml").exists()
    assert not (ep / "runs").exists()
    assert not (ep / E.PAGE_NAME).exists(), "the launcher rendered on the rejected exit"

    rc, out, err = cli([str(ep)], capsys)
    assert rc == 0, (out, err)
    page = E.read_page(ep)
    assert "no grade record" in page.text_of("sec-verdict")
    timing = page.text_of("stage-timing")
    assert timing.count("not on the record") == 3, timing
    for step in ("questioner", "staging", "review"):
        assert step in timing
    assert page.ids_with("world-") == [], page.ids_with("world-")


def test_1025_held_teardown_fault_after_a_completed_grade(tmp_path):
    """A teardown fault held by `_cluster_released` is raised AFTER the render: the launch still
    leaves through `LauncherRefused` naming the teardown, `judge.yaml` is on disk, and so is
    `learning.html` with the `judge` row on its stage table — the renderer was called inside the
    held-fault frame once the `clock.step(Step.JUDGE)` frame had closed (J1), not after the
    outer `with` where the held fault would have skipped it.
    """
    with pytest.raises(_cli().LauncherRefused, match="teardown did not verify"):
        ST._launch(tmp_path, door=ST._StickyDoor())
    ep = _cli().episode_dir_for(T.EPISODE_ID)
    assert (ep / "judge.yaml").is_file(), "the control failed: the grade did not land"
    timing = hook_page(ep).text_of("stage-timing")
    assert "judge" in timing, timing
    assert "not on the record" not in timing, timing


def test_1025_how_the_operator_learns_where_the_page_is(tmp_path, capsys):
    """The launcher prints the page's path on stderr beside the episode line, and the CLI
    prints it on stdout (J2) — parity with `visualize_run`.
    """
    launch = ST._launch(tmp_path)
    err = capsys.readouterr().err
    page = launch.episode_dir / E.PAGE_NAME
    assert launch.rc == 0
    assert page.is_file()
    assert str(page) in err, f"stderr never named the page: {err!r}"
    rc, out, _err = cli([str(launch.episode_dir)], capsys)
    assert rc == 0
    assert str(page) in out


def test_1025_the_cli_exit_status_for_a_degraded_page(tmp_path, capsys):
    """A page that was written but carries a reader's refusal sentence (a `judge.yaml` that is
    not a grade record) exits 0 — the degradation is on the page — and the refusal sentence is
    echoed to stderr; non-zero is reserved for no page at all (no `family.yaml`, a refused write).
    """
    ep = E.sample_episode(tmp_path)
    E.plant_raw(ep.dir / "judge.yaml", "- not\n- a grade\n")
    rc, out, err = cli([str(ep.dir)], capsys)
    assert rc == 0, (out, err)
    assert ep.page.is_file()
    assert "grade record unreadable" in E.read_page(ep.dir).text_of("sec-verdict")
    assert "grade record unreadable" in err, err

    E.plant_link(ep.page, tmp_path / "nowhere")
    rc, out, err = cli([str(ep.dir)], capsys)
    assert rc == 1, (rc, out, err)
    assert _err_lines(err), (rc, out, err)


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


def test_1025_cli_argument_names_an_existing_regular_file_not_a_directory(tmp_path, capsys):
    """`main([<file>])` returns 1, one reason line on stderr, no page (d01)."""
    ep = E.sample_episode(tmp_path)
    rc, out, err = cli([str(ep.dir / "family.yaml")], capsys)
    assert rc == 1, (rc, out, err)
    assert len(_err_lines(err)) == 1, (rc, out, err)
    assert not ep.page.exists()


def test_1025_relative_and_trailing_slash_arguments(tmp_path, monkeypatch, capsys):
    """The page lands at `<episode_dir>/learning.html` for a cwd-relative path, a trailing
    slash and resolvable `..` segments alike; every link on the page is relative
    (`runs/<episode>-<world>/runtime.html`) so the argument's spelling and the cwd change
    nothing (d11).
    """
    ep = E.sample_episode(tmp_path)
    monkeypatch.chdir(tmp_path)
    rel = ep.dir.relative_to(tmp_path)
    renders = []
    for spelling in (f"{rel}/", f"{rel.parent}/../{rel}", str(rel)):
        if ep.page.exists():
            ep.page.unlink()
        rc, out, err = cli([spelling], capsys)
        assert rc == 0, (spelling, rc, out, err)
        assert ep.page.is_file(), (spelling, rc, out, err)
        renders.append(ep.page.read_bytes())
    assert len(set(renders)) == 1, "the argument's spelling changed the page"
    page = E.read_page(ep.dir)
    world_links = [h for h in page.hrefs if h.endswith("runtime.html")]
    assert world_links, "no world link on the page"
    for href in world_links:
        assert href.startswith("runs/"), href
        assert str(tmp_path) not in href, href
    assert all(not h.startswith("/") for h in page.hrefs), page.hrefs


def test_1025_runs_base_and_episodes_base_env_vars_point_at_nonexistent_paths_during_render(
        tmp_path, monkeypatch):
    """`render_episode` produces the same page with `DEFENDER_RUNS_BASE` /
    `DEFENDER_EPISODES_BASE` unset, set to nonexistent paths, or set to real ones — O6's
    positive control (g26: no reader reaches `resolve_runs_base`).
    """
    ep = E.sample_episode(tmp_path)
    renders = []
    for runs, episodes in ((None, None), (str(tmp_path / "nope-runs"), str(tmp_path / "nope-eps")),
                           (str(tmp_path / "defender-runs"), str(tmp_path / "episodes-root"))):
        for var, value in ((T.RUNS_BASE_ENV, runs), (T.EPISODES_BASE_ENV, episodes)):
            if value is None:
                monkeypatch.delenv(var, raising=False)
            else:
                monkeypatch.setenv(var, value)
        page = render(ep)
        assert f"world-{E.GRADED_WORLD}" in page.by_id
        assert "undecidable" in page.text_of("sec-verdict")
        renders.append(ep.page.read_bytes())
    assert len(set(renders)) == 1, "the environment's roots changed the page"


def _refused_manifest(tmp_path, capsys, plant) -> tuple[int, str, str, E.Episode]:
    ep = E.sample_episode(tmp_path)
    plant(ep.dir / "family.yaml")
    rc, out, err = cli([str(ep.dir)], capsys)
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


def test_1025_family_yaml_is_a_directory_not_a_file(tmp_path, capsys):
    """Refused like malformed syntax: exit 1, one reason line on stderr naming the manifest,
    no page.
    """
    def plant(p):
        p.unlink()
        p.mkdir()
    rc, _out, err, _ep = _refused_manifest(tmp_path, capsys, plant)
    lines = _err_lines(err)
    assert rc == 1, (rc, err)
    assert len(lines) == 1, (rc, err)
    assert "family.yaml" in lines[0], (rc, err)


def test_1025_family_yaml_is_zero_bytes(tmp_path, capsys):
    """Refused (an empty document is not a manifest mapping): exit 1, one reason line, no page
    — never a manifest with zero worlds.
    """
    rc, _out, err, _ep = _refused_manifest(tmp_path, capsys, lambda p: E.plant_raw(p, b""))
    lines = _err_lines(err)
    assert rc == 1, (rc, err)
    assert len(lines) == 1, (rc, err)
    assert "family.yaml" in lines[0], (rc, err)


def test_1025_family_yaml_top_level_document_is_a_list_not_a_mapping(tmp_path, capsys):
    """Refused: exit 1, one reason line naming the manifest, no page."""
    rc, _out, err, _ep = _refused_manifest(
        tmp_path, capsys, lambda p: E.plant_raw(p, "- world_id: a\n- world_id: b\n"))
    lines = _err_lines(err)
    assert rc == 1, (rc, err)
    assert len(lines) == 1, (rc, err)
    assert "family.yaml" in lines[0], (rc, err)


# ---------------------------------------------------------------------------------------
# d05 / J3 / J4 — location and process independence; concurrency
# ---------------------------------------------------------------------------------------


def _live996_shaped(tmp_path: Path, root: Path) -> E.Episode:
    """The second archive's shape: no family draw, no `samples.yaml`, a pre-#1007 grade with an
    ungradable row and `family_outcome` absent."""
    ep = E.sample_episode(tmp_path, root=root, family_draw=False, samples=False, judge=False)
    doc = E.sample_grade()
    doc["worlds"] = [E.ungradable_row(E.WITHHELD_WORLD, declared="benign"),
                     E.world_row(E.GRADED_WORLD, declared="malicious", has_refused=None)]
    doc["verdict_word"] = "survived"
    for key in ("family_outcome", "family_failed_reason", "family_malformed_replies",
                "world_enqueued_rows", "world_enqueued_to", "world_findings", "withheld_findings"):
        del doc[key]
    E.write_judge(ep.dir, doc)
    return ep


def test_1025_both_archived_episodes_render_from_a_copied_dir_with_no_runs_base_store_or_checkout_and_the_bytes_do_not_depend_on_where(
        tmp_path, monkeypatch):
    """Each archive shape (the fresh-authkeys shape and the live-996 shape — no family draw, no
    `samples.yaml`, an ungradable row, pre-#1007 fields absent) copied under two different roots
    AND two different directory names, with the `DEFENDER_*` roots unset, cwd elsewhere and no
    `.git` above, renders without raising, and the two renders of one archive are byte-identical
    — no absolute path and no directory name in the page (correction 4: the episode id is the
    manifest's). Rejected: any read of the source run dir (not in the archive).
    """
    for var in (T.RUNS_BASE_ENV, T.EPISODES_BASE_ENV):
        monkeypatch.delenv(var, raising=False)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    shapes = {"fresh": E.sample_episode(tmp_path, root=tmp_path / "build-a"),
              "live996": _live996_shaped(tmp_path, tmp_path / "build-b")}
    for name, built in shapes.items():
        one = E.copy_episode(built, tmp_path / "root-one" / f"{name}-copy-one")
        two = E.copy_episode(built, tmp_path / "root-two" / "nested" / f"{name}-renamed-two")
        render(one)
        render(two)
        a, b = one.page.read_bytes(), two.page.read_bytes()
        assert a == b, f"{name}: the two copies rendered differently"
        text = a.decode("utf-8")
        for absent in (str(tmp_path), "root-one", "renamed-two", "copy-one"):
            assert absent not in text, f"{name}: {absent!r} leaked into the page"
        assert E.EPISODE_ID in text


def test_1025_repair_and_regrade_leaves_the_page_stale(tmp_path):
    """The page carries NO render-provenance line — no timestamp, no record mtime (J3): two
    renders of one directory at different times are byte-identical and today's date appears
    nowhere in the bytes; a repaired-and-regraded record changes the page only through the
    record's own values (a new verdict word), never through a "rendered at" stamp.
    """
    ep = E.sample_episode(tmp_path)
    render(ep)
    first = ep.page.read_bytes()
    assert date.today().isoformat() not in first.decode("utf-8")
    later = ep.page.stat().st_mtime_ns + 5_000_000_000
    os.utime(ep.dir / "judge.yaml", ns=(later, later))
    render(ep)
    assert ep.page.read_bytes() == first, "a record mtime or a render time reached the page"
    doc = E.sample_grade()
    doc["verdict_word"] = "survived"
    E.write_judge(ep.dir, doc)
    page = render(ep)
    assert "survived" in page.text_of("sec-verdict")
    assert ep.page.read_bytes() != first


def test_1025_byte_identity_across_two_interpreter_processes(tmp_path):
    """Two interpreter processes with different hash seeds render the same directory to
    byte-identical pages — every set the page iterates is emitted in a defined order (numeric
    draws, `STEPS`, sorted labels), so d05's location independence is also process
    independence (J3).
    """
    ep = E.sample_episode(tmp_path)
    target = visualize_episode().__name__
    code = (f"from pathlib import Path; from {target} import render_episode; "
            f"render_episode(Path({str(ep.dir)!r}))")
    pages = []
    for seed in ("1", "424242"):
        env = dict(os.environ, PYTHONHASHSEED=seed, PYTHONPATH=str(T.DEFENDER.parent))
        proc = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True,
                              text=True, cwd=str(tmp_path))
        assert proc.returncode == 0, proc.stderr
        pages.append(ep.page.read_bytes())
    assert pages[0] == pages[1], "the two processes' pages differ"
    page = E.read_page(ep)
    assert len([i for i in page.ids if i.startswith("f-")]) == E.SAMPLE.findings, "positive control"


def test_1025_two_renders_in_flight_against_the_same_episode_dir(tmp_path):
    """Two renders of one episode running at the same time leave a WHOLE page — the last
    `os.replace` wins outright, there is no torn intermediate state and no staged temporary —
    and, both computing the same bytes from the same records, the page equals a third, solitary
    render (J3: no lock, no snapshot guarantee, determinism instead).
    """
    ep = E.sample_episode(tmp_path)
    errors: list[BaseException] = []

    def go() -> None:
        try:
            visualize_episode().render_episode(ep.dir)
        except BaseException as bad:  # noqa: BLE001 — collected and asserted below
            errors.append(bad)

    threads = [threading.Thread(target=go) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)
    assert not errors, errors
    concurrent = ep.page.read_bytes()
    assert not [p for p in ep.dir.iterdir() if p.name.startswith(".")], "a staged temp is left"
    page = render(ep)
    assert ep.page.read_bytes() == concurrent, "a concurrent render left a torn or foreign page"
    assert len([i for i in page.ids if i.startswith("f-")]) == E.SAMPLE.findings, "positive control"


def test_1025_judge_yaml_replaced_by_a_concurrent_re_grade_partway_through_one_render(tmp_path):
    """A `judge.yaml` rewritten (verdict `undecidable` → `survived`) while the render is in
    flight — from a signal handler that fires only inside the page module's frame — costs the
    render nothing: no error, a whole page carrying one of the two verdicts, and the next
    render carries the new one (J3: each record is read once per render, no cross-file
    snapshot is promised).
    """
    ep = E.sample_episode(tmp_path)
    regrade = E.sample_grade()
    regrade["verdict_word"] = "survived"

    with E.when_inside(lambda: E.write_judge(ep.dir, regrade, check=False)) as seen:
        page = render(ep)
    assert seen["hit"], "the rewrite never landed inside the render"
    band = page.text_of("sec-verdict")
    assert ("undecidable" in band) != ("survived" in band), band
    assert page.raw.rstrip().endswith("</html>"), "the page is not whole"
    assert "survived" in render(ep).text_of("sec-verdict")


def test_1025_draw_or_judge_yaml_record_is_rewritten_mid_render(tmp_path):
    """A per-draw document rewritten while the render is in flight (a claim replaced) produces
    no error and a whole page whose findings carry either the old or the new text; each reader
    reads independently, as-of when it is touched, and the next render shows the rewrite (J3).
    """
    ep = E.sample_episode(tmp_path)
    rewritten = E.draw_doc(findings=[E.finding(subject="defender", claim="REWRITTEN CLAIM")])

    with E.when_inside(lambda: E.draw_document(ep.dir, E.GRADED_WORLD, 0, rewritten,
                                               check=False)) as seen:
        page = render(ep)
    assert seen["hit"], "the rewrite never landed inside the render"
    findings = page.text_of("sec-findings")
    assert ("REWRITTEN CLAIM" in findings) or ("defender claim 0" in findings), findings
    assert page.raw.rstrip().endswith("</html>")
    assert "REWRITTEN CLAIM" in render(ep).text_of("sec-findings")


def test_1025_episode_dir_given_through_a_symlink(tmp_path, capsys):
    """`episodes/latest -> <id>` as the CLI argument is accepted (J4): exit 0, the page written
    inside the TARGET beside `judge.yaml`, and every world link composed from names
    (`runs/<episode>-<world>/runtime.html`) — identical whether computed against the link or
    its target.
    """
    ep = E.sample_episode(tmp_path)
    latest = ep.dir.parent / "latest"
    latest.symlink_to(ep.dir, target_is_directory=True)
    rc, out, err = cli([str(latest)], capsys)
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


def test_1025_questioner_or_staging_abort_leaves_a_partial_directory(tmp_path, monkeypatch, capsys):
    """The launcher writes no page on an abort (the hook is after JUDGE). The standalone CLI
    renders when `family.yaml` exists — a staging abort: no-grade band, a stage row per `STEPS`
    member with a wall for the recorded step (`questioner`) and "not on the record" for the
    other five, no world sections (no `runs/`), records section "absent" per record. When the
    abort preceded `write_family` (the questioner interrupted) there is no `family.yaml` and
    d01's exit-1 / no-page arm applies.
    """
    launcher = _cli()
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-staging"))
    ep, _b, _a = ST._abort(tmp_path, launcher.LauncherRefused,
                           door=T.FakeDoor(fault=T.Fault(raise_after=2)))
    assert not (ep / E.PAGE_NAME).exists(), "the launcher rendered on an abort"
    assert (ep / "family.yaml").is_file()
    assert not (ep / "runs").exists()
    rc, out, err = cli([str(ep)], capsys)
    assert rc == 0, (out, err)
    page = E.read_page(ep)
    assert "no grade record" in page.text_of("sec-verdict")
    timing = page.text_of("stage-timing")
    assert timing.count("not on the record") == 5, timing
    assert page.ids_with("world-") == []
    assert page.text_of("sec-records").count("absent") >= 3, page.text_of("sec-records")

    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-questioner"))
    questioner = ST._Interrupting(launcher.episode_dir_for(T.EPISODE_ID))
    ep2, _b, _a = ST._abort(tmp_path, launcher.LauncherRefused, questioner=questioner)
    assert not (ep2 / "family.yaml").exists(), "the control failed: the manifest was written"
    rc, out, err = cli([str(ep2)], capsys)
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
        visualize_episode().render_episode(ep.dir)
    assert seen["hit"], "the interrupt never landed inside the render"
    assert ep.page.read_bytes() == previous, "a partial page replaced the previous one"
    assert sorted(p.name for p in ep.dir.iterdir()) == listing, "a staged temporary was left"

    with pytest.raises(KeyboardInterrupt), \
            E.when_inside(E.raise_now(KeyboardInterrupt("mid-render"))) as seen:
        ST._launch(tmp_path)
    assert seen["hit"], "the interrupt never landed inside the launcher's render"
    launched = _cli().episode_dir_for(T.EPISODE_ID)
    assert (launched / "judge.yaml").is_file(), "the grade was not on disk before the render"
    assert not (launched / E.PAGE_NAME).exists(), "a partial page was left by the interrupt"
    assert not [p for p in launched.iterdir() if p.name.startswith(".")], "a staged temp is left"


def test_1025_standalone_render_of_a_live_episode(tmp_path):
    """The renderer writes nothing but `learning.html` and mutates no record: on an episode
    still being written — no `judge.yaml` yet, a trace whose last row is torn, a `staged.yaml`
    caught mid-append — it renders each record as read at that instant through the readers'
    own fault arms (the torn row dropped and counted, the staging record refused, the no-grade
    band) and the tree snapshot differs in exactly the page. No "live" indicator is owed.
    """
    ep = E.sample_episode(tmp_path, judge=False)
    trace = ep.dir / "wire_logs" / "questioner_trace.jsonl"
    torn = trace.read_text(encoding="utf-8").rstrip("\n")
    trace.write_text(torn[: len(torn) // 2], encoding="utf-8")
    with (ep.dir / "staged.yaml").open("a", encoding="utf-8") as fh:
        fh.write("- world: {half\n")
    before = E.snapshot(ep.dir)
    page = render(ep)
    after = E.snapshot(ep.dir)
    assert {k for k in set(before) | set(after) if before.get(k) != after.get(k)} == {E.PAGE_NAME}
    assert "no grade record" in page.text_of("sec-verdict")
    assert "1 unreadable row" in page.text_of("tx-questioner_trace"), page.text_of("tx-questioner_trace")
    assert "staging record unreadable" in page.text_of("sec-records")


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
        visualize_episode().render_episode(ep.dir)
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
        visualize_episode().render_episode(ep.dir)
    assert seen["hit"]
    assert not ep.page.exists(), "a partial page was written"
    assert sorted(p.name for p in ep.dir.iterdir()) == listing

    render(ep)
    previous = ep.page.read_bytes()
    with pytest.raises(RuntimeError, match="mid-build"), \
            E.when_inside(E.raise_now(RuntimeError("mid-build"))) as seen:
        visualize_episode().render_episode(ep.dir)
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
        rc, out, err = cli([str(ep.dir)], capsys)
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

    launched = _cli().episode_dir_for(T.EPISODE_ID)
    judge = _ReadOnlyJudge(launched, default=J.as_reply_text(J.reply_doc()))
    try:
        launch = ST._launch(tmp_path, judge=judge)
        err = capsys.readouterr().err
    finally:
        launched.chmod(0o755)
    assert launch.rc == 0, "a refused page write changed the exit status"
    assert "could not be rendered" in err, err
    assert not (launched / E.PAGE_NAME).exists()
