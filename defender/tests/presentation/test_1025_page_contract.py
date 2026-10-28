"""#1025 — the episode page's entry-point contract: `render_episode`, the CLI, the launcher hook, the
guarded write, and location independence."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import os
import subprocess
import sys
from pathlib import Path

import pytest

from defender.tests.support.presentation import _episode_1025 as E
from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.presentation import test_1025_stage_timing as ST

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")

NOT_ROOT = pytest.mark.skipif(
    os.geteuid() == 0, reason="root ignores permission bits — CI runs non-root (defender/CLAUDE.md)")


_tmp_roots = E.tmp_roots
visualize_episode = E.page_module
render = E.render
cli = E.cli
cli_on = E.cli_on
hook_page = E.hook_page


def _cli():
    return E.mod("learning.branch.cli")


def _err_lines(err: str) -> list[str]:
    return [line for line in err.splitlines() if line.strip()]


def test_1025_render_episode_writes_learning_html_beside_judge_yaml_and_returns_its_path(tmp_path):
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
        rc, out, err = cli(argv, capsys)
        assert rc == 1, f"main({argv}) returned {rc}: out={out!r} err={err!r}"
        assert len(_err_lines(err)) == 1, f"main({argv}) wrote {err!r} to stderr, not one line"
        assert not (bare / E.PAGE_NAME).exists()
        assert not (base / E.PAGE_NAME).exists()
        assert not ep.page.exists(), f"main({argv}) wrote the page"


def test_1025_a_link_planted_at_learning_html_is_refused_not_written_through(tmp_path):
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
    ep = E.sample_episode(tmp_path)
    mirror = run_visualizations_dir / E.EPISODE_ID
    assert not mirror.exists(), "precondition: a stale mirror from another run"
    before = E.snapshot(ep.dir)
    page = render(ep)
    after = E.snapshot(ep.dir)
    changed = {k for k in set(before) | set(after) if before.get(k) != after.get(k)}
    assert changed == {E.PAGE_NAME}, f"the render touched {sorted(changed)}"
    assert not mirror.exists(), "the page was mirrored into run-visualizations/"
    assert "sec-verdict" in page.by_id, "positive control: the one changed file is the page"


def test_1025_the_launcher_renders_the_page_after_the_judge_frame_with_every_step_on_it(tmp_path):
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
    fault itself is the guarded write meeting the link; the fake decides nothing. The launcher
    mints the episode's id, so the folder is the one `ST._NextEpisode` finds at the seam."""

    def __init__(self, episode: ST._NextEpisode, target: Path, **kw):
        super().__init__(**kw)
        self.episode, self.target = episode, Path(target)

    def __call__(self, prompt, **kw):
        page = self.episode.dir / E.PAGE_NAME
        if not page.is_symlink():
            E.plant_link(page, self.target)
        return super().__call__(prompt, **kw)


def test_1025_a_render_fault_is_printed_and_changes_neither_the_exit_status_nor_judge_yaml(
        tmp_path, monkeypatch, capsys):
    outside = tmp_path / "outside.html"
    outside.write_text("OUTSIDE", encoding="utf-8")
    judge = _PlantingJudge(ST._NextEpisode(), outside, default=J.as_reply_text(J.reply_doc()))
    launch = ST._launch(tmp_path, judge=judge)
    err = capsys.readouterr().err
    assert launch.rc == 0, "a render fault changed the launch's exit status"
    assert (launch.episode_dir / "judge.yaml").is_file()
    assert "could not be rendered" in err, err
    assert outside.read_text(encoding="utf-8") == "OUTSIDE"
    assert (launch.episode_dir / E.PAGE_NAME).is_symlink()

    control = ST._launch(tmp_path)
    assert control.rc == 0
    assert hook_page(control.episode_dir).by_id, "the control launch did not write a real page"


def test_1025_preflight_refused_episode_and_the_page(tmp_path, capsys):
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


def test_1025_cli_invoked_with_no_positional_argument(tmp_path, capsys):
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
    rc, _out, err, _ep = _refused_manifest(
        tmp_path, capsys, lambda p: E.plant_raw(p, "worlds: [\n  {world_id: b"))
    lines = _err_lines(err)
    assert rc == 1, (rc, err)
    assert len(lines) == 1, (rc, err)
    assert "family.yaml" in lines[0], lines[0]
    assert "could not be read" in lines[0], lines[0]
    assert "nothing is at that name" not in lines[0], lines[0]
    assert "missing" not in lines[0], lines[0]


def test_1025_episode_dir_given_through_a_symlink(tmp_path, capsys, monkeypatch):
    from defender.tests.storage.ids_1187 import _spec1187 as R

    monkeypatch.delenv(R.EPISODES_BASE_ENV, raising=False)
    tenant = E.page_tenant()
    episodes = R.episodes_dir(location_path(tenant.data_root), str(tenant.id))
    episode_id = R.new_id()
    built = E.sample_episode(tmp_path, root=episodes, runs=False)
    target = episodes / episode_id
    built.dir.rename(target)
    T.write_family(target, E.sample_manifest(episode_id=episode_id))
    latest = episodes / "latest"
    latest.symlink_to(target, target_is_directory=True)
    rc, out, err = cli(E.cli_argv(latest), capsys)
    assert rc == 1, (out, err)
    assert "latest" in err, err
    assert R.EPISODES_BASE_ENV not in err, f"refused for the retired variable, not the id: {err}"
    assert not (target / E.PAGE_NAME).exists()
    rc, out, err = cli(E.cli_argv(target), capsys)
    assert rc == 0, (out, err)
    assert (target / E.PAGE_NAME).is_file()


def test_1025_questioner_or_preflight_abort_leaves_a_partial_directory(tmp_path, monkeypatch, capsys):
    launcher = _cli()
    oracle_seam = ST._Interrupting(ST._NextEpisode())
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

    questioner = ST._Interrupting(ST._NextEpisode())
    ep2, _b, _a = ST._abort(tmp_path, launcher.LauncherRefused, questioner=questioner)
    assert not (ep2 / "family.yaml").exists(), "the control failed: the manifest was written"
    # Drain the launcher's own stderr (it primes the capture before the questioner runs), so
    # the assertion below reads only the CLI's report.
    capsys.readouterr()
    rc, out, err = cli_on(ep2, capsys)
    assert rc == 1, (out, err)
    assert len(_err_lines(err)) == 1, (out, err)
    assert not (ep2 / E.PAGE_NAME).exists(), (out, err)


def test_1025_an_interrupt_during_the_render(tmp_path):
    ep = E.sample_episode(tmp_path)
    render(ep)
    previous = ep.page.read_bytes()
    listing = sorted(p.name for p in ep.dir.iterdir())
    with pytest.raises(KeyboardInterrupt), \
            E.when_inside(E.raise_now(KeyboardInterrupt("mid-render")), at="_write_page") as seen:
        E.render_episode(ep.dir, module=visualize_episode())
    assert seen["hit"], "the interrupt never landed inside the render"
    assert ep.page.read_bytes() == previous, "a partial page replaced the previous one"
    assert sorted(p.name for p in ep.dir.iterdir()) == listing, "a staged temporary was left"

    nxt = ST._NextEpisode()
    with pytest.raises(KeyboardInterrupt), \
            E.when_inside(E.raise_now(KeyboardInterrupt("mid-render")), at="_write_page") as seen:
        ST._launch(tmp_path)
    assert seen["hit"], "the interrupt never landed inside the launcher's render"
    launched = nxt.dir
    assert (launched / "judge.yaml").is_file(), "the grade was not on disk before the render"
    assert not (launched / E.PAGE_NAME).exists(), "a partial page was left by the interrupt"
    assert not [p for p in launched.iterdir() if p.name.startswith(".")], "a staged temp is left"


def test_1025_a_refused_write_leaves_no_residue(tmp_path):
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
    ep = E.sample_episode(tmp_path)
    listing = sorted(p.name for p in ep.dir.iterdir())
    with pytest.raises(RuntimeError, match="mid-build"), \
            E.when_inside(E.raise_now(RuntimeError("mid-build")), at="_render_document") as seen:
        E.render_episode(ep.dir, module=visualize_episode())
    assert seen["hit"]
    assert not ep.page.exists(), "a partial page was written"
    assert sorted(p.name for p in ep.dir.iterdir()) == listing

    render(ep)
    previous = ep.page.read_bytes()
    with pytest.raises(RuntimeError, match="mid-build"), \
            E.when_inside(E.raise_now(RuntimeError("mid-build")), at="_render_document") as seen:
        E.render_episode(ep.dir, module=visualize_episode())
    assert seen["hit"]
    assert ep.page.read_bytes() == previous


@NOT_ROOT
def test_1025_a_read_only_episode_directory(tmp_path, capsys):
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
        def __init__(self, episode, **kw):
            super().__init__(**kw)
            self.episode = episode

        def __call__(self, prompt, **kw):
            reply = super().__call__(prompt, **kw)
            self.episode.dir.chmod(0o555)
            return reply

    # The launcher mints the episode's id: the folder is the one the launch makes.
    nxt = ST._NextEpisode()
    judge = _ReadOnlyJudge(nxt, default=J.as_reply_text(J.reply_doc()))
    try:
        launch = ST._launch(tmp_path, judge=judge)
        err = capsys.readouterr().err
    finally:
        for made in ST._episodes_now() - nxt.before:
            made.chmod(0o755)
    launched = nxt.dir
    assert launch.rc == 0, "a refused page write changed the exit status"
    assert "could not be rendered" in err, err
    assert not (launched / E.PAGE_NAME).exists()


def test_1025_the_standalone_script_runs_with_no_pythonpath_from_any_cwd(tmp_path):
    ep = E.sample_episode(tmp_path)
    script = Path(visualize_episode().__file__)
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    # `--tenant T <episode id>` finds the episode under the tenant's own `<T>/episodes/`, so
    # the child is handed no episodes base.
    env.pop(T.EPISODES_BASE_ENV, None)
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
    (ep.dir / "served" / f"{T.fixture_world_id(E.CONTROL)}.jsonl").unlink()
    E.plant_link(ep.dir / "served" / f"{T.fixture_world_id(E.GRADED_WORLD)}.jsonl",
                 ep.dir / "family.yaml")


def test_1025_an_unhealthy_episode_renders_no_absolute_path_and_byte_identically_from_two_roots(
        tmp_path, monkeypatch):
    for var in (T.RUNS_BASE_ENV, T.EPISODES_BASE_ENV):
        monkeypatch.delenv(var, raising=False)
    built = E.sample_episode(tmp_path, root=T.tenant_episodes(tmp_path / "build"))
    _unhealthy(built)
    one = E.copy_episode(built, tmp_path / "root-one" / built.dir.name)
    two = E.copy_episode(built, tmp_path / "root-two" / "nested" / built.dir.name)
    page = render(one)
    render(two)
    text = one.page.read_text(encoding="utf-8")
    for absent in (str(tmp_path), "root-one", "root-two", "nested"):
        assert absent not in text, f"{absent!r} leaked into the page"
    _assert_a_renamed_copy_is_refused(built, tmp_path / "root-three", "unhealthy")
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


def _assert_a_renamed_copy_is_refused(built: E.Episode, root: Path, name: str) -> None:
    """`built` copied under `root` to a folder named by a FRESH UUID — a well-formed episode id,
    so only the manifest check can refuse it — is refused, naming both the folder's id and the
    id its manifest carries, and no page is written for it."""
    from defender.tests.storage.ids_1187 import _spec1187 as R

    folder_id = R.new_id()
    renamed = E.copy_episode(built, root / folder_id)
    manifest_id = T.mod("_yaml").safe_load(
        (renamed.dir / "family.yaml").read_text(encoding="utf-8"))["episode_id"]
    assert manifest_id != folder_id, "the scene needs a manifest naming another episode"
    err = R.raised(E.render_episode, renamed.dir, module=visualize_episode())
    assert err is not None, f"{name}: a copy renamed to {folder_id} rendered"
    text = R.message(err)
    assert manifest_id in text, f"{name}: the refusal does not name the manifest's id: {text}"
    assert folder_id in text, f"{name}: the refusal does not name the folder's id: {text}"
    assert not renamed.page.exists(), f"{name}: a page was written for a renamed copy"
