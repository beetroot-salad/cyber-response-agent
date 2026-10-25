"""#1108 P4 slice S-C — the run page.

- O-WARN (U8, U12): a stale run's page carries a banner naming the kind, the reason and the
  commit used, read from the HOST record beside the run dir; fresh and pinned runs carry none;
  a stamp the box rewrites (suppress or forge) changes nothing on the page.
- O-U6: the run page has no lesson-history section and no table-of-contents entry for one.
  (The structural half, "nothing in `presentation/` runs git", is slice S-A's.)

Entry: a real hermetic run driven through the replay harness (`test_922_renderer.driven_run`), its
page saved by the real post-run step (`run_common.visualize` over the tenant-bound handle), read
back from the run dir. The run's knowledge source is planted as the host record
(`test_stale_visibility.write_host_record`, assumed seam `RunPaths.knowledge_source()`), and the
box-readable provenance stamp carries its informational view (OD17: no reason) unless a test
plays the box rewriting it.
"""
from __future__ import annotations

import html
import re
from pathlib import Path

import pytest

from defender.tests.tenancy.tenant_1108_p4.test_stale_visibility import (
    FRESH_COMMIT,
    PINNED_COMMIT,
    RAW_REASON,
    STALE_COMMIT,
    STALE_KINDS,
    SHORT_COMMIT,
    knowledge_source,
    names_commit,
    stamp_knowledge_source,
    stamp_view,
    write_host_record,
)

pytestmark = pytest.mark.e2e

#: A reason as hostile as a publish refusal can quote (a merged commit's path, a forge's error
#: body): markup and quotes that a page printing it raw would execute or break on.
HOSTILE_REASON = 'forge said <img src=x onerror="alert(1)"> & left "main" unprotected'


def _page(run_dir: Path) -> str:
    """Save the run's page through the real post-run step and read it back."""
    from defender import run_common
    from defender.tests.e2e.test_922_renderer import tenant_run
    from defender.tests.support.shared.contracts._data_root_1078 import (
        current_data_root,
        set_up_tenant,
    )

    page_file = run_dir / "runtime.html"
    page_file.unlink(missing_ok=True)
    run = tenant_run(run_dir)
    run_common.visualize(run, tenant=set_up_tenant(current_data_root(), run.tenant_id))
    return page_file.read_text(encoding="utf-8")


#: The pytest temp root, whose folder names spell the test's name (`test_o_warn_a_stale_...`):
#: the page shows the run dir's path, so a word search must not read the test's own name.
_TMP_ROOTS: list[str] = []


def _visible(page: str) -> str:
    """The page without its inlined stylesheet and scripts (a CSS class or a script string naming
    `stale` is not something the reader sees) and without the test's temp paths."""
    text = re.sub(r"(?is)<(style|script)\b.*?</\1\s*>", "", page)
    for root in _TMP_ROOTS:
        text = re.sub(re.escape(root) + r"[^\s<\"']*", "<TMP>", text)
    return text


@pytest.fixture
def run_dir(tmp_path):
    from defender.tests.e2e.test_922_renderer import MARKER, driven_run

    _TMP_ROOTS[:] = [str(tmp_path.parent), html.escape(str(tmp_path.parent))]
    driven = driven_run(tmp_path)
    assert MARKER in _page(driven), "positive control: the page renders this run"
    return driven


def _record(run_dir: Path, source: dict) -> None:
    """Run start's two writes: the host record (authoritative) and the stamp's informational view."""
    write_host_record(run_dir, source)
    stamp_knowledge_source(run_dir, stamp_view(source))


def _normalized(page: str) -> str:
    return re.sub(r"\d{4}-\d{2}-\d{2}[T ][\d:.]+(?:Z|[+-]\d{2}:?\d{2})?", "<TS>", _visible(page))


@pytest.mark.parametrize("stale_kind", STALE_KINDS)
def test_o_warn_a_stale_runs_page_carries_a_banner_naming_kind_reason_and_commit(
        run_dir, stale_kind):
    """O-WARN: the page of a run whose host record is stale names its kind, its raw reason
    (operator-facing; the host record is the only place it is kept) and the commit the run used;
    the same run recorded fresh shows none of them."""
    reason = RAW_REASON[stale_kind]
    _record(run_dir, knowledge_source("fresh"))
    fresh = _visible(_page(run_dir))
    _record(run_dir, knowledge_source("stale", stale_kind=stale_kind))
    stale = _visible(_page(run_dir))

    assert html.escape(reason) not in fresh, "positive control"
    assert reason not in fresh, "positive control"
    assert html.escape(reason) in stale or reason in stale, (
        f"O-WARN: the stale ({stale_kind}) run's page does not show why it is stale: {reason!r}")
    assert names_commit(stale, STALE_COMMIT), (
        f"O-WARN: the stale run's page does not name the commit it used ({STALE_COMMIT})")
    assert "stale" in stale.lower(), "O-WARN: the stale run's page does not say it is stale"
    assert stale_kind in stale.lower(), (
        f"O-WARN: the stale run's page does not name its kind ({stale_kind})")
    assert "stale" not in fresh.lower(), "O-WARN: a fresh run's page says it is stale"
    assert stale_kind not in fresh.lower(), (
        f"O-WARN: a fresh run's page names a stale kind ({stale_kind})")


#: What a tampering box writes into the stamp: a commit and a reason of its own.
TAMPERED_COMMIT = "0ddba110ddba110ddba110ddba110ddba110ddba"
TAMPERED_REASON = "box says: open https://evil.invalid/ to fix"


@pytest.mark.parametrize("tamper", ["suppress", "forge"])
def test_o_warn_a_box_rewritten_stamp_changes_nothing_on_the_page(run_dir, tamper):
    """O-WARN, danger lens (U12, OD17): the stamp sits in the box's rw bind, so the page reads the
    host record only. The box rewriting the stamp changes nothing on the page, both ways:
    - suppress: host record stale, stamp rewritten to fresh -> the banner is still there;
    - forge: host record fresh, stamp rewritten to stale with the box's own commit and reason ->
      still no banner, and neither the planted commit nor reason appears."""
    if tamper == "suppress":
        host = knowledge_source("stale", stale_kind="transient")
        planted = knowledge_source("fresh", commit=STALE_COMMIT)
    else:
        host = knowledge_source("fresh")
        planted = knowledge_source("stale", stale_kind="operator", commit=TAMPERED_COMMIT,
                                   reason=TAMPERED_REASON)
    _record(run_dir, host)
    honest = _page(run_dir)
    stamp_knowledge_source(run_dir, planted)
    tampered = _page(run_dir)

    assert _normalized(tampered) == _normalized(honest), (
        f"O-WARN: a box-rewritten stamp ({tamper}) changed the run page — the page must read "
        "the host record only")
    visible = _visible(tampered).lower()
    if tamper == "suppress":
        assert "stale" in visible, (
            "O-WARN: the box suppressed the stale banner by rewriting the stamp to fresh")
        assert names_commit(visible, STALE_COMMIT), "O-WARN: the banner lost the host's commit"
    else:
        assert "stale" not in visible, "O-WARN: the box forged a stale banner through the stamp"
        assert TAMPERED_COMMIT[:SHORT_COMMIT] not in visible, "the planted commit is on the page"
        assert "evil.invalid" not in visible, "the planted reason is on the page"


def test_o_warn_the_banner_shows_a_hostile_reason_escaped(run_dir):
    """O-WARN, danger lens: a reason quoting attacker-influenced text (a merged path, a forge's
    error body) is shown as text — escaped, never as markup."""
    _record(run_dir, knowledge_source("stale", stale_kind="operator", reason=HOSTILE_REASON))
    page = _page(run_dir)
    assert html.escape(HOSTILE_REASON, quote=False) in page or html.escape(HOSTILE_REASON) in page, (
        "O-WARN: the banner does not show the stale reason (escaped)")
    assert '<img src=x onerror="alert(1)">' not in page, (
        "the stale reason reached the page as markup")


@pytest.mark.parametrize(("kind", "commit"), [("fresh", FRESH_COMMIT), ("pinned", PINNED_COMMIT)],
                         ids=["fresh", "pinned"])
def test_o_warn_fresh_and_pinned_runs_pages_carry_no_stale_banner(run_dir, kind, commit):
    """O-WARN: a fresh or pinned run's page says nothing about stale knowledge; the same run
    recorded stale does (positive control on the same page)."""
    _record(run_dir, knowledge_source(kind, commit=commit))
    page = _visible(_page(run_dir))
    assert "stale" not in page.lower(), f"O-WARN: a {kind} run's page carries a stale banner"
    for stale_kind in STALE_KINDS:
        assert stale_kind not in page.lower(), f"O-WARN: a {kind} run's page names {stale_kind}"

    _record(run_dir, knowledge_source("stale", stale_kind="transient"))
    assert "stale" in _visible(_page(run_dir)).lower(), (
        "positive control: the same run recorded stale shows a banner on the same page")


@pytest.mark.parametrize("how", ["missing-with-stamp", "corrupt"])
def test_od22_an_unreadable_host_record_shows_a_stale_operator_banner(run_dir, how):
    """OD22' (3): where a host record should exist (the stamp names a source) but is missing, or
    the record is corrupt, the page claims no freshness: a stale banner of kind operator saying
    the knowledge record is unreadable. Control: the same run with a fresh host record shows no
    banner."""
    from defender.tests.tenancy.tenant_1108_p4.test_stale_visibility import (
        plant_unreadable_host_record,
    )

    _record(run_dir, knowledge_source("fresh"))
    assert "stale" not in _visible(_page(run_dir)).lower(), "positive control"

    plant_unreadable_host_record(run_dir, how)  # the stamp says fresh
    page = _visible(_page(run_dir)).lower()
    assert "stale" in page, f"OD22: a {how} host record left the page claiming fresh"
    assert "operator" in page, f"OD22: the {how}-record banner is not of kind operator"
    assert "knowledge record unreadable" in page, (
        f"OD22: the {how}-record banner does not say the knowledge record is unreadable")


def test_od22_a_pre_p4_run_page_shows_no_banner(run_dir):
    """OD22' (2): a run with no host record and no `knowledge_source` in its stamp (pre-P4; old
    runs are not rewritten) shows no banner. Control on the same page: the same run whose stamp
    names a source with the record missing (case 3) shows the unreadable banner."""
    from defender.tests.tenancy.tenant_1108_p4.test_stale_visibility import (
        plant_pre_p4_run,
        plant_unreadable_host_record,
    )

    plant_pre_p4_run(run_dir)
    page = _visible(_page(run_dir)).lower()
    assert "stale" not in page, "OD22': a pre-P4 run's page carries a stale banner"
    assert "knowledge record unreadable" not in page, "OD22': a pre-P4 run is called unreadable"

    plant_unreadable_host_record(run_dir, "missing-with-stamp")
    assert "knowledge record unreadable" in _visible(_page(run_dir)).lower(), (
        "positive control: a missing record where one should exist shows the unreadable banner")


def test_o_u6_the_run_page_has_no_lesson_history_section_or_toc_entry(run_dir):
    """O-U6 (U6): the run page drops the lesson-history panel (today's footer of "concurrent
    lesson commits", read with `git log` over the product tree) and its table-of-contents link.
    The rest of the table of contents stays (positive control)."""
    page = _page(run_dir)
    visible = _visible(page)

    toc = re.search(r'(?is)<nav class="toc">.*?</nav>', page)
    assert toc is not None, "positive control: the page still has its table of contents"
    for own in ('href="#sec-metrics"', 'href="#sec-transcript"'):
        assert own in toc.group(0), (
            f"positive control: the table of contents still links the run's own {own}")

    assert 'id="sec-footer"' not in page, "O-U6: the lesson-history section is still rendered"
    assert 'href="#sec-footer"' not in page, "O-U6: the table of contents still links lesson history"
    for phrase in ("lesson commit", "lesson change tracking", "lesson history"):
        assert phrase not in visible.lower(), (
            f"O-U6: the run page still shows lesson history ({phrase!r})")
