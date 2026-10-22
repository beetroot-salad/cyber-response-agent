"""#1108 P4 slice S-C — the run page.

- O-WARN (U8): a stale run's page carries a banner naming the kind, the reason and the commit
  used; fresh and pinned runs carry none.
- O-U6: the run page has no lesson-history section and no table-of-contents entry for one.
  (The structural half, "nothing in `presentation/` runs git", is slice S-A's.)

Entry: a real hermetic run driven through the replay harness (`test_922_renderer.driven_run`), its
page saved by the real post-run step (`run_common.visualize` over the tenant-bound handle), read
back from the run dir. The run's knowledge source is planted in its run record (the provenance
stamp; see `test_stale_visibility.knowledge_source` for the one place its shape is spelled).
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
    knowledge_source,
    names_commit,
    stamp_knowledge_source,
)

pytestmark = pytest.mark.e2e

#: A reason as hostile as the run record (box-writable) can carry: markup and quotes that a page
#: printing it raw would execute or break on.
HOSTILE_REASON = 'forge said <img src=x onerror="alert(1)"> & left "main" unprotected'


def _page(run_dir: Path) -> str:
    """Save the run's page through the real post-run step and read it back."""
    from defender import run_common
    from defender.tests.e2e.test_922_renderer import tenant_run

    page_file = run_dir / "runtime.html"
    page_file.unlink(missing_ok=True)
    run_common.visualize(tenant_run(run_dir))
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


@pytest.mark.parametrize("stale_kind", STALE_KINDS)
def test_o_warn_a_stale_runs_page_carries_a_banner_naming_kind_reason_and_commit(
        run_dir, stale_kind):
    """O-WARN: the page of a run recorded stale names its kind, its reason (operator-facing, so
    the raw reason is shown) and the commit the run used; the same run recorded fresh shows none
    of them."""
    reason = RAW_REASON[stale_kind]
    stamp_knowledge_source(run_dir, knowledge_source("fresh"))
    fresh = _visible(_page(run_dir))
    stamp_knowledge_source(run_dir, knowledge_source("stale", stale_kind=stale_kind))
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


def test_o_warn_the_banner_shows_a_box_written_reason_escaped(run_dir):
    """O-WARN, danger lens: the run record sits in the box's rw bind, so its reason is shown as
    text — escaped, never as markup."""
    stamp_knowledge_source(run_dir, knowledge_source("stale", stale_kind="operator",
                                                     reason=HOSTILE_REASON))
    page = _page(run_dir)
    assert html.escape(HOSTILE_REASON, quote=False) in page or html.escape(HOSTILE_REASON) in page, (
        "O-WARN: the banner does not show the stale reason (escaped)")
    assert '<img src=x onerror="alert(1)">' not in page, (
        "the box-written stale reason reached the page as markup")


@pytest.mark.parametrize(("kind", "commit"), [("fresh", FRESH_COMMIT), ("pinned", PINNED_COMMIT)],
                         ids=["fresh", "pinned"])
def test_o_warn_fresh_and_pinned_runs_pages_carry_no_stale_banner(run_dir, kind, commit):
    """O-WARN: a fresh or pinned run's page says nothing about stale knowledge; the same run
    recorded stale does (positive control on the same page)."""
    stamp_knowledge_source(run_dir, knowledge_source(kind, commit=commit))
    page = _visible(_page(run_dir))
    assert "stale" not in page.lower(), f"O-WARN: a {kind} run's page carries a stale banner"
    for stale_kind in STALE_KINDS:
        assert stale_kind not in page.lower(), f"O-WARN: a {kind} run's page names {stale_kind}"

    stamp_knowledge_source(run_dir, knowledge_source("stale", stale_kind="transient"))
    assert "stale" in _visible(_page(run_dir)).lower(), (
        "positive control: the same run recorded stale shows a banner on the same page")


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
