"""#1540 F8, the CSP guard's own controls: a page loaded through the real ingress, a violation it triggers is recorded
(across a navigation and a closed tab too), and a clean load records none."""
from __future__ import annotations

from defender.tests.frontend._flow1161 import FAILED, screen
from defender.tests.frontend.conftest import WAIT_MS, guard_csp

INLINE_SCRIPT = "const s = document.createElement('script'); s.textContent = 'void 0'; document.body.append(s);"
THIRD_PARTY_IMAGE = ("const i = document.createElement('img'); i.src = 'https://example.invalid/x.png';"
                     " document.body.append(i);")


def _wait_for(page, violations, count=1):
    for _ in range(50):
        if len(violations) >= count:
            return
        page.wait_for_timeout(100)


def _guarded_page(browser, world):
    context = browser.new_context()
    context.set_default_timeout(WAIT_MS)
    violations = guard_csp(context)
    page = context.new_page()
    page.goto(f"{world.origin}/{FAILED}")
    screen(page, FAILED)
    return context, page, violations


def test_1540_f8_a_clean_page_load_records_no_csp_violation(browser, world):
    """A page load that stays within the ingress's CSP leaves the guard empty (F8, positive control)."""
    context = browser.new_context()
    try:
        violations = guard_csp(context)
        page = context.new_page()
        page.goto(f"{world.origin}/{FAILED}")
        screen(page, FAILED)
        page.wait_for_load_state("networkidle")
        page.wait_for_timeout(500)
        assert violations == []
    finally:
        context.close()


def test_1540_f8_an_inline_script_is_recorded_as_a_csp_violation(browser, world):
    """The guard records an inline script the ingress's CSP blocks (F8)."""
    context, page, violations = _guarded_page(browser, world)
    try:
        page.evaluate(INLINE_SCRIPT)
        _wait_for(page, violations)
        assert violations
        assert "script-src" in violations[0] or "default-src" in violations[0], violations
    finally:
        context.close()


def test_1540_f8_a_third_party_image_is_recorded_as_a_csp_violation(browser, world):
    """The guard records a third-party origin the ingress's CSP blocks (F8, F1)."""
    context, page, violations = _guarded_page(browser, world)
    try:
        page.evaluate(THIRD_PARTY_IMAGE)
        _wait_for(page, violations)
        assert violations
        assert "example.invalid" in violations[0], violations
    finally:
        context.close()


def test_1540_f8_violations_in_later_documents_and_closed_tabs_are_still_recorded(browser, world):
    """The guard keeps reporting after a navigation, and what a tab reported stays after the tab closes (F8)."""
    context, page, violations = _guarded_page(browser, world)
    try:
        page.evaluate(THIRD_PARTY_IMAGE)
        _wait_for(page, violations)
        page.goto(f"{world.origin}/{FAILED}?again=1")  # another document
        screen(page, FAILED)
        page.evaluate(INLINE_SCRIPT)
        _wait_for(page, violations, 2)
        page.close()
        assert len(violations) >= 2, violations
        assert any("example.invalid" in v for v in violations), violations
    finally:
        context.close()
