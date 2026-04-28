"""Benign-action shortcircuit for REPORT.

Optional per-signature opt-in: when ANALYZE routed `disposition: true_positive`
purely by authority exhaustion AND the alert's command body matches the
playbook's `## Benign action classes` list, REPORT downgrades to
inconclusive. Asymmetric on cost: a false fire downgrades to inconclusive
(analyst still reviews); a missed fire keeps the existing true_positive
behavior.

Lifted out of report.py because the shortcircuit is a self-contained
opt-in concern with three small helpers — no entanglement with the
mechanical composers or the report.md assembly.
"""

from __future__ import annotations

import json

from scripts.orchestrate import Context, OrchestrationError

from scripts.handlers._playbook import load_playbook_metadata


# Common shell wrappers that wrap a benign command in a process tree. We
# strip these prefixes before comparing the alert's command body against the
# playbook's `## Benign action classes` list — `bash -c whoami` should match
# `whoami`, not the full wrapped form.
_SHELL_WRAPPER_PREFIXES = (
    "bash -c", "sh -c", "zsh -c", "ksh -c", "dash -c", "ash -c",
    "/bin/bash -c", "/bin/sh -c", "/bin/zsh -c",
    "/usr/bin/bash -c", "/usr/bin/sh -c",
)


def _normalize_command_body(cmdline: str) -> str:
    """Strip a `<shell> -c` wrapper and surrounding quotes; lowercase.

    Returns the inner command body for matching against the benign-action
    list. Idempotent — never strips more than one wrapper, never strips
    arguments past the first body. Caller compares the result against
    bullet entries verbatim.
    """
    s = cmdline.strip().lower()
    for prefix in _SHELL_WRAPPER_PREFIXES:
        if s.startswith(prefix + " "):
            s = s[len(prefix) + 1 :].strip()
            break
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        s = s[1:-1].strip()
    return s


def _command_body_matches_benign_list(
    cmdline: str, benign_classes: list[str],
) -> str | None:
    """Return the matching benign-class entry, or None.

    Match policy: exact equality on the normalized body, OR the body starts
    with `<class> ` (i.e. the same command with arguments / flags). This
    handles entries like `ls` (matches `ls -la /tmp`) and `cat /etc/os-release`
    (matches verbatim). Multi-token classes match only the exact prefix.
    """
    if not benign_classes:
        return None
    body = _normalize_command_body(cmdline)
    if not body:
        return None
    for entry in benign_classes:
        ent = entry.strip().lower()
        if not ent:
            continue
        if body == ent:
            return entry
        if body.startswith(ent + " "):
            return entry
    return None


def _maybe_apply_benign_action_shortcircuit(
    ctx: Context,
    *,
    disposition: str,
    confidence: str,
    termination_category: str,
    surviving_hypotheses: list[str],
) -> tuple[str, str, bool, str | None]:
    """Override `(disposition, confidence)` to `(inconclusive, medium)` when:

    1. The signature playbook declares a `## Benign action classes` list
       (opt-in — empty list disables the short-circuit).
    2. The alert's command body (stripped of any `<shell> -c` wrapper)
       matches an entry on that list.
    3. ANALYZE routed `disposition: true_positive` purely by exhaustion of
       authority — termination_category in {trust-root, exhaustion-escalation}
       AND no hypothesis on the surviving list reached `++` (we approximate
       this by gating on `disposition: true_positive` rather than `benign`,
       which already requires anchor grounding).

    Returns `(disposition, confidence, applied, matched_class)`. When
    `applied=True`, REPORT downgrades to inconclusive and the rationale
    composer cites the matched class.

    Cost of a false positive (firing when shouldn't): inconclusive instead
    of true_positive — analyst still reviews. Cost of a false negative
    (not firing when should): unchanged from today — analyst reviews a
    true_positive that was actually inconclusive. Asymmetric in favor
    of firing when the conditions hold.
    """
    if disposition != "true_positive":
        return disposition, confidence, False, None
    if termination_category not in ("trust-root", "exhaustion-escalation"):
        return disposition, confidence, False, None

    try:
        playbook = load_playbook_metadata(ctx.signature_id)
    except OrchestrationError:
        # Signature directory absent or malformed — short-circuit cannot
        # reason about it; defer to the rest of REPORT.
        return disposition, confidence, False, None
    benign_classes = playbook.benign_action_classes
    if not benign_classes:
        return disposition, confidence, False, None

    alert_path = ctx.run_dir / "alert.json"
    if not alert_path.exists():
        return disposition, confidence, False, None
    try:
        alert = json.loads(alert_path.read_text())
    except (OSError, json.JSONDecodeError):
        return disposition, confidence, False, None

    cmdline = (
        alert.get("data", {})
        .get("output_fields", {})
        .get("proc", {})
        .get("cmdline", "")
    )
    if not isinstance(cmdline, str) or not cmdline:
        return disposition, confidence, False, None

    matched = _command_body_matches_benign_list(cmdline, benign_classes)
    if matched is None:
        return disposition, confidence, False, None

    return "inconclusive", "medium", True, matched
