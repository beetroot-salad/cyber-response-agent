"""#1003 — the correlation lead's template id, driven through the REAL `run_investigation`.

THE DEFECT, END TO END. A deployment's own catalog and table are what the run reads, and
before #1003 a template whose `verb:` disagreed with the table's grant loaded clean: the run
opened its budget, claimed `l-00c`, and dispatched a lead told to bind an id its grant-
filtered index could not list. The unit half of this spec (`test_correlation_template_1003`)
pins the check; this half pins WHERE it fires — at run start, over the run's own tree, before
the budget opens, before the wire log opens, before any model is asked anything (O2, O3) —
and pins the authored contract the lead is handed (O4).

THE HARNESS. `_lead_zero_808.run` drives a real `run_investigation` with fake elastic verbs
through the `verbs=` seam. What #1003 adds is the tree: `drive(defender_dir=…)` points the
run at a PLANTED mirror of this checkout — every top-level entry symlinked, `skills/` copied
so one template file can be edited — because the shipped table and the shipped config are
process-cached reads that grant `elastic.alerts` and name the shipped id, so the catalog is
the one input an e2e can vary. The positive control on the same tree (the template copied
verbatim) proves the mirror is a tree the run dispatches from.

THE ORACLES. A typed error out of `run_investigation` naming both pairs; the run dir's own
artifacts (`budget.json`, `wire_logs/`, the `l-00c` sidecar); the fake models' request
counts; the fake registry's call record. For O4, the sidecar's authored text outside the
untrusted frame — the same split `test_808_correlation_lead` cuts — scanned for vendor
tokens, with the frame proven non-empty and proven to have carried the tokens the strip
removed.
"""
from __future__ import annotations

import re
import shutil
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender.tests.e2e._lead_zero_808 import (  # noqa: E402
    CORRELATION_SUMMARY,
    L3,
    alert_doc,
    answer_hits,
    elastic_backend,
    hit,
    materialize_alert,
    run,
)
from defender.tests.e2e._replay_harness import (  # noqa: E402
    DEFENDER,
    ReplayFn,
    Turn,
    VerbRecorder,
    drive,
)

pytestmark = pytest.mark.e2e

TEMPLATE_REL = Path("skills") / "gather" / "queries" / "elastic" / "correlate-alerts-by-entity.md"
#: The shipped id, transcribed (the unit module holds the same literal for the same reason).
SHIPPED_TEMPLATE_ID = "elastic.correlate-alerts-by-entity"
RULE_ID = "v2-sshd-success-after-failures"

#: Not mirrored into the planted tree: the venv, caches, this suite, the replay goldens —
#: nothing a run reads, and the first two are large.
_NOT_MIRRORED = frozenset({".venv", "__pycache__", "tests", "fixtures-e2e", "run-visualizations"})

ANCESTORS = [
    hit(ts="2026-05-25T15:26:10.000Z", user="dev.dana", ip="172.18.0.15", host="office-ws-1"),
    hit(ts="2026-05-25T15:26:50.000Z", user="svc.config-mgmt", ip="172.18.0.4", host="db-1"),
]


def planted_defender(root: Path) -> Path:
    """A defender tree the run can be pointed at whose CATALOG is editable: every top-level
    entry of this checkout symlinked (adapters, prompts, knowledge, the package itself), and
    `skills/` copied for real. `<root>/repo/defender`, so `defender_dir.parent` is a repo
    root the way the catalog's repo-relative locators expect."""
    tree = root / "repo" / "defender"
    tree.mkdir(parents=True)
    for entry in DEFENDER.iterdir():
        if entry.name in _NOT_MIRRORED or entry.name == "skills":
            continue
        (tree / entry.name).symlink_to(entry)
    shutil.copytree(DEFENDER / "skills", tree / "skills")
    return tree


def _rebind_verb(tree: Path, verb: str) -> None:
    """Edit the planted template's ONE `verb:` line — the same-vendor edit the grounding
    reproduced (`alerts` -> `query`), applied on the catalog side."""
    path = tree / TEMPLATE_REL
    text = path.read_text(encoding="utf-8")
    assert text.count("\nverb: alerts\n") == 1, "the shipped template's front matter moved"
    path.write_text(text.replace("\nverb: alerts\n", f"\nverb: {verb}\n"), encoding="utf-8")


def _authored(text: str) -> str:
    """Everything OUTSIDE the untrusted frame — the harness's own words. The same cut
    `test_808_correlation_lead` makes to tell a document naming the rule (evidence) from the
    harness naming it (a narrowing)."""
    framed = re.compile(r"<run-[0-9a-zA-Z]*-untrusted>.*?</run-[0-9a-zA-Z]*-untrusted>", re.DOTALL)
    return framed.sub("", text)


# =========================================================================================
# O2 / O3 — a mismatch between the run's catalog and the table refuses the run at start.
# =========================================================================================

def test_a_catalog_whose_template_disagrees_with_the_table_refuses_the_run_before_anything_is_spent(tmp_path):
    """The reproduced silent burn, closed where the design puts the check. The planted
    tree's template binds `verb: query`; the process's table grants the holder
    `elastic.alerts`; the process's config names this template. The run must end at
    `run_investigation`'s own frame with the typed refusal naming BOTH pairs and the id —
    and NOTHING downstream happened: no `budget.json` (the check precedes `open_budget`), no
    `wire_logs/` (precedes the logger), no `l-00c` sidecar (precedes `prepare_correlation_
    lead`), no verb call (precedes item 1), and neither fake model was asked for a turn.

    POSITIVE CONTROL on the same tree first: the template copied verbatim, and the run
    proceeds to claim `l-00c` and dispatch it — so the mirror is a tree the run reads its
    catalog from, and the refusal below is the template edit's doing."""
    tree = planted_defender(tmp_path / "ok")
    res = run(tmp_path / "ok", run_id="lz1003-ok", answer=answer_hits(ANCESTORS), defender_dir=tree)
    assert res.has_sidecar(L3), f"positive control: the planted tree did not dispatch l-00c ({res.gather_raw_names()})"
    assert res.gather is not None
    assert len(res.gather.seen) == 1, "positive control: item 3 was not dispatched"
    assert str(tree) in res.gather.seen[0], "positive control: the lead was not dispatched from the planted tree"
    assert res.budget, "positive control: the budget did not open"

    tree = planted_defender(tmp_path / "bad")
    _rebind_verb(tree, "query")
    run_dir = materialize_alert(tmp_path / "bad", alert_doc())
    rec = VerbRecorder()
    main = ReplayFn([Turn(tool_calls=[("read_file", {"path": str(run_dir / "alert.json")})]),
                     Turn(text="Investigation complete.")])
    gather = ReplayFn([Turn(text=CORRELATION_SUMMARY)])

    from defender.runtime.lead_zero import CorrelationDispatchError

    with pytest.raises(CorrelationDispatchError) as caught:
        drive(run_dir, run_id="lz1003-bad", main=main, gather=gather,
              verbs=elastic_backend(rec, answer_hits(ANCESTORS)), defender_dir=tree)
    message = str(caught.value)
    assert SHIPPED_TEMPLATE_ID in message, message
    assert "elastic.query" in message, f"the template's pair is not named:\n{message}"
    assert "elastic.alerts" in message, f"the table's pair is not named:\n{message}"

    assert not (run_dir / "budget.json").exists(), "the budget opened before the check"
    assert not (run_dir / "wire_logs").exists(), "the wire log opened before the check"
    assert not (run_dir / "gather_raw" / f"{L3}.lead.json").exists(), "l-00c was claimed before the check"
    assert rec.calls == [], f"a backend call was issued before the check: {rec.verbs}"
    assert main.seen == [], "MAIN was asked for a turn before the check"
    assert gather.seen == [], "the gather model was asked for a turn before the check"


# =========================================================================================
# O4 — the authored contract is vendor-neutral; the vendor facts live in the template.
# =========================================================================================

def test_the_authored_contract_carries_no_vendor_field_names_or_envelope_shape(tmp_path):
    """The lead's goal and `what_to_summarize`, OUTSIDE the untrusted frame, name no
    `kibana.` field and none of the envelope words `hits` / `total` / `truncated` — those
    are the template's to say (its Goal and Pitfalls already do). What stays is the neutral
    frame: the breadth instruction the 808 suite anchors on, and the configured id.

    Two positive controls keep the scan honest: the frame is non-empty and CARRIES a
    `kibana.` token (an ancestor document naming the rule that fired), so the split is
    proven to remove something; and the unstripped goal does contain the token, so "absent
    from the authored text" is the strip's work and not a scenario that never put it in."""
    from defender.runtime.lead_zero import CORRELATION_TEMPLATE

    res = run(tmp_path, run_id="lz1003-prose", alert=alert_doc(rule_id=RULE_ID),
              answer=answer_hits([
                  hit(ts="2026-05-25T15:26:10.000Z", user="dev.dana",
                      **{"kibana.alert.rule.rule_id": RULE_ID,
                         "kibana.alert.rule.name": "v2 sshd success after failures"}),
              ]))
    sidecar = res.sidecar(L3)
    goal = sidecar["goal"]
    what = sidecar["what_to_summarize"]
    assert isinstance(what, list), sidecar
    assert what, sidecar

    assert "kibana." in goal, "the scenario no longer puts a vendor field inside the evidence frame"
    authored_goal = _authored(goal)
    assert authored_goal != goal, "the frame strip removed nothing — the split is not doing work"
    assert authored_goal.strip(), "the frame strip ate the harness's own text"

    # The field family by any spelling (`kibana.`, `alert.rule`), the vendor's index, and the
    # vendor's envelope by name or by its fields: a paraphrase that keeps "the alerts index"
    # and "the envelope's count field" is the same vendor shape with the tokens filed off
    # (adversary H4). `\balerts\b` alone is NOT scanned — "prior alerts" is the neutral
    # concept the design keeps.
    vendor = re.compile(r"\bkibana\.|\balert\.rule\b|\balerts index\b", re.IGNORECASE)
    envelope = re.compile(r"\b(?:hits|total|truncated|envelope)\b", re.IGNORECASE)
    for label, text in (("goal", authored_goal), *((f"what_to_summarize[{i}]", w) for i, w in enumerate(what))):
        assert vendor.search(text) is None, f"a vendor field name in the authored {label}:\n{text}"
        assert envelope.search(text) is None, f"an envelope word in the authored {label}:\n{text}"

    assert "not narrow to this alert's own rule" in authored_goal, authored_goal
    # The design's replacement sentences, pinned POSITIVELY: the concept survives the token
    # scan only if it is actually said in the neutral form (prose split pieces 1 and 3).
    assert "correlation over PRIOR ALERTS" in authored_goal, authored_goal
    assert "the template says where its count is read" in authored_goal.lower(), authored_goal
    assert CORRELATION_TEMPLATE in authored_goal, authored_goal
    assert CORRELATION_TEMPLATE == SHIPPED_TEMPLATE_ID
