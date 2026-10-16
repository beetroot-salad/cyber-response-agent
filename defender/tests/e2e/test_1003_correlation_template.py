"""#1003 e2e: a correlation template whose verb disagrees with the table's grant refuses the run at start, before anything is spent; runs that never dispatch the lead are not refused."""
from __future__ import annotations

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
_NOT_MIRRORED = frozenset({".venv", "__pycache__", "tests", "fixtures-e2e"})
#: Copied for real rather than symlinked: the tree a scenario edits. `skills/` holds the
#: catalog. The config and the table are NOT in the tree since #1106 — they are the run's
#: TENANT's (`drive(tenant=…)`), so a scenario varying the config plants a tenant.
_COPIED = frozenset({"skills"})

ANCESTORS = [
    hit(ts="2026-05-25T15:26:10.000Z", user="dev.dana", ip="172.18.0.15", host="office-ws-1"),
    hit(ts="2026-05-25T15:26:50.000Z", user="svc.config-mgmt", ip="172.18.0.4", host="db-1"),
]


def planted_defender(root: Path) -> Path:
    """A defender tree the run can be pointed at whose CATALOG and CONFIG are editable:"""
    tree = root / "repo" / "defender"
    tree.mkdir(parents=True)
    for entry in DEFENDER.iterdir():
        if entry.name in _NOT_MIRRORED or entry.name in _COPIED:
            continue
        (tree / entry.name).symlink_to(entry)
    for name in _COPIED:
        shutil.copytree(DEFENDER / name, tree / name)
    return tree


def _mismatched(root: Path) -> Path:
    """The reproduced silent burn as a tree:"""
    tree = planted_defender(root)
    _rebind_verb(tree, "query")
    return tree


def _rebind_verb(tree: Path, verb: str) -> None:
    """Edit the planted template's ONE `verb:` line — the same-vendor edit the grounding reproduced (`alerts` ->..."""
    path = tree / TEMPLATE_REL
    text = path.read_text(encoding="utf-8")
    assert text.count("\nverb: alerts\n") == 1, "the shipped template's front matter moved"
    path.write_text(text.replace("\nverb: alerts\n", f"\nverb: {verb}\n"), encoding="utf-8")


# =========================================================================================
# O2 / O3 — a mismatch between the run's catalog and the table refuses the run at start.
# =========================================================================================

def test_a_catalog_whose_template_disagrees_with_the_table_refuses_the_run_before_anything_is_spent(tmp_path):
    """The reproduced silent burn, closed where the design puts the check."""
    tree = planted_defender(tmp_path / "ok")
    res = run(tmp_path / "ok", run_id="lz1003-ok", answer=answer_hits(ANCESTORS), defender_dir=tree)
    assert res.has_sidecar(L3), f"positive control: the planted tree did not dispatch l-00c ({res.gather_raw_names()})"
    assert res.gather is not None
    assert len(res.gather.seen) == 1, "positive control: item 3 was not dispatched"
    assert str(tree) in res.gather.seen[0], "positive control: the lead was not dispatched from the planted tree"
    assert res.budget, "positive control: the budget did not open"

    tree = _mismatched(tmp_path / "bad")
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

    # #1235 round 2: "no budget opened" has no read left — the run's budget lives on a
    # `RunState` that writes nothing and that a raising run hands back to no one. What the
    # budget would have counted (a backend call, a model turn) is read directly below.
    assert not (run_dir / "wire_logs").exists(), "the wire log opened before the check"
    assert not (run_dir / "gather_raw" / f"{L3}.lead.json").exists(), "l-00c was claimed before the check"
    assert rec.calls == [], f"a backend call was issued before the check: {rec.verbs}"
    assert main.seen == [], "MAIN was asked for a turn before the check"
    assert gather.seen == [], "the gather model was asked for a turn before the check"


def test_a_run_that_will_not_dispatch_the_lead_is_not_refused_for_its_template(tmp_path):
    """The check is gated on the SAME predicate as the dispatch."""
    from defender.tests._branch_947 import spec_at
    from defender.tests._session_store_705 import store_factory, store_mod
    from defender.tests.e2e._replay_harness import GOLDEN, _split_at_fences

    # (a) no registry injected: the K12 state, 61 of 96 `drive()` sites.
    tree = _mismatched(tmp_path / "noreg")
    res = run(tmp_path / "noreg", run_id="lz1003-noreg", verbs=None, defender_dir=tree)
    assert not res.has_sidecar(L3), "a run with no registry claimed l-00c"
    assert res.summary_dict.get("truncated_by") is None, res.summary_dict

    # (b) a resume: a real source run on this checkout, then a sibling driven over the
    # mismatched tree with a registry whose recorder catches every call lead-0 would make.
    sink: list = []
    source = run(
        tmp_path / "source", run_id="lz1003-source", answer=answer_hits(ANCESTORS),
        stores=sink, store_factory=store_factory(tmp_path, sink=sink),
        # one real call by `l-00c`: a branch needs a query that reached a system (#1222)
        gather_turns=[
            Turn(tool_calls=[("query", {"system": "elastic", "verb": "alerts",
                                        "params": {"native_query": "user.name:dev.dana"}})]),
            Turn(text=CORRELATION_SUMMARY),
        ],
        main_turns=[
            *[Turn(tool_calls=[("append_block", {"text": chunk})])
              for chunk in _split_at_fences(
                  (GOLDEN / "investigation.md").read_text(encoding="utf-8"), 7)],
            Turn(text="Holding here; the evidence is in hand and nothing is settled."),
        ],
    )
    assert source.summary_dict.get("truncated_by") is None, source.summary_dict
    store = sink[0]
    prefix_ids = store_mod().path_row_ids(store, store_mod().main_session_id(store))
    spec = spec_at(store, source.run_dir, prefix_ids[-1],
                   prompt="Continue this investigation from where it stands.")

    tree = _mismatched(tmp_path / "resumed")
    sibling_dir = materialize_alert(tmp_path / "resumed", alert_doc())
    rec = VerbRecorder()
    sibling = ReplayFn([Turn(text="Resumed and stopping.")])
    summary = drive(sibling_dir, run_id="lz1003-sibling", main=sibling, resume=spec,
                    verbs=elastic_backend(rec, answer_hits(ANCESTORS)), defender_dir=tree)
    assert summary.get("truncated_by") is None, summary
    assert sibling.seen, "the resumed run never reached its model"
    assert rec.calls == [], f"a resumed run issued a backend call: {rec.verbs}"
    # The sibling's `l-00c` sidecar is the SOURCE's, carried across with the rest of the run
    # dir (a resume inherits its artifacts) — not a claim this run made over the mismatched
    # tree: byte-identical to the source's, and the source's names the shipped id.
    sidecar = sibling_dir / "gather_raw" / f"{L3}.lead.json"
    assert sidecar.read_bytes() == (source.run_dir / "gather_raw" / f"{L3}.lead.json").read_bytes()


def test_the_config_is_read_from_the_tree_the_run_reads(tmp_path):
    """The id comes from the RUN's `lead-zero.yaml` (its tenant's, #1106), not from a process-cached read of this..."""
    from defender.runtime.lead_zero_config import LeadZeroConfigError, lead_zero_config_path
    from defender.tests import _tenants1106 as T1106
    from defender.tests.tenant_1107_settings import _spec1107 as S1107

    tree = planted_defender(tmp_path / "second")
    shipped = tree / TEMPLATE_REL
    planted_id = "elastic.correlate-alerts-by-entity-second"
    second = shipped.with_name("correlate-alerts-by-entity-second.md")
    second.write_text(
        shipped.read_text(encoding="utf-8").replace(f"id: {SHIPPED_TEMPLATE_ID}\n", f"id: {planted_id}\n", 1),
        encoding="utf-8",
    )
    # #1106: the config is the RUN's tenant's, handed in — a tenant planted outside the tree
    # whose table grants the lead `elastic.alerts` and whose config names the planted id.
    T1106.place_tenant(tmp_path / "tenants", "acme", configs=S1107.config_texts("acme"),
                       lead_zero=f"correlation_template: {planted_id}\n")
    tenant = T1106.accept(tmp_path / "tenants", "acme")
    config = lead_zero_config_path(tenant.settings)
    assert config.is_file(), "the planted tenant carries no config"
    assert not config.is_symlink(), "the config must be the tenant's own copy"

    res = run(tmp_path / "second", run_id="lz1003-second", answer=answer_hits(ANCESTORS),
              defender_dir=tree, tenant=tenant)
    assert res.has_sidecar(L3), f"the planted tree did not dispatch l-00c ({res.gather_raw_names()})"
    goal = res.sidecar(L3)["goal"]
    assert f"`{planted_id}`" in goal, goal
    assert f"`{SHIPPED_TEMPLATE_ID}`" not in goal, (
        f"the lead was told to bind the CHECKOUT's configured id, not the run tree's:\n{goal}"
    )
    assert (res.run_dir / "wire_logs").is_dir(), \
        "positive control: a run that read its config never opened its wire log"

    config.unlink()
    run_dir = materialize_alert(tmp_path / "noconfig", alert_doc())
    with pytest.raises(LeadZeroConfigError) as caught:
        drive(run_dir, run_id="lz1003-noconfig", main=ReplayFn([Turn(text="never")]),
              gather=ReplayFn([Turn(text=CORRELATION_SUMMARY)]),
              verbs=elastic_backend(VerbRecorder(), answer_hits(ANCESTORS)), defender_dir=tree,
              tenant=tenant)
    assert str(config) in str(caught.value), str(caught.value)
    # #1235 round 2: the run's budget lives on a `RunState` a raising run hands back to no
    # one, so "nothing was spent before the config was read" is read off the run dir instead.
    assert not (run_dir / "wire_logs").exists(), "the run opened its logger before the config was read"


# =========================================================================================
# O4 — the authored contract is vendor-neutral; the vendor facts live in the template.
# =========================================================================================
