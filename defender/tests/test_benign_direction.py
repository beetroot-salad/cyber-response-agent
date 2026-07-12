"""FP-direction loop integration: benign judge validation, direction-aware
findings append, environment-observation append, and the shared author gate."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REAL_REPO = Path(__file__).resolve().parents[2]
LEARNING_SRC = REAL_REPO / "defender" / "learning"  # source dir for file-path refs

from defender.learning.author.lessons import run as author  # type: ignore[import-not-found]
from defender.learning import loop  # type: ignore[import-not-found]
from defender.learning.author.verify_forward import forward as verify_forward  # type: ignore[import-not-found]


# --------------------------------------------------------------------------
# validate_judge_benign_doc
# --------------------------------------------------------------------------


def _valid_benign_doc() -> dict:
    return {
        "outcome": "survived",
        "outcome_rationale": "routine story consistent with all leads",
        "encounter_analysis": "lead by lead ...",
        "defender_findings": [
            {
                "type": "lead-set",
                "subject_anchor": "no-lead-exists",
                "subject_topic": "monitor-account authorization",
                "finding": "never grounded the authorization anchor",
                "citations": [],
            }
        ],
        "environment_observations": [
            {
                "subject": "monitoring-port-probe",
                "alert_rule_ids": ["v2-falco-suspicious-network-tool"],
                "entities": [
                    {"type": "process", "class": "nc"},
                    {"type": "socket", "class": "tcp"},
                ],
                "relevance_criteria": "nc -z probe from a container",
                "fact": "svc.monitoring runs the documented probe pattern",
                "citations": [],
            }
        ],
        "confidence": "moderate-high",
    }


def test_validate_benign_doc_accepts_valid() -> None:
    assert loop.validate_judge_benign_doc(_valid_benign_doc())


def test_validate_benign_doc_rejects_adversarial_outcome() -> None:
    doc = _valid_benign_doc()
    doc["outcome"] = "caught"  # adversarial enum, not benign
    with pytest.raises(loop.RunUnprocessable, match="outcome keyword"):
        loop.validate_judge_benign_doc(doc)


def test_validate_benign_doc_accepts_refuted_and_skip() -> None:
    doc = _valid_benign_doc()
    doc["outcome"] = "refuted"
    assert loop.validate_judge_benign_doc(doc)
    skip = {"outcome": "skip-passthrough", "outcome_rationale": "not ours",
            "defender_findings": []}
    assert loop.validate_judge_benign_doc(skip)


def test_validate_benign_doc_rejects_bad_finding_type() -> None:
    doc = _valid_benign_doc()
    doc["defender_findings"][0]["type"] = "detection-confirmed"  # adversarial-only
    with pytest.raises(loop.RunUnprocessable, match="not in"):
        loop.validate_judge_benign_doc(doc)


def test_validate_benign_doc_accepts_disposition_confirmed() -> None:
    doc = _valid_benign_doc()
    doc["defender_findings"][0]["type"] = "disposition-confirmed"
    assert loop.validate_judge_benign_doc(doc)


def test_validate_benign_doc_rejects_empty_rule_anchor() -> None:
    doc = _valid_benign_doc()
    doc["environment_observations"][0]["alert_rule_ids"] = []
    with pytest.raises(loop.RunUnprocessable, match="alert_rule_ids"):
        loop.validate_judge_benign_doc(doc)


def test_validate_benign_doc_rejects_malformed_entity_selector() -> None:
    doc = _valid_benign_doc()
    doc["environment_observations"][0]["entities"] = [{"type": "process"}]
    with pytest.raises(loop.RunUnprocessable, match="type, class"):
        loop.validate_judge_benign_doc(doc)


# --------------------------------------------------------------------------
# append_findings (direction-aware) + append_environment_observations
# --------------------------------------------------------------------------


@pytest.fixture
def loop_paths(tmp_path: Path) -> tuple[loop.LoopPaths, Path]:
    """Queue files isolated under tmp via an injected LoopPaths — no monkeypatching.

    The learning_run_dir resolves under paths.repo_root so the source_run_dir
    formatter's relative_to() works.
    """
    paths = loop.LoopPaths(repo_root=tmp_path)
    lrd = paths.runs_dir / "case-1"
    lrd.mkdir(parents=True)
    return paths, lrd


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_append_findings_benign_namespace_and_direction(loop_paths) -> None:
    paths, lrd = loop_paths
    doc = _valid_benign_doc()
    # add an audit-only finding that must be filtered out
    doc["defender_findings"].append({
        "type": "disposition-confirmed", "subject_anchor": "l-001",
        "subject_topic": "justified", "finding": "x", "citations": [],
    })
    n = loop.append_findings(doc, "case-1", "rule-x", lrd, direction="benign", paths=paths)
    assert n == 1  # disposition-confirmed filtered
    rows = _read_jsonl(paths.pending_file)
    assert len(rows) == 1
    assert rows[0]["finding_id"] == "case-1/benign/0"
    assert rows[0]["direction"] == "benign"
    assert rows[0]["judge_outcome"] == "survived"


def test_append_findings_adversarial_unchanged(loop_paths) -> None:
    paths, lrd = loop_paths
    doc = {
        "outcome": "survived",
        "defender_findings": [
            {"type": "lead-set", "subject_anchor": "no-lead-exists",
             "subject_topic": "t", "finding": "f", "citations": []},
            {"type": "detection-confirmed", "subject_anchor": "l-001",
             "subject_topic": "t", "finding": "f", "citations": []},
        ],
    }
    n = loop.append_findings(doc, "case-1", "rule-x", lrd, paths=paths)
    assert n == 1
    rows = _read_jsonl(paths.pending_file)
    assert rows[0]["finding_id"] == "case-1/0"  # no benign/ namespace
    assert rows[0]["direction"] == "adversarial"


def test_append_environment_observations(loop_paths) -> None:
    paths, lrd = loop_paths
    doc = _valid_benign_doc()
    # canonical key already matches the judge's anchor → stored verbatim.
    n = loop.append_environment_observations(
        doc, "case-1", "v2-falco-suspicious-network-tool", lrd, paths=paths
    )
    assert n == 1
    rows = _read_jsonl(paths.environment_observations.file)
    assert rows[0]["observation_id"] == "case-1/0"
    assert rows[0]["alert_rule_ids"] == ["v2-falco-suspicious-network-tool"]
    assert rows[0]["entities"] == [
        {"type": "process", "class": "nc"}, {"type": "socket", "class": "tcp"}]
    assert rows[0]["subject"] == "monitoring-port-probe"
    # idempotent re-append writes nothing new
    assert loop.append_environment_observations(
        doc, "case-1", "v2-falco-suspicious-network-tool", lrd, paths=paths
    ) == 0


def test_append_environment_observations_unions_canonical_key(loop_paths) -> None:
    """When the judge's free-read rule id differs from the deterministic
    alert_rule_key, the stored anchor must carry the canonical key (leading) so
    the runtime actor + forward-check — which both query by alert_rule_key —
    still retrieve the lesson for its own source case."""
    paths, lrd = loop_paths
    doc = _valid_benign_doc()
    n = loop.append_environment_observations(doc, "case-1", "rule-100110", lrd, paths=paths)
    assert n == 1
    rows = _read_jsonl(paths.environment_observations.file)
    assert rows[0]["alert_rule_ids"] == [
        "rule-100110", "v2-falco-suspicious-network-tool"]
    assert rows[0]["alert_rule_key"] == "rule-100110"


def test_anchor_with_case_key_dedups_and_normalizes() -> None:
    # canonical key already present → no duplication, order preserved.
    assert loop._anchor_with_case_key(["a", "b"], "a") == ["a", "b"]
    # absent → prepended.
    assert loop._anchor_with_case_key(["b"], "a") == ["a", "b"]
    # scalar judge value + blank entries normalized to a list of non-empty str.
    assert loop._anchor_with_case_key("b", "a") == ["a", "b"]
    assert loop._anchor_with_case_key([" ", "b"], "a") == ["a", "b"]


def test_append_environment_observations_skip_passthrough(loop_paths) -> None:
    paths, lrd = loop_paths
    doc = {"outcome": "skip-passthrough", "outcome_rationale": "x",
           "defender_findings": [], "environment_observations": []}
    assert loop.append_environment_observations(
        doc, "case-1", "rule-x", lrd, paths=paths
    ) == 0


# --------------------------------------------------------------------------
# Adversarial env stream → shared lessons-environment corpus (issue #298):
# validate_judge_doc env block + append_actor_environment_observations
# --------------------------------------------------------------------------


def _valid_adversarial_doc_with_env() -> dict:
    return {
        "outcome": "caught",
        "defender_findings": [
            {"type": "detection-confirmed", "subject_anchor": "l-002",
             "subject_topic": "outbound baseline", "finding": "f", "citations": []},
        ],
        "actor_observations": [
            {"type": "misprediction", "subject_anchor": "cover",
             "subject_topic": "443 blend", "observation": "assumed 443 blends"},
        ],
        "environment_observations": [
            {
                "subject": "jump-box-1",
                "alert_rule_ids": ["v2-falco-suspicious-network-tool"],
                "entities": [
                    {"type": "process", "class": "nc"},
                    {"type": "socket", "class": "tcp-endpoint"},
                ],
                "relevance_criteria": "outbound from jump-box-1",
                "fact": "jump-box-1 outbound baseline is ports 9200 and 22 only",
                "citations": [],
            }
        ],
    }


def test_validate_judge_doc_accepts_environment_observations() -> None:
    assert loop.validate_judge_doc(_valid_adversarial_doc_with_env())


def test_validate_judge_doc_rejects_empty_env_rule_anchor() -> None:
    doc = _valid_adversarial_doc_with_env()
    doc["environment_observations"][0]["alert_rule_ids"] = []
    with pytest.raises(loop.RunUnprocessable, match="alert_rule_ids"):
        loop.validate_judge_doc(doc)


def test_validate_judge_doc_rejects_malformed_env_selector() -> None:
    doc = _valid_adversarial_doc_with_env()
    doc["environment_observations"][0]["entities"] = [{"type": "process"}]
    with pytest.raises(loop.RunUnprocessable, match="type, class"):
        loop.validate_judge_doc(doc)


def test_append_actor_environment_observations(loop_paths) -> None:
    paths, lrd = loop_paths
    doc = _valid_adversarial_doc_with_env()
    n = loop.append_actor_environment_observations(
        doc, "case-1", "v2-falco-suspicious-network-tool", lrd, paths=paths
    )
    assert n == 1
    rows = _read_jsonl(paths.actor_environment_observations.file)
    # adv-env/ namespace prevents collision with benign env ids on the same run.
    assert rows[0]["observation_id"] == "case-1/adv-env/0"
    assert rows[0]["subject"] == "jump-box-1"
    assert rows[0]["fact"].startswith("jump-box-1 outbound baseline")
    assert rows[0]["judge_outcome"] == "caught"
    assert rows[0]["provenance"] == "adversarial"
    # carries the keys verify_forward_env.py reads.
    assert rows[0]["alert_rule_key"] == "v2-falco-suspicious-network-tool"
    assert "source_run_dir" in rows[0]
    # idempotent re-append writes nothing new.
    assert loop.append_actor_environment_observations(
        doc, "case-1", "v2-falco-suspicious-network-tool", lrd, paths=paths
    ) == 0


def test_append_actor_environment_observations_skip_passthrough(loop_paths) -> None:
    paths, lrd = loop_paths
    doc = {"outcome": "skip-passthrough", "defender_findings": [],
           "environment_observations": []}
    assert loop.append_actor_environment_observations(
        doc, "case-1", "rule-x", lrd, paths=paths
    ) == 0


def test_append_actor_environment_observations_unions_canonical_key(loop_paths) -> None:
    paths, lrd = loop_paths
    doc = _valid_adversarial_doc_with_env()
    n = loop.append_actor_environment_observations(doc, "case-1", "rule-100110", lrd, paths=paths)
    assert n == 1
    rows = _read_jsonl(paths.actor_environment_observations.file)
    assert rows[0]["alert_rule_ids"] == [
        "rule-100110", "v2-falco-suspicious-network-tool"]


def test_adversarial_and_benign_env_ids_do_not_collide(loop_paths) -> None:
    """An ``inconclusive`` case runs both directions; both env streams feed the
    one shared corpus. The ids must differ so the second drain's idempotency
    check (corpus-wide) does not swallow a genuinely distinct observation."""
    paths, lrd = loop_paths
    benign = _valid_benign_doc()
    adv = _valid_adversarial_doc_with_env()
    loop.append_environment_observations(benign, "case-1", "rule-x", lrd, paths=paths)
    loop.append_actor_environment_observations(adv, "case-1", "rule-x", lrd, paths=paths)
    benign_id = _read_jsonl(paths.environment_observations.file)[0]["observation_id"]
    adv_id = _read_jsonl(paths.actor_environment_observations.file)[0]["observation_id"]
    assert benign_id == "case-1/0"
    assert adv_id == "case-1/adv-env/0"
    assert benign_id != adv_id


# --------------------------------------------------------------------------
# author.py direction-aware ground-truth gate
# --------------------------------------------------------------------------


def test_ground_truth_gate_direction_aware() -> None:
    # adversarial finding confirmed only on a benign disposition (confident FN)
    assert author._has_confident_ground_truth("adversarial", "benign")
    assert not author._has_confident_ground_truth("adversarial", "malicious")
    # benign finding confirmed only on a malicious disposition (confident FP)
    assert author._has_confident_ground_truth("benign", "malicious")
    assert not author._has_confident_ground_truth("benign", "benign")
    # inconclusive / unknown confirm neither
    assert not author._has_confident_ground_truth("adversarial", "inconclusive")
    assert not author._has_confident_ground_truth("benign", "inconclusive")
    assert not author._has_confident_ground_truth("benign", None)


def test_verifier_expected_disposition_direction_aware() -> None:
    # Adversarial lessons must PRESERVE the recorded (benign) call — pass it
    # through. Benign (FP) lessons exist to drive the agent OFF the recorded
    # `malicious` over-escalation toward `benign`, so the verifier must target
    # `benign`, not the recorded malicious (else every FP lesson is held BAD).
    assert verify_forward.expected_disposition("adversarial", "benign") == "benign"
    assert verify_forward.expected_disposition("benign", "malicious") == "benign"
    # Direction, not the recorded value, decides the benign target.
    assert verify_forward.expected_disposition("benign", "inconclusive") == "benign"


# --------------------------------------------------------------------------
# extract_case_entities — prologue (:V) parsing for benign-actor retrieval
# --------------------------------------------------------------------------


def test_extract_case_entities_emits_qualified_class_tokens(tmp_path: Path) -> None:
    """The dense `class` column is already `type:class`-qualified; emit it
    verbatim (no double-prefix) so it matches lessons_env_retrieve selectors."""
    inv = tmp_path / "investigation.md"
    inv.write_text(
        "```invlang\n"
        ":V prologue.vertices [id|type|class|ident|attrs?]\n"
        "v-001|endpoint|endpoint:linux|web-04.prod|role=asset-server\n"
        "v-002|process|process:nc|nc[2188]|cmdline_via=shell\n"
        "v-003|socket|socket:tcp|10.20.7.118:9100|\n"
        "v-002|process|process:nc|nc[2190]|\n"  # dup type:class — de-duped
        "\n"
        ":E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]\n"
        "e-001|connected|v-002|v-003|2026-05-05T03:42:11Z|siem-event:wazuh|\n"
        "```\n"
    )
    # Each token is the retrieval's `type:class` input verbatim — a single
    # type prefix, never `process:process:nc`. Dup rows collapse.
    assert loop.extract_case_entities(inv) == "endpoint:linux,process:nc,socket:tcp"


def test_extract_case_entities_absent_block(tmp_path: Path) -> None:
    inv = tmp_path / "investigation.md"
    inv.write_text("```invlang\n:H hypothesize.hypotheses\n```\n")
    assert loop.extract_case_entities(inv) == ""
    assert loop.extract_case_entities(tmp_path / "missing.md") == ""


# --------------------------------------------------------------------------
# lessons_env_retrieve — rule anchor is required (P2-a): an empty-anchor lesson
# must match NOTHING on a rule-anchored query, not everything.
# --------------------------------------------------------------------------

import subprocess  # noqa: E402

RETRIEVE = REAL_REPO / "defender" / "scripts" / "lessons" / "lessons_env_retrieve.py"
VENV_PY = REAL_REPO / "defender" / ".venv" / "bin" / "python3"
_PY = str(VENV_PY) if VENV_PY.is_file() else sys.executable


def _write_lesson(corpus: Path, name: str, frontmatter: str, body: str = "fact.") -> Path:
    corpus.mkdir(parents=True, exist_ok=True)
    path = corpus / f"{name}.md"
    path.write_text(f"---\n{frontmatter}\n---\n\n{body}\n")
    return path


def _retrieve(corpus: Path, *args: str) -> list[str]:
    proc = subprocess.run(
        [_PY, str(RETRIEVE), "--corpus", str(corpus), *args],
        capture_output=True, text=True, check=True,
    )
    return [ln.split("\t", 1)[0] for ln in proc.stdout.splitlines() if ln.strip()]


def test_retrieve_skips_empty_anchor_on_rule_query(tmp_path: Path) -> None:
    corpus = tmp_path / "lessons-environment"
    _write_lesson(corpus, "anchored", "alert_rule_ids: [rule-100110]\nstatus: live")
    _write_lesson(corpus, "unanchored", "alert_rule_ids: []\nstatus: live")
    # Rule-anchored query: only the anchored lesson; the empty-anchor lesson
    # must NOT surface (previously it matched every rule).
    names = {Path(p).name for p in _retrieve(corpus, "--alert-rule-ids", "rule-100110")}
    assert names == {"anchored.md"}
    # A query for an unrelated rule returns nothing — the unanchored lesson
    # does not leak across rules.
    assert _retrieve(corpus, "--alert-rule-ids", "rule-9999") == []
    # Whole-corpus listing (no rule filter) is still unfiltered on this axis.
    names = {Path(p).name for p in _retrieve(corpus)}
    assert names == {"anchored.md", "unanchored.md"}


# --------------------------------------------------------------------------
# verify_forward_env — forward-check uses the source prologue + canonical key
# (P2-b / #1), not the observation's own selectors.
# --------------------------------------------------------------------------

from defender.learning.author.verify_forward import env as verify_forward_env  # type: ignore[import-not-found]  # noqa: E402


def _make_source_run(tmp_path: Path, prologue_rows: str) -> Path:
    run = tmp_path / "runs" / "case-1"
    run.mkdir(parents=True)
    (run / "investigation.md").write_text(
        "```invlang\n"
        ":V prologue.vertices [id|type|class|ident|attrs?]\n"
        f"{prologue_rows}"
        "```\n"
    )
    return run


def test_verify_env_case_entities_from_prologue_not_row(tmp_path: Path) -> None:
    """The check rebuilds case entities from the source investigation prologue,
    so a bad selector the curator copied into the observation can't self-confirm."""
    run = _make_source_run(tmp_path, "v-001|process|process:nc|nc[1]|\n")
    # Observation carries a double-prefixed selector; the prologue does not.
    row = {
        "source_run_dir": str(run) + "/",
        "entities": [{"type": "process", "class": "process:nc"}],
    }
    # source_run_dir here is ABSOLUTE, so resolve_run_bundle returns it as-is and the
    # runs_dir arg is ignored (this case exercises the absolute-passthrough branch). The
    # repo-relative/basename worktree-immune branch (#425) is covered by
    # test_verify_forward.py::test_env_case_entities_off_state_root.
    assert verify_forward_env.case_entities_arg(row, tmp_path / "runs") == "process:nc"
    # Empty / missing source → empty entities.
    assert verify_forward_env.case_entities_arg({}, tmp_path / "runs") == ""


def _run_verify_env(lesson: Path, obs_id: str, corpus: Path, pending: Path) -> str:
    """Drive the REAL environment forward-check in-process (#558 — it has no CLI any more).

    The corpus, the pending queue and the runs dir arrive on the ``CheckContext`` exactly as the
    curator's ``forward_check`` tool builds one from its deps. ``run_verify`` is never called:
    the env check is a deterministic retrieval, so it touches no model."""
    from defender.learning.author.verify_forward.checks import ENV_CHECK, CheckContext

    def _never(**_kw):  # the env check must never reach the model transport
        raise AssertionError("the deterministic env check called the verify transport")

    ctx = CheckContext(
        check=ENV_CHECK, lesson_path=lesson, lesson_text=lesson.read_text(),
        source_id=obs_id, direction="adversarial",
        runs_dir=lesson.parent, pending=pending, corpus_dir=corpus,
        repo_root=REAL_REPO, check_index=0, run_verify=_never,
    )
    return ENV_CHECK.run(ctx)


def test_verify_env_bad_when_lesson_selector_unsatisfiable(tmp_path: Path) -> None:
    """A lesson whose selector the real prologue can't satisfy → BAD, even when
    the observation row echoes the same selector (the old self-confirming bug)."""
    run = _make_source_run(tmp_path, "v-001|process|process:nc|nc[1]|\n")
    corpus = tmp_path / "lessons-environment"
    pending = tmp_path / "env.jsonl"
    obs = {
        "observation_id": "case-1/0",
        "alert_rule_key": "rule-100110",
        "alert_rule_ids": ["rule-100110"],
        "entities": [{"type": "process", "class": "process:nc"}],  # double-prefixed
        "source_run_dir": str(run) + "/",
    }
    pending.write_text(json.dumps(obs) + "\n")
    # Mis-keyed lesson (selector echoes the bad observation selector).
    bad = _write_lesson(
        corpus, "bad",
        "alert_rule_ids: [rule-100110]\nstatus: live\n"
        "entities:\n  - {type: process, class: process:nc}",
    )
    assert _run_verify_env(bad, "case-1/0", corpus, pending) == "BAD"
    # Correctly-keyed lesson (class matches the prologue's `nc`) → GOOD.
    good = _write_lesson(
        corpus, "good",
        "alert_rule_ids: [rule-100110]\nstatus: live\n"
        "entities:\n  - {type: process, class: nc}",
    )
    assert _run_verify_env(good, "case-1/0", corpus, pending) == "GOOD"


def test_verify_env_bad_when_rule_anchor_missing_canonical_key(tmp_path: Path) -> None:
    """The check queries by the canonical alert_rule_key; a lesson anchored only
    on the judge's divergent rule id (missing the canonical key) → BAD."""
    run = _make_source_run(tmp_path, "v-001|process|process:nc|nc[1]|\n")
    corpus = tmp_path / "lessons-environment"
    pending = tmp_path / "env.jsonl"
    obs = {
        "observation_id": "case-1/0",
        "alert_rule_key": "rule-100110",
        "entities": [{"type": "process", "class": "nc"}],
        "source_run_dir": str(run) + "/",
    }
    pending.write_text(json.dumps(obs) + "\n")
    lesson = _write_lesson(
        corpus, "wrong-anchor",
        "alert_rule_ids: [some-other-rule]\nstatus: live\n"
        "entities:\n  - {type: process, class: nc}",
    )
    assert _run_verify_env(lesson, "case-1/0", corpus, pending) == "BAD"


# --------------------------------------------------------------------------
# resolution_method (#338): adversarial judge doc validation
# --------------------------------------------------------------------------


def test_validate_judge_doc_accepts_resolution_method() -> None:
    doc = _valid_adversarial_doc_with_env()
    doc["resolution_method"] = "identity-confirmed (l-002) + no-egress (l-005); authority: CISO"
    assert loop.validate_judge_doc(doc)


def test_validate_judge_doc_optional_resolution_method() -> None:
    # Absent key is fine (emitted only on benign dispositions).
    doc = _valid_adversarial_doc_with_env()
    doc.pop("resolution_method", None)
    assert loop.validate_judge_doc(doc)


def test_validate_judge_doc_rejects_empty_resolution_method() -> None:
    doc = _valid_adversarial_doc_with_env()
    doc["resolution_method"] = "   "
    with pytest.raises(loop.RunUnprocessable, match="resolution_method"):
        loop.validate_judge_doc(doc)


def test_validate_judge_doc_rejects_non_string_resolution_method() -> None:
    doc = _valid_adversarial_doc_with_env()
    doc["resolution_method"] = ["a", "b"]
    with pytest.raises(loop.RunUnprocessable, match="resolution_method"):
        loop.validate_judge_doc(doc)


# --------------------------------------------------------------------------
# Benign judge scoped closed-ticket read (#338): settings surface + injection
# --------------------------------------------------------------------------


def test_wiring_closed_ticket_read_flag() -> None:
    from defender.learning.core.directions import ADVERSARIAL, BENIGN
    assert BENIGN.judge_wiring.closed_ticket_read is True
    assert ADVERSARIAL.judge_wiring.closed_ticket_read is False


def test_build_judge_invocation_benign_injects_scoped_read(tmp_path: Path) -> None:
    from defender.learning.pipeline.judge import run as su
    run_dir = tmp_path / "20260620T0000Z-sshd"
    (run_dir / "gather_raw").mkdir(parents=True)
    (run_dir / "alert.json").write_text(
        json.dumps({"rule": {"id": "5710", "description": "x"}, "timestamp": "2026-06-01T00:00:00+00:00"})
    )
    story = run_dir / "actor_benign_story.md"
    story.write_text("1. Routine story\nciting case-OLD as covering policy\n")
    telem = run_dir / "projected_telemetry_benign.yaml"
    telem.write_text("projections: []\n")
    lrd = tmp_path / "learn" / run_dir.name
    lrd.mkdir(parents=True)
    (lrd / "past_tickets.txt").write_text("- case-OLD: benign — nightly scan\n")

    inv = su.build_judge_invocation(
        run_dir, story, telem, lrd,
        comparison_dirname="comparison_benign",
        closed_ticket_read=True,
    )
    # The injected section names the closed-only read, the in-flight key, and the menu.
    assert "<cited_policy_read>" in inv.user_text
    assert "--require-closed" in inv.user_text
    assert run_dir.name in inv.user_text          # the in-flight key it must never read
    assert "case-OLD" in inv.user_text            # candidate closed case from the menu
    # The scoped closed-ticket pins ride on the invocation → the in-process judge builds
    # its closed-only bash grant from them (see engine_pydantic._ticket_grant).
    assert inv.ticket_cli is not None


def test_build_judge_invocation_adversarial_has_no_ticket_read(tmp_path: Path) -> None:
    from defender.learning.pipeline.judge import run as su
    run_dir = tmp_path / "case-adv"
    (run_dir / "gather_raw").mkdir(parents=True)
    (run_dir / "alert.json").write_text(json.dumps({"rule": {"id": "5710"}}))
    story = run_dir / "actor_story.md"
    story.write_text("Attack story\n")
    telem = run_dir / "projected_telemetry.yaml"
    telem.write_text("projections: []\n")
    lrd = tmp_path / "learn2" / run_dir.name
    lrd.mkdir(parents=True)

    inv = su.build_judge_invocation(run_dir, story, telem, lrd)  # defaults: adversarial
    assert "cited_policy_read" not in inv.user_text
    assert inv.ticket_cli is None                  # no closed-ticket read on the adversarial leg
