"""Unit tests for offline enrichment: the verdict read (driver) + the idempotent,
non-fatal annotate write (writer). Transport is stubbed — no docker/network.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from defender.learning import ticket_enrichment
from defender.scripts.case_history import case_ticket, ticket_writer
from defender.scripts.case_history.ticket_writer import TicketWriterDeps


# ---------------------------------------------------------------------------
# Driver: read the adversarial outcome from judge_findings.yaml
# ---------------------------------------------------------------------------


def _write_verdict(lrd: Path, outcome: str) -> None:
    lrd.joinpath("judge_findings.yaml").write_text(
        f"outcome: {outcome}\ndefender_findings: []\n"
    )


def test_read_outcome_valid(tmp_path: Path):
    _write_verdict(tmp_path, "caught")
    assert ticket_enrichment._read_adversarial_outcome(tmp_path) == "caught"


def test_read_outcome_tolerates_trailing_rationale(tmp_path: Path):
    # The judge sometimes fuses the keyword with a clause; the loop's parser
    # takes the head token.
    tmp_path.joinpath("judge_findings.yaml").write_text(
        "outcome: caught. The investigation refuted the story.\ndefender_findings: []\n"
    )
    assert ticket_enrichment._read_adversarial_outcome(tmp_path) == "caught"


def test_read_outcome_missing_file_is_none(tmp_path: Path):
    assert ticket_enrichment._read_adversarial_outcome(tmp_path) is None


def test_read_outcome_malformed_is_none(tmp_path: Path):
    tmp_path.joinpath("judge_findings.yaml").write_text("outcome: not-a-real-keyword\n")
    assert ticket_enrichment._read_adversarial_outcome(tmp_path) is None


@pytest.mark.parametrize("body", ["just a string\n", "- a\n- b\n", "42\n"])
def test_read_outcome_non_mapping_is_none(tmp_path: Path, body: str):
    # A verdict that parses to a non-dict (scalar/list) must be a WARN+None, not an
    # uncaught AttributeError on .get() that would crash run_one before enqueue.
    tmp_path.joinpath("judge_findings.yaml").write_text(body)
    assert ticket_enrichment._read_adversarial_outcome(tmp_path) is None


def test_enrich_skips_when_no_verdict(tmp_path: Path, monkeypatch):
    calls = []
    monkeypatch.setattr(ticket_enrichment, "annotate_case_ticket",
                        lambda key, outcome: calls.append((key, outcome)))
    ticket_enrichment.enrich_case_ticket(tmp_path / "run-1", tmp_path)
    assert calls == []  # no verdict file → no write attempted


def test_enrich_delegates_outcome_keyed_on_run_dir_name(tmp_path: Path, monkeypatch):
    lrd = tmp_path / "learn"
    lrd.mkdir()
    _write_verdict(lrd, "survived")
    calls = []
    monkeypatch.setattr(ticket_enrichment, "annotate_case_ticket",
                        lambda key, outcome: calls.append((key, outcome)))
    ticket_enrichment.enrich_case_ticket(tmp_path / "20260620-case", lrd)
    assert calls == [("20260620-case", "survived")]  # key is the run-dir basename


# ---------------------------------------------------------------------------
# Writer: annotate_case_ticket — GET-then-check idempotency, non-fatal
# ---------------------------------------------------------------------------


_CONFIG = {"URL_BASE": "http://x:8080", "BASTION_HOST": "web-1", "TIMEOUT_SEC": "10"}


def _deps(request, load_config=None) -> TicketWriterDeps:
    """Writer deps with a fake transport; config defaults to the canned `_CONFIG`
    (pass `load_config=lambda: None` to exercise the missing-config path). Mirrors
    the `_deps(**overrides)` test idiom in test_lead_author.py."""
    return TicketWriterDeps(
        load_config=load_config if load_config is not None else (lambda: dict(_CONFIG)),
        request=request,
    )


def _request_404(c, m, p, body=None):
    """GET → 404; any POST fails the test (the writer must not write after a 404)."""
    if m == "POST":
        pytest.fail("posted after 404")
    return "404", "not found"


@pytest.fixture
def stub_transport():
    """Build a writer deps whose config + HTTP are faked so annotate/enrich run
    without docker. Returns a recorder dict: set `recorder['ticket']` to the
    GET-returned ticket, read POSTs off `recorder['posts']`, and pass
    `recorder['deps']` as the entrypoint's `deps=`."""
    rec = {"ticket": {"key": "c", "comments": []}, "posts": []}

    def fake_request(config, method, path, body=None):
        if method == "GET":
            return "200", json.dumps(rec["ticket"])
        rec["posts"].append((path, body))  # POST (and any non-GET) is a write
        return "201", ""

    rec["deps"] = _deps(fake_request)
    return rec


def test_annotate_posts_once_on_clean_ticket(stub_transport):
    ticket_writer.annotate_case_ticket("c", "caught", deps=stub_transport["deps"])
    assert len(stub_transport["posts"]) == 1
    path, body = stub_transport["posts"][0]
    assert path.endswith("/comments")
    assert case_ticket.parse_survival_from_comments([{"body": body["body"]}]) is True


def test_annotate_idempotent_when_already_flagged(stub_transport):
    # Ticket already carries an enrichment comment → no second post.
    flagged = case_ticket.enrichment_to_comment("caught")
    stub_transport["ticket"] = {"key": "c", "comments": [{"author": "learning", **flagged}]}
    ticket_writer.annotate_case_ticket("c", "caught", deps=stub_transport["deps"])
    assert stub_transport["posts"] == []


def test_annotate_non_fatal_on_404():
    ticket_writer.annotate_case_ticket("missing", "caught", deps=_deps(_request_404))  # must not raise


def test_annotate_non_fatal_on_transport_error():
    deps = _deps(lambda c, m, p, body=None: (None, "transport error: boom"))
    ticket_writer.annotate_case_ticket("c", "caught", deps=deps)  # must not raise


def test_annotate_no_config_is_noop():
    # request must never be called when config is absent.
    deps = _deps(lambda *a, **k: pytest.fail("called transport without config"),
                 load_config=lambda: None)
    ticket_writer.annotate_case_ticket("c", "caught", deps=deps)


# ---------------------------------------------------------------------------
# Driver: read resolution_method + delegate (issue #338)
# ---------------------------------------------------------------------------


def _write_verdict_with_method(lrd: Path, outcome: str, method: str) -> None:
    lrd.joinpath("judge_findings.yaml").write_text(
        f"outcome: {outcome}\ndefender_findings: []\nresolution_method: {method}\n"
    )


def test_read_resolution_method_valid(tmp_path: Path):
    _write_verdict_with_method(tmp_path, "caught", "identity-confirmed (l-002)")
    assert ticket_enrichment._read_resolution_method(tmp_path) == "identity-confirmed (l-002)"


def test_read_resolution_method_absent_is_none(tmp_path: Path):
    _write_verdict(tmp_path, "caught")  # no resolution_method key
    assert ticket_enrichment._read_resolution_method(tmp_path) is None


def test_read_resolution_method_missing_file_is_none(tmp_path: Path):
    assert ticket_enrichment._read_resolution_method(tmp_path) is None


def test_read_resolution_method_non_string_is_none(tmp_path: Path):
    tmp_path.joinpath("judge_findings.yaml").write_text(
        "outcome: caught\ndefender_findings: []\nresolution_method:\n  - a\n  - b\n"
    )
    assert ticket_enrichment._read_resolution_method(tmp_path) is None


def test_enrich_delegates_resolution_method_when_present(tmp_path: Path, monkeypatch):
    lrd = tmp_path / "learn"
    lrd.mkdir()
    _write_verdict_with_method(lrd, "caught", "no-egress (l-005)")
    seen = []
    monkeypatch.setattr(ticket_enrichment, "annotate_case_ticket",
                        lambda key, outcome: seen.append(("annotate", key, outcome)))
    monkeypatch.setattr(ticket_enrichment, "enrich_case_resolution",
                        lambda key, method: seen.append(("resolution", key, method)))
    ticket_enrichment.enrich_case_ticket(tmp_path / "case-9", lrd)
    assert seen == [
        ("annotate", "case-9", "caught"),
        ("resolution", "case-9", "no-egress (l-005)"),
    ]


def test_enrich_skips_resolution_method_when_absent(tmp_path: Path, monkeypatch):
    lrd = tmp_path / "learn"
    lrd.mkdir()
    _write_verdict(lrd, "caught")  # outcome only, no resolution_method
    seen = []
    monkeypatch.setattr(ticket_enrichment, "annotate_case_ticket",
                        lambda key, outcome: seen.append("annotate"))
    monkeypatch.setattr(ticket_enrichment, "enrich_case_resolution",
                        lambda key, method: pytest.fail("called without a method"))
    ticket_enrichment.enrich_case_ticket(tmp_path / "case-9", lrd)
    assert seen == ["annotate"]


def test_enrich_skips_resolution_method_when_outcome_not_seed_eligible(tmp_path: Path, monkeypatch):
    # A method present but a non-seed-eligible outcome (`survived` = flagged FN) must NOT
    # stamp a covering policy: the resolution-method rides the seed-eligibility polarity,
    # so the store never carries a benign covering policy on a case the probe contested.
    lrd = tmp_path / "learn"
    lrd.mkdir()
    _write_verdict_with_method(lrd, "survived", "no-egress (l-005)")
    seen = []
    monkeypatch.setattr(ticket_enrichment, "annotate_case_ticket",
                        lambda key, outcome: seen.append("annotate"))
    monkeypatch.setattr(ticket_enrichment, "enrich_case_resolution",
                        lambda key, method: pytest.fail("stamped a policy on a survived case"))
    ticket_enrichment.enrich_case_ticket(tmp_path / "case-9", lrd)
    assert seen == ["annotate"]


# ---------------------------------------------------------------------------
# Writer: enrich_case_resolution — GET-then-append transition, idempotent
# ---------------------------------------------------------------------------


_GROUNDED_METHOD = "identity-confirmed (l-002) + no-egress (l-005)"


def test_enrich_resolution_posts_transition_on_ungrounded(stub_transport):
    stub_transport["ticket"] = {"key": "c", "resolution": "benign — routine", "comments": []}
    ticket_writer.enrich_case_resolution("c", _GROUNDED_METHOD, deps=stub_transport["deps"])
    assert len(stub_transport["posts"]) == 1
    path, body = stub_transport["posts"][0]
    assert path.endswith("/transitions")
    assert body["status"] == "closed"
    # The new resolution preserves disposition/reason and carries the grounded method.
    assert case_ticket.ticket_disposition({"resolution": body["resolution"]}) == "benign"
    assert case_ticket.resolution_method_from_resolution(body["resolution"]) == _GROUNDED_METHOD


def test_enrich_resolution_idempotent_when_already_grounded(stub_transport):
    grounded = case_ticket.append_resolution_method("benign — routine", _GROUNDED_METHOD)
    stub_transport["ticket"] = {"key": "c", "resolution": grounded, "comments": []}
    ticket_writer.enrich_case_resolution("c", "different (l-009)", deps=stub_transport["deps"])
    assert stub_transport["posts"] == []  # already grounded → no write


def test_enrich_resolution_skips_foreign_resolution(stub_transport):
    stub_transport["ticket"] = {"key": "c", "resolution": "Closed by analyst.", "comments": []}
    ticket_writer.enrich_case_resolution("c", _GROUNDED_METHOD, deps=stub_transport["deps"])
    assert stub_transport["posts"] == []  # not our close resolution → untouched


def test_enrich_resolution_noop_on_empty_method(stub_transport):
    ticket_writer.enrich_case_resolution("c", "", deps=stub_transport["deps"])
    assert stub_transport["posts"] == []


def test_enrich_resolution_non_fatal_on_404():
    deps = _deps(_request_404)
    ticket_writer.enrich_case_resolution("missing", _GROUNDED_METHOD, deps=deps)  # must not raise


def test_enrich_resolution_no_config_is_noop():
    deps = _deps(lambda *a, **k: pytest.fail("transport without config"),
                 load_config=lambda: None)
    ticket_writer.enrich_case_resolution("c", _GROUNDED_METHOD, deps=deps)
