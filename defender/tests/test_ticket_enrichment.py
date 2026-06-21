"""Unit tests for offline enrichment: the verdict read (driver) + the idempotent,
non-fatal annotate write (writer). Transport is stubbed — no docker/network.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from defender.learning import ticket_enrichment
from defender.scripts.case_history import case_ticket, ticket_writer


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


@pytest.fixture
def stub_transport(monkeypatch):
    """Fake the writer's config + HTTP so annotate runs without docker. Returns a
    recorder dict; set `recorder['ticket']` to the GET-returned ticket."""
    rec = {"ticket": {"key": "c", "comments": []}, "posts": []}
    monkeypatch.setattr(ticket_writer, "_load_config", lambda: dict(_CONFIG))

    def fake_request(config, method, path, body=None):
        if method == "GET":
            return "200", json.dumps(rec["ticket"])
        return "201", ""

    def fake_post(config, path, body):
        rec["posts"].append((path, body))
        return "201", ""

    monkeypatch.setattr(ticket_writer, "_request", fake_request)
    monkeypatch.setattr(ticket_writer, "_post", fake_post)
    return rec


def test_annotate_posts_once_on_clean_ticket(stub_transport):
    ticket_writer.annotate_case_ticket("c", "caught")
    assert len(stub_transport["posts"]) == 1
    path, body = stub_transport["posts"][0]
    assert path.endswith("/comments")
    assert case_ticket.parse_survival_from_comments([{"body": body["body"]}]) is True


def test_annotate_idempotent_when_already_flagged(stub_transport):
    # Ticket already carries an enrichment comment → no second post.
    flagged = case_ticket.enrichment_to_comment("caught")
    stub_transport["ticket"] = {"key": "c", "comments": [{"author": "learning", **flagged}]}
    ticket_writer.annotate_case_ticket("c", "caught")
    assert stub_transport["posts"] == []


def test_annotate_non_fatal_on_404(monkeypatch):
    monkeypatch.setattr(ticket_writer, "_load_config", lambda: dict(_CONFIG))
    monkeypatch.setattr(ticket_writer, "_request",
                        lambda c, m, p, body=None: ("404", "not found"))
    posted = []
    monkeypatch.setattr(ticket_writer, "_post",
                        lambda c, p, b: posted.append(1) or ("201", ""))
    ticket_writer.annotate_case_ticket("missing", "caught")  # must not raise
    assert posted == []


def test_annotate_non_fatal_on_transport_error(monkeypatch):
    monkeypatch.setattr(ticket_writer, "_load_config", lambda: dict(_CONFIG))
    monkeypatch.setattr(ticket_writer, "_request",
                        lambda c, m, p, body=None: (None, "transport error: boom"))
    ticket_writer.annotate_case_ticket("c", "caught")  # must not raise


def test_annotate_no_config_is_noop(monkeypatch):
    monkeypatch.setattr(ticket_writer, "_load_config", lambda: None)
    # _request must never be called when config is absent.
    monkeypatch.setattr(ticket_writer, "_request",
                        lambda *a, **k: pytest.fail("called transport without config"))
    ticket_writer.annotate_case_ticket("c", "caught")
