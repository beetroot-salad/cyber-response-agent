"""Lead-author streaming-layer error translation."""
from __future__ import annotations

import pytest

from defender.learning import _agent_stream, lead_author


def test_agent_stream_error_translates_to_lead_author_error(tmp_repo, monkeypatch):
    """Mirror of test_author_streaming_timeout.test_agent_stream_error_translates.

    AgentStreamError raised inside ``run_streaming`` must surface as
    ``LeadAuthorError`` so callers' existing exception handling holds.
    """

    def boom(*args, **kwargs):
        raise _agent_stream.AgentStreamError("agent failed (rc=42):\nstderr: x")

    monkeypatch.setattr(lead_author, "run_streaming", boom)
    with pytest.raises(lead_author.LeadAuthorError, match="lead-author agent failed"):
        lead_author.invoke_agent(tmp_repo.root, [])


def test_agent_stream_timeout_translates_to_lead_author_timeout(
    tmp_repo, monkeypatch
):
    monkeypatch.setattr(lead_author, "LEAD_AUTHOR_TIMEOUT", 11)

    def boom(*args, **kwargs):
        raise _agent_stream.AgentStreamError(
            "agent timed out after 11s (see /tmp/x)"
        )

    monkeypatch.setattr(lead_author, "run_streaming", boom)
    with pytest.raises(lead_author.LeadAuthorError, match="timed out after 11s"):
        lead_author.invoke_agent(tmp_repo.root, [])
