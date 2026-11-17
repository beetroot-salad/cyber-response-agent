"""A model built once serves requests from one event loop after another.

The product drives agents from synchronous code through `execution.run_sync`, a fresh loop per call, and reuses
one model across those calls (the branch oracle's and verifier's agents). With one connection pool per client, a
request could take a keep-alive connection a closed loop had opened and fail with "Event loop is closed": every
other request of a branch oracle did, and two worlds of an episode lost all their retries to it.
"""
from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from defender.execution import run_sync
from defender.providers.openai_compat import OpenAICompatProvider


class _Chat(BaseHTTPRequestHandler):
    """An OpenAI-compatible chat endpoint over HTTP/1.1 keep-alive, so the client pools its connection."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *_args: object) -> None:
        pass

    def do_POST(self) -> None:  # noqa: N802 — the handler's method name is the HTTP verb
        self.rfile.read(int(self.headers["content-length"]))
        body = json.dumps({
            "id": "c", "object": "chat.completion", "created": 0, "model": "m",
            "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "ok"}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        }).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def chat_url() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Chat)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/v1"
    finally:
        server.shutdown()
        server.server_close()


def test_one_model_serves_requests_from_successive_event_loops(chat_url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    from pydantic_ai import Agent

    monkeypatch.setenv("TEST_LOOPS_KEY", "k")
    provider = OpenAICompatProvider(id="loops", base_url=chat_url, api_key_var="TEST_LOOPS_KEY", aliases={},
                                    main_effort="none", gather_effort="none", prefixes=())
    agent = Agent(provider.build_model("m"))

    answers = [run_sync(agent.run("hi")).output for _ in range(4)]   # each call is a loop of its own

    assert answers == ["ok"] * 4

