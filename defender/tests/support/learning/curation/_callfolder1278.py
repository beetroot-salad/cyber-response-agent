"""#1278 A1 machinery: a model on the wire for the three curators, and what the drain left behind.

`WireModel` is an Anthropic-compatible endpoint on 127.0.0.1 (`ANTHROPIC_BASE_URL`, precedent
`tests/runtime/providers/_spec1243.py`): the real stage code runs unmodified up to the HTTP call,
so what a curator's model is shown (the system prompt, the roots line) and what its tools answer
are read off the requests it receives. Nothing here implements policy under test.
"""
from __future__ import annotations

import json
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

#: A curator ends on this; the marker is the lessons and questioner curators' return contract.
AUTHOR_RESULT = 'AUTHOR_RESULT: {"committed": [], "consumed_skip": [], "commit_message": "noop"}'
#: The wire model every drain-level A1 case sets for the three curators' model knobs.
MODEL = "claude-sonnet-4-5"
MODEL_ENV = ("LEARNING_AUTHOR_MODEL", "LEAD_AUTHOR_MODEL")
#: The tools a curator's model can read with: the lessons curators' `lesson_read`, the lead
#: author's `read_file`.
READ_TOOLS = ("read_file", "lesson_read")


@dataclass
class Conversation:
    """One curator call as the wire saw it: its requests in order."""

    requests: list[dict[str, Any]] = field(default_factory=list)

    @property
    def system(self) -> str:
        system = self.requests[0].get("system", "")
        if isinstance(system, list):
            return "\n".join(str(b.get("text", "")) for b in system)
        return str(system)

    @property
    def first_user(self) -> str:
        return json.dumps(self.requests[0].get("messages"))

    def seen(self) -> str:
        """Everything the model was ever shown in this call."""
        return json.dumps(self.requests, ensure_ascii=False)

    def answers(self) -> str:
        """The tool results the model got back: every request after the first carries them."""
        return json.dumps([r.get("messages") for r in self.requests[1:]], ensure_ascii=False)

    def roots_line(self) -> str:
        """The harness preamble's `Workspace roots:` line (`_pydantic_stage.build_stage_agent`)."""
        for line in self.system.splitlines():
            if line.startswith("Workspace roots:"):
                return line
        return ""


def _tool_use(call_id: str, tool: str, path: str) -> dict[str, Any]:
    return {"type": "tool_use", "id": call_id, "name": tool, "input": {"path": path}}


def _message(content: list[dict[str, Any]], stop: str) -> dict[str, Any]:
    return {"id": "msg_1278", "type": "message", "role": "assistant", "model": MODEL, "content": content,
            "stop_reason": stop, "stop_sequence": None,
            "usage": {"input_tokens": 1, "output_tokens": 1}}


class WireModel:
    """The model behind `ANTHROPIC_BASE_URL`. Each call (a conversation, told apart by its first
    user message) first reads every path `attacks(conversation_so_far)` names, with the tool its
    request offers, and then ends with `final`. With `fail`, every request is still recorded and answered with
    that HTTP status instead. A context manager; `url` is the base URL."""

    def __init__(self, attacks: Callable[[Conversation], Iterable[str]] = lambda _c: (),
                 final: str = AUTHOR_RESULT, fail: int | None = None) -> None:
        self.calls: list[Conversation] = []
        self._by_user: dict[str, Conversation] = {}
        self._lock = threading.Lock()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 — the stdlib's name
                body = json.loads(self.rfile.read(int(self.headers.get("content-length") or 0)) or b"{}")
                with owner._lock:
                    answer = owner._answer(body, attacks, final)
                status = 200
                if fail is not None:
                    status, answer = fail, {"type": "error", "error": {"type": "invalid_request_error", "message": "refused"}}
                payload = json.dumps(answer).encode("utf-8")
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_a: Any) -> None:
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def _answer(self, body: dict[str, Any], attacks: Callable[[Conversation], Iterable[str]],
                final: str) -> dict[str, Any]:
        first = json.dumps(body["messages"][0], ensure_ascii=False)
        conversation = self._by_user.get(first)
        if conversation is None:
            conversation = self._by_user[first] = Conversation()
            self.calls.append(conversation)
        conversation.requests.append(body)
        if len(body["messages"]) > 1:
            return _message([{"type": "text", "text": final}], "end_turn")
        tools = [t["name"] for t in body.get("tools", [])]
        reader = next((t for t in READ_TOOLS if t in tools), None)
        paths = list(attacks(conversation)) if reader else []
        if not paths:
            return _message([{"type": "text", "text": final}], "end_turn")
        return _message([_tool_use(f"toolu_{i}", reader, p) for i, p in enumerate(paths)], "tool_use")

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def __enter__(self) -> WireModel:
        self._thread.start()
        return self

    def __exit__(self, *_exc: Any) -> None:
        self._server.shutdown()
        self._server.server_close()


def files_below(root: Path) -> list[Path]:
    """Every regular file under `root`, deepest included; nothing when it does not exist."""
    return sorted(p for p in root.rglob("*") if p.is_file()) if root.is_dir() else []
