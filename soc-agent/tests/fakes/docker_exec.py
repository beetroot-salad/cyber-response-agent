"""In-memory replacement for `host_query.docker_exec`.

`docker_exec(host, argv) -> (output, returncode)` is the docker boundary that
the host-query CLI's tests would otherwise mock. This fake records every call
and returns a canned (output, returncode) so tests can assert on argv shape and
host routing without a docker daemon.

Install via `monkeypatch.setattr(host_query, "docker_exec", fake)`.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class FakeDockerExec:
    output: str = ""
    returncode: int = 0
    calls: list[tuple[str, list[str]]] = field(default_factory=list)

    def __call__(self, host: str, argv: list[str]) -> tuple[str, int]:
        self.calls.append((host, list(argv)))
        return self.output, self.returncode

    @property
    def called(self) -> bool:
        return bool(self.calls)

    @property
    def last(self) -> tuple[str, list[str]]:
        if not self.calls:
            raise AssertionError("FakeDockerExec: no calls recorded yet")
        return self.calls[-1]
