"""#1214 attack-2 helpers — NO test functions. A host actor whose OpenBao answers a chosen secret accessor at unwrap,
a `git` stub on PATH that records what a real git process is handed, and a `docker` stub that records its argv."""
from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

import httpx

from defender.tests.tenancy.lifecycle_1214._fakes import OPENBAO_URL

UNWRAP = "/v1/sys/wrapping/unwrap"


def host_answering_accessor(world: Any, accessor: str) -> None:
    """Replace the world's host actor with one whose OpenBao client reports `accessor` as the unwrapped secret's accessor
    (everything else is the world's fake OpenBao, unchanged)."""
    def handle(request: httpx.Request) -> httpx.Response:
        response = world.openbao.handle(request)
        if request.url.path == UNWRAP and response.status_code == 200:
            body = json.loads(response.content)
            body["data"]["secret_id_accessor"] = accessor
            return httpx.Response(200, json=body)
        return response

    client = httpx.AsyncClient(transport=httpx.MockTransport(handle), base_url=OPENBAO_URL)
    world.host_actor = world.new_host(world.tenants, openbao_login=client)


class GitStub:
    """A `git` executable first on PATH that records, per call, its argv, its whole environment and every file under its
    HOME (the lifecycle's scratch home), and copies what each `include.path=/dev/fd/N` argument reads to `sealed`."""

    def __init__(self, folder: Path) -> None:
        self.bin = folder / "bin"
        self.record = folder / "git-record.txt"
        self.sealed = folder / "git-sealed.txt"
        self.bin.mkdir(parents=True)
        script = self.bin / "git"
        script.write_text(
            "#!/bin/sh\n"
            f"{{ echo \"ARGV:$*\"; env; for f in $(find \"$HOME\" -type f 2>/dev/null); do echo \"FILE:$f\"; cat \"$f\"; done; }}"
            f" >> '{self.record}'\n"
            "for a in \"$@\"; do case \"$a\" in include.path=*) cat \"${a#include.path=}\" >> "
            f"'{self.sealed}' 2>/dev/null;; esac; done\n"
            "exit 0\n", encoding="utf-8")
        script.chmod(script.stat().st_mode | stat.S_IXUSR)

    def path(self) -> str:
        return f"{self.bin}{os.pathsep}{os.environ.get('PATH', '')}"

    def recorded(self) -> str:
        return self.record.read_text(encoding="utf-8") if self.record.exists() else ""

    def sealed_text(self) -> str:
        return self.sealed.read_text(encoding="utf-8") if self.sealed.exists() else ""


class DockerStub:
    """A `docker` executable first on PATH that records each call's arguments (after `docker`), one per line with an
    end marker after each call, and answers `{}`."""

    END = "--end-of-call--"

    def __init__(self, folder: Path) -> None:
        self.bin = folder / "bin"
        self.record = folder / "docker-record.txt"
        self.bin.mkdir(parents=True)
        script = self.bin / "docker"
        script.write_text(
            "#!/bin/sh\n"
            f"for a in \"$@\"; do printf '%s\\n' \"$a\"; done >> '{self.record}'\n"
            f"echo '{self.END}' >> '{self.record}'\n"
            "echo '{}'\n"
            "exit 0\n", encoding="utf-8")
        script.chmod(script.stat().st_mode | stat.S_IXUSR)

    def path(self) -> str:
        return f"{self.bin}{os.pathsep}{os.environ.get('PATH', '')}"

    def calls(self) -> list[list[str]]:
        """Each call's arguments, in order."""
        if not self.record.exists():
            return []
        calls: list[list[str]] = [[]]
        for line in self.record.read_text(encoding="utf-8").splitlines():
            if line == self.END:
                calls.append([])
            else:
                calls[-1].append(line)
        return calls[:-1]
