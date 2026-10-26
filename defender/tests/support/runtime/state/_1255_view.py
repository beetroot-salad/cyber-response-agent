"""Independent model-path literals, host layouts, argv recording, and model response observations."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import os
import re
import subprocess
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from defender.records import RUN_LAYOUT
from defender.tests.support.shared._fixture_uuid import fixture_uuid

DEFENDER = Path(__file__).resolve().parents[4]
REPO_ROOT = DEFENDER.parent

MODEL_RUN = "/runs/current"
MODEL_RUNS = "/runs"
MODEL_DEFENDER = "/defender"
MODEL_AGENT = "/agent"
MODEL_ROOTS = (MODEL_RUN, MODEL_DEFENDER, MODEL_AGENT)
MODEL_ALERT = f"{MODEL_RUN}/{RUN_LAYOUT.alert_input_dir}/alert.json"
MODEL_ENV = {
    "DEFENDER_RUN_DIR": MODEL_RUN,
    "DEFENDER_RUNS_BASE": MODEL_RUNS,
    "DEFENDER_DIR": MODEL_DEFENDER,
    "DEFENDER_AGENT_DIR": MODEL_AGENT,
}

TENANT_A = fixture_uuid("tenant:tnt-qzv7a")
TENANT_B = fixture_uuid("tenant:orgx-kw3b")
STATIC_ROOTFS = "python:3.11-slim"


def under_model_root(value: str) -> bool:
    """Whether `value` is one of the three model roots or a path below one."""
    return any(value == root or value.startswith(root + "/") for root in MODEL_ROOTS)


def model_path(host: Path | str, *, run_dir: Path | str, defender_dir: Path | str = DEFENDER,
               agent: Path | str | None = None) -> str:
    """Map lexical host paths using independent model-root literals; refuse paths outside the three trees."""
    p = Path(str(host))
    roots = [(Path(str(r)), m) for r, m in ((run_dir, MODEL_RUN), (defender_dir, MODEL_DEFENDER),
                                            (agent, MODEL_AGENT)) if r is not None]
    for root, model in sorted(roots, key=lambda rm: len(rm[0].parts), reverse=True):
        try:
            rel = p.relative_to(root)
        except ValueError:
            continue
        return model if rel == Path(".") else f"{model}/{rel.as_posix()}"
    raise ValueError(f"{host} lies under none of the model view's three trees")


@dataclass(frozen=True)
class Layout:
    """Hold the data root, accepted tenant, and checkout for one host layout."""

    data_root: Path
    tenant_id: str
    tenant: Any
    checkout: Path

    @property
    def agent(self) -> Path:
        return Path(self.tenant.agent)

    def staged(self) -> tuple[Path, Path]:
        """The tenant's agent half staged as a run copy (`stage/agent`, its token), under this
        layout's data root: what a run box is started over. One per layout, so every box a test
        starts for it binds the same copy."""
        from defender.tests.support.tenancy._run_copy_stage import staged_agent

        if self.data_root not in _STAGED:
            _STAGED[self.data_root] = staged_agent(self.agent, self.data_root / "run-copies")
        return _STAGED[self.data_root]


#: Each layout's one staged run copy, by its (per-test, unique) data root.
_STAGED: dict[Path, tuple[Path, Path]] = {}


def mirror_checkout(root: Path, *, own_lessons: bool = False) -> Path:
    """Create a symlink mirror with an optional private lessons folder."""
    tree = Path(root) / "defender"
    tree.mkdir(parents=True)
    for entry in DEFENDER.iterdir():
        if entry.name in {".venv", "__pycache__"} or (own_lessons and entry.name == "lessons"):
            continue
        (tree / entry.name).symlink_to(entry)
    if own_lessons:
        (tree / "lessons").mkdir()
    return tree


def make_layout(base: Path, tenant_id: str, *, checkout: Path | None = None) -> Layout:
    """Set up a fixture tenant under a distinct nested data root."""
    from defender.tests.support.shared.contracts import _data_root_1078

    data_root = Path(base) / f"host-{tenant_id}" / "data"
    data_root.mkdir(parents=True)
    tenant = _data_root_1078.set_up_tenant(data_root, tenant_id)
    return Layout(data_root=data_root, tenant_id=tenant_id, tenant=tenant,
                  checkout=Path(checkout) if checkout is not None else DEFENDER)


def natural_run(layout: Layout, alert_bytes: bytes, label: str) -> Path:
    """Materialize a natural run through its tenant's runs repository. #1279 (A3): setup mints
    the run id; `label` only names the staged alert file."""
    from defender import run_common

    staged = location_path(layout.data_root).parent / f"alert-{label}.json"
    staged.write_bytes(alert_bytes)
    run = run_common.materialize_run(staged, tenant=layout.tenant)
    return Path(run.run_dir)


def host_tokens(*layouts: Layout, extra: Iterable[Path | str] = ()) -> list[str]:
    """Return host-layout tokens, longest first, for model-visible leak detection."""
    tokens: set[str] = {str(REPO_ROOT), str(DEFENDER)}
    for layout in layouts:
        tokens |= {str(location_path(layout.data_root)), str(location_path(layout.data_root).resolve()), layout.tenant_id,
                   str(layout.checkout), str(layout.checkout.resolve()),
                   str(layout.checkout.parent)}
    home = os.path.expanduser("~")
    if home not in ("", "/"):
        tokens.add(home)
    tokens |= {str(e) for e in extra}
    return sorted((t for t in tokens if t and t != "/"), key=len, reverse=True)


def _token_re(token: str) -> re.Pattern[str]:
    """A path token matches as a path (not inside a longer name); a bare name (a tenant id) matches as a word."""
    return re.compile(r"(?<![\w.-])" + re.escape(token) + r"(?![\w.-])"
                      if not token.startswith("/") else
                      re.escape(token) + r"(?![\w.-])")


def scan(text: str, tokens: Sequence[str]) -> list[str]:
    """The host tokens `text` carries, each with a little context. Empty means none."""
    hits: list[str] = []
    for token in tokens:
        for m in _token_re(token).finditer(text):
            lo, hi = max(0, m.start() - 40), min(len(text), m.end() + 40)
            hits.append(f"{token!r} in …{text[lo:hi]!r}…")
    return hits


class FakeDocker:
    """`DockerFn` that records every argv."""

    CREATE_REFUSAL = "refused by the #1255 static check\n"

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], **_kw: object) -> subprocess.CompletedProcess:
        argv = list(argv)
        self.calls.append(argv)
        if argv[:3] == ["docker", "run", "--detach"]:
            return subprocess.CompletedProcess(argv, 1, "", self.CREATE_REFUSAL)
        if argv[:3] == ["docker", "image", "inspect"]:
            return subprocess.CompletedProcess(argv, 0, "sha256:0\n", "")
        if argv[:2] == ["docker", "version"]:
            return subprocess.CompletedProcess(argv, 0, "29.0.0\n", "")
        return subprocess.CompletedProcess(argv, 1, "", "Error: No such object\n")

    @property
    def create(self) -> list[str]:
        creates = [c for c in self.calls if c[:3] == ["docker", "run", "--detach"]]
        assert len(creates) == 1, f"expected exactly one create, saw {len(creates)}: {self.calls}"
        return creates[0]


@dataclass
class Create:
    """A `docker run` argv read back into its parts."""

    argv: list[str]
    name: str = ""
    workdir: str = ""
    env: dict[str, str] = field(default_factory=dict)
    mounts: list[tuple[str, str, bool]] = field(default_factory=list)

    def target_of(self, source: Path | str) -> str | None:
        """The target the mount whose source is `source` lands at, or None."""
        hits = [t for s, t, _ in self.mounts if s == str(source)]
        assert len(hits) <= 1, f"{source} is mounted twice: {self.mounts}"
        return hits[0] if hits else None

    def readonly_of(self, source: Path | str) -> bool:
        return next(ro for s, _, ro in self.mounts if s == str(source))


def parse_create(argv: Sequence[str]) -> Create:
    out = Create(argv=list(argv))
    for i, tok in enumerate(argv):
        nxt = argv[i + 1] if i + 1 < len(argv) else ""
        if tok == "--name":
            out.name = nxt
        elif tok == "--workdir":
            out.workdir = nxt
        elif tok == "--env":
            k, _, v = nxt.partition("=")
            assert k not in out.env, f"env key {k} set twice on the create"
            out.env[k] = v
        elif tok == "--mount":
            fields_ = dict(f.partition("=")[::2] for f in nxt.split(",") if "=" in f)
            readonly = "readonly" in nxt.split(",")
            out.mounts.append((fields_.get("source", ""), fields_.get("target", ""), readonly))
    return out


_SOURCE_RE = re.compile(r"(?<=source=)[^,]*")
_TOKEN_LABEL_RE = re.compile(r"^(defender\.start-token=).*$")
_SECCOMP_RE = re.compile(r"^(seccomp=).*$")


def masked_create(argv: Sequence[str]) -> list[str]:
    """Mask only daemon-owned sources, seccomp path, container name, and start token."""
    out: list[str] = []
    for i, tok in enumerate(argv):
        prev = argv[i - 1] if i else ""
        if prev == "--name":
            tok = "<NAME>"
        elif prev == "--label":
            tok = _TOKEN_LABEL_RE.sub(r"\1<TOKEN>", tok)
        elif prev == "--security-opt":
            tok = _SECCOMP_RE.sub(r"\1<PROFILE>", tok)
        elif prev == "--mount":
            tok = _SOURCE_RE.sub("<SOURCE>", tok)
        out.append(tok)
    return out


class Recorder:
    """Record full message objects while replaying scripted turns."""

    __name__ = "Recorder"

    def __init__(self, turns: list[Any], *,
                 before: dict[int, Callable[[], None]] | None = None) -> None:
        from defender.tests.e2e._replay_harness import ReplayFn

        self._replay = ReplayFn(turns)
        self._before = dict(before) if before is not None else {}
        self.requests: list[list[Any]] = []

    @property
    def calls(self) -> int:
        return self._replay.calls

    def __call__(self, messages, info):
        hook = self._before.get(len(self.requests))
        self.requests.append(list(messages))
        if hook is not None:
            hook()
        return self._replay(messages, info)

    def first_user_text(self) -> str:
        """Message 0's user prompt text (the opening prompt)."""
        from pydantic_ai.messages import UserPromptPart

        for part in self.requests[0][0].parts:
            if isinstance(part, UserPromptPart):
                return part.content if isinstance(part.content, str) else str(part.content)
        raise AssertionError("the first request carries no user prompt")

    def answer_to(self, request_index: int) -> tuple[str, str]:
        """Return the tool result or retry from the preceding scripted response."""
        from pydantic_ai.messages import RetryPromptPart, ToolReturnPart

        last = self.requests[request_index][-1]
        returns = [p for p in last.parts if isinstance(p, ToolReturnPart)]
        retries = [p for p in last.parts if isinstance(p, RetryPromptPart)]
        assert len(returns) + len(retries) == 1, (
            f"request {request_index} carries {len(returns)} returns and {len(retries)} retries; "
            "a scenario here answers one call per turn")
        if returns:
            c = returns[0].content
            return "return", c if isinstance(c, str) else str(c)
        c = retries[0].content
        return "retry", c if isinstance(c, str) else str(c)

    def all_text(self) -> str:
        """Every part of every request flattened — the O3 scanner's input."""
        from defender.tests.e2e._replay_harness import messages_text

        return "\n".join(messages_text(r) for r in self.requests)
