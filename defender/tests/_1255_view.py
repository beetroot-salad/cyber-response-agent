"""#1255 slice B (the model view) — shared machinery for the `test_1255_view_*` suites. NO tests.

Design rev 4, P1: one host-owned mapping, built once at run start:

    run folder         -> /runs/current
    code checkout      -> /defender
    tenant agent half  -> /agent

Everything the model reads names the right-hand column; every path it hands back is mapped to the
left-hand column at one inbound point. The expected values the suites assert are the DESIGN's
literals below — nothing here calls a production renderer to learn what a model path looks like.

What lives here, and why each is test machinery rather than policy:

* `Layout` / `make_layout` — one HOST layout: a data root, a set-up tenant under it (through the
  real `create_tenant` / `accept_tenant`, `_data_root_1078.set_up_tenant`), and the checkout the run
  is handed (the real one, or a symlink mirror of it at another path, #1003's `defender_dir`
  seam). Two layouts that differ in all three are what makes "host-independent" observable:
  equality across ONE host's runs cannot see host layout at all (design, twin-check paragraph).
* `host_tokens` / `scan` — a test-time detector (the design names it so: "substring scanning for
  host prefixes is a test-time detector only"). It never edits anything.
* `FakeDocker` — a daemon double that RECORDS argv and refuses the create. It implements no box
  policy; the argv it records is production's (`start_box` -> `_create_argv`).
* `parse_create` / `masked_create` — read a recorded `docker run` argv back into its parts.
* `Recorder` — a FunctionModel callable that keeps every request's message objects, so a tool
  RESULT (or a refusal) is attributed to the call that produced it.
"""
from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from defender.run_repository import RUN_LAYOUT

DEFENDER = Path(__file__).resolve().parents[1]
REPO_ROOT = DEFENDER.parent

# ---------------------------------------------------------------------------------------------
# The design's model view (rev 4, "Model view (P1)" table and the Box bullet). Literals, on
# purpose: these are the contract, not a computation.
# ---------------------------------------------------------------------------------------------
MODEL_RUN = "/runs/current"
MODEL_RUNS = "/runs"
MODEL_DEFENDER = "/defender"
MODEL_AGENT = "/agent"
#: The three trees' model roots. A model path is one of these or below one.
MODEL_ROOTS = (MODEL_RUN, MODEL_DEFENDER, MODEL_AGENT)
#: The run's alert as the model names it: the run folder's own relative layout under /runs/current.
MODEL_ALERT = f"{MODEL_RUN}/{RUN_LAYOUT.alert_input_dir}/alert.json"
#: The design's env constants for the box (rev 4: "Working directory and environment become
#: constants: DEFENDER_RUN_DIR, DEFENDER_RUNS_BASE=/runs, DEFENDER_DIR, DEFENDER_AGENT_DIR").
MODEL_ENV = {
    "DEFENDER_RUN_DIR": MODEL_RUN,
    "DEFENDER_RUNS_BASE": MODEL_RUNS,
    "DEFENDER_DIR": MODEL_DEFENDER,
    "DEFENDER_AGENT_DIR": MODEL_AGENT,
}

#: Two tenant ids no shipped text contains, so a hit of either is a leak, never prose.
TENANT_A = "tnt-qzv7a"
TENANT_B = "orgx-kw3b"
#: The image the static checks name explicitly, so `resolve_rootfs` reads nothing off a planted
#: checkout (the image's identity is not what these tests are about).
STATIC_ROOTFS = "python:3.11-slim"


def under_model_root(value: str) -> bool:
    """Whether `value` is one of the three model roots or a path below one."""
    return any(value == root or value.startswith(root + "/") for root in MODEL_ROOTS)


def model_path(host: Path | str, *, run_dir: Path | str, defender_dir: Path | str = DEFENDER,
               agent: Path | str | None = None) -> str:
    """The design table's spelling of a HOST path under one of the three trees, for a scripted
    model turn that names a path (rev 4: "Every path the model hands back is mapped model -> host"
    — a model only ever holds the right-hand column, so a script that hands back the left-hand
    one scripts a model that cannot exist once host paths are refused).

    Lexical (no `resolve()`: the spelling is the point, and a link under a tree must keep its
    tree), the most specific root first. A path under none of the three raises — every scripted
    path this migrates is inside a tree, so a raise means the script names something the model
    view cannot reach, which is a finding, not a fallback."""
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


# ---------------------------------------------------------------------------------------------
# Host layouts
# ---------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Layout:
    """One host layout: where the data root is, what the tenant is called, where the checkout
    the run is handed sits. `tenant` is the real accepted `Tenant`."""

    data_root: Path
    tenant_id: str
    tenant: Any
    checkout: Path

    @property
    def agent(self) -> Path:
        return Path(self.tenant.agent)


def mirror_checkout(root: Path, *, own_lessons: bool = False) -> Path:
    """A checkout at another host path: `<root>/defender`, every top-level entry of this
    checkout symlinked in (`test_936`'s `_planted_defender` idiom, the #1003 `defender_dir`
    seam). `.venv`/`__pycache__` stay out. The run reads the same code and corpus through a
    different spelling, which is what "a different checkout path" means to the host.
    `own_lessons`: `lessons/` is a real, empty folder of the mirror's own, so the only lessons a
    run can match are the ones a test writes — and their host path is under the mirror."""
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
    """A data root at `<base>/<…>/data`, the committed fixture tenant set up under it as
    `tenant_id` (the operator's steps, `_data_root_1078.set_up_tenant`), and `checkout` (default:
    this checkout). The data root is nested one level deeper than `base` so two layouts made under
    sibling bases differ in depth as well as in name."""
    from defender.tests import _data_root_1078

    data_root = Path(base) / f"host-{tenant_id}" / "data"
    data_root.mkdir(parents=True)
    tenant = _data_root_1078.set_up_tenant(data_root, tenant_id)
    return Layout(data_root=data_root, tenant_id=tenant_id, tenant=tenant,
                  checkout=Path(checkout) if checkout is not None else DEFENDER)


def natural_run(layout: Layout, alert_bytes: bytes, run_id: str) -> Path:
    """A natural run's folder made the way `run.py` makes it: `run_common.materialize_run` under
    the layout's tenant, through its runs repository (never a spelled path)."""
    from defender import run_common

    staged = layout.data_root.parent / f"alert-{run_id}.json"
    staged.write_bytes(alert_bytes)
    run = run_common.materialize_run(staged, run_id, tenant=layout.tenant)
    return Path(run.run_dir)


# ---------------------------------------------------------------------------------------------
# The detector
# ---------------------------------------------------------------------------------------------
def host_tokens(*layouts: Layout, extra: Iterable[Path | str] = ()) -> list[str]:
    """Every host-layout string the model must never be shown (O3): each data root, each tenant
    name, each checkout path (as handed and resolved), this checkout and its repo root (a
    symlinked mirror resolves to them), the host user's home. Longest first, so a report names
    the most specific hit."""
    tokens: set[str] = {str(REPO_ROOT), str(DEFENDER)}
    for layout in layouts:
        tokens |= {str(layout.data_root), str(layout.data_root.resolve()), layout.tenant_id,
                   str(layout.checkout), str(layout.checkout.resolve()),
                   str(layout.checkout.parent)}
    home = os.path.expanduser("~")
    if home not in ("", "/"):
        tokens.add(home)
    tokens |= {str(e) for e in extra}
    return sorted((t for t in tokens if t and t != "/"), key=len, reverse=True)


def _token_re(token: str) -> re.Pattern[str]:
    """A path token matches as a path (not inside a longer name); a bare name (a tenant id)
    matches as a word."""
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


# ---------------------------------------------------------------------------------------------
# The daemon double and the create argv
# ---------------------------------------------------------------------------------------------
class FakeDocker:
    """`DockerFn` that records every argv. It answers: no container by that name (inspect rc 1,
    `docker version` rc 0 so that reads as a free name), the image present, and the create
    REFUSED (rc 1) — so `start_box` renders its real create argv, hands it here, and stops with a
    `BoxFault` before anything else runs. It decides nothing the tests assert."""

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
    #: (source, target, readonly) per `--mount`, in argv order.
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
    """The create argv with what legitimately differs per run or per host DAEMON masked: the
    container name (derived from the run id — O4's fresh ids), the per-start token label, each
    bind SOURCE (a host path the daemon needs; never inside the box's view), and the seccomp
    profile's host path (read by the daemon, never visible in the box). Everything else — every
    target, the workdir, every env pair, the image — must be identical for an arm and a natural
    run and across host layouts."""
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


# ---------------------------------------------------------------------------------------------
# The model double
# ---------------------------------------------------------------------------------------------
class Recorder:
    """A replay callable (`drive`'s `main=` / `gather=`) that keeps every request it was sent as
    message objects, then answers the next scripted turn. `requests[i]` is the full message
    history the model received at its i-th request. `before[i]`, when given, runs as request i
    arrives, before the turn answering it is returned — so a scenario can change the host's
    disk between two tool calls, where only the model's own timing can put it."""

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

    # -- reading what came back ---------------------------------------------------------------
    def first_user_text(self) -> str:
        """Message 0's user prompt text (the opening prompt)."""
        from pydantic_ai.messages import UserPromptPart

        for part in self.requests[0][0].parts:
            if isinstance(part, UserPromptPart):
                return part.content if isinstance(part.content, str) else str(part.content)
        raise AssertionError("the first request carries no user prompt")

    def answer_to(self, request_index: int) -> tuple[str, str]:
        """What the tool call(s) of the response before request `request_index` came back as:
        `("return", text)` for a tool result, `("retry", text)` for a refusal bounced back as
        retry feedback. The answer is the LAST message of that request."""
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
