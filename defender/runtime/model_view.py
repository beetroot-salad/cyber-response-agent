"""The model's workspace coordinates (#1255 and #1262)."""
from __future__ import annotations

import dataclasses
from pathlib import Path, PurePosixPath

#: The run folder as the model sees it. Not `/run`: invlang treats the runs folder (its parent)
#: as its corpus and prints a case's folder name, so the folder holding the run must hold only it.
MODEL_RUN = PurePosixPath("/runs/current")
#: The code checkout (shims, skills, lessons) as the model sees it.
MODEL_DEFENDER = PurePosixPath("/defender")
#: The tenant's agent half as the model sees it.
MODEL_AGENT = PurePosixPath("/agent")
MODEL_WORKSPACE = PurePosixPath("/workspace")
MODEL_LEARNING = PurePosixPath("/learning/current")
MODEL_DRAFT = PurePosixPath("/draft")

RootPairs = tuple[tuple[PurePosixPath, Path], ...]


def _fold_double_slash(p: PurePosixPath) -> PurePosixPath:
    """POSIX lets `//x` mean `/x`; pathlib keeps `//` as its own anchor, so it is folded here."""
    return PurePosixPath("/", *p.parts[1:]) if p.anchor == "//" else p


@dataclasses.dataclass(frozen=True)
class ModelView:
    """Immutable root mappings and working directory, shared by all filesystem roles."""

    roots: RootPairs
    cwd: PurePosixPath

    def __post_init__(self) -> None:
        for model, host in self.roots:
            if model.anchor != "/" or model == PurePosixPath("/") or ".." in model.parts:
                raise ValueError(f"invalid model root: {model}")
            if not host.is_absolute() or ".." in host.parts:
                raise ValueError(f"invalid host root: {host}")
        for i, (model, host) in enumerate(self.roots):
            for other, source in self.roots[:i]:
                if model == other or model in other.parents or other in model.parents:
                    raise ValueError(f"conflicting model roots: {model}, {other}")
                if host.resolve() == source.resolve():
                    raise ValueError(f"ambiguous host root: {host}")
        if not self.cwd.is_absolute() or self.to_host(str(self.cwd)) is None:
            raise ValueError(f"working directory is outside the model view: {self.cwd}")

    @classmethod
    def for_run(cls, run_dir: Path, defender_dir: Path, tenant_agent: Path | None = None,
                *, extra_roots: RootPairs = ()) -> ModelView:
        roots: RootPairs = ((MODEL_RUN, Path(run_dir)), (MODEL_DEFENDER, Path(defender_dir)))
        if tenant_agent is not None:
            roots += ((MODEL_AGENT, Path(tenant_agent)),)
        return cls((*roots, *extra_roots), MODEL_RUN)

    @classmethod
    def for_learning(cls, run_dir: Path, repo_root: Path, *, extra_roots: RootPairs = ()) -> ModelView:
        return cls(((MODEL_WORKSPACE, Path(repo_root)), (MODEL_LEARNING, Path(run_dir)),
                    *extra_roots), MODEL_WORKSPACE)

    @classmethod
    def for_draft(cls, defender_dir: Path, draft_root: Path) -> ModelView:
        return cls(((MODEL_DEFENDER, Path(defender_dir)), (MODEL_DRAFT, Path(draft_root))),
                   MODEL_DRAFT / "agent")

    @classmethod
    def for_scope(cls, run_dir: Path, defender_dir: Path, cwd_anchor: Path,
                  tenant_agent: Path | None = None, *, extra_roots: RootPairs = ()) -> ModelView:
        """Compile bind's run-anchored, checkout-anchored or draft-anchored workspace geography.
        Anchored on a tenant agent root (a batch draft's `agent/`, #1108 P4), it is the drain
        box's own geography (`for_draft`)."""
        if tenant_agent is not None and cwd_anchor == tenant_agent and tenant_agent.name == "agent":
            return cls(((MODEL_DEFENDER, Path(defender_dir)),
                        (MODEL_DRAFT, Path(tenant_agent).parent), *extra_roots),
                       MODEL_DRAFT / "agent")
        if cwd_anchor == defender_dir.parent:
            agent = ((MODEL_AGENT, tenant_agent),) if tenant_agent is not None else ()
            return cls.for_learning(run_dir, defender_dir.parent, extra_roots=(*agent, *extra_roots))
        return cls.for_run(run_dir, defender_dir, tenant_agent, extra_roots=extra_roots)

    def trees(self) -> tuple[tuple[PurePosixPath, Path], ...]:
        """(model root, host root) for each tree this run has. The model roots are disjoint."""
        return self.roots

    def roots_text(self) -> str:
        """The model roots, for a refusal telling the model where it may name paths."""
        return ", ".join(str(m) for m, _ in self.trees())

    # -- inbound ---------------------------------------------------------------------------
    def to_host(self, operand: str) -> Path | None:
        """The host path a model operand names, or `None` outside the declared trees or with a
        `..` component. A relative operand is anchored on the declared working directory.
        The result is lexical: nothing is resolved,
        so a link stays for the gate and the rooted core to refuse."""
        p = _fold_double_slash(PurePosixPath(operand))
        if not p.is_absolute():
            p = self.cwd / p
        if ".." in p.parts:
            return None
        for model, host in self.trees():
            if p == model:
                return host
            if model in p.parents:
                return host / p.relative_to(model)
        return None

    # -- outbound --------------------------------------------------------------------------
    def to_model(self, host: Path | str) -> str:
        """The model path of a host path under one of the trees, matched as the host spells it
        first and then resolved (a lesson found through a resolved corpus path). The most
        specific host root wins: the run folder may sit inside the checkout. A path under no
        tree is a `ValueError` — the caller was about to show the model a host path."""
        h = Path(host)
        for candidate, resolve in ((h, False), (h, True)):
            if resolve:
                try:
                    candidate = candidate.resolve()
                except (OSError, RuntimeError):
                    break
            best: tuple[PurePosixPath, Path] | None = None
            for model, root in self.trees():
                r = root.resolve() if resolve else root
                if (candidate == r or r in candidate.parents) and (
                        best is None or len(r.parts) > len(best[1].parts)):
                    best = (model, r)
            if best is not None:
                model, r = best
                rel = candidate.relative_to(r)
                return str(model) if rel == Path(".") else str(model / rel.as_posix())
        raise ValueError(f"{host} lies under none of the model view's trees")


def runs_base() -> PurePosixPath:
    """The runs folder the model sees: the run folder's parent, holding only it."""
    return MODEL_RUN.parent


__all__ = ["MODEL_AGENT", "MODEL_DEFENDER", "MODEL_RUN", "MODEL_WORKSPACE", "MODEL_LEARNING",
           "MODEL_DRAFT", "ModelView", "RootPairs", "runs_base"]
