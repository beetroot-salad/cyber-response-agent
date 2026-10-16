"""The model's one view of its workspace (#1255, design rev 4 P1).

Every run, natural or arm, boxed or not, shows the model the same three trees at the same three
paths, whatever the host's layout:

    run folder         -> /runs/current
    code checkout      -> /defender
    tenant agent half  -> /agent

The host keeps working on its own paths. A path the model hands back is mapped to the host at
one inbound point (`ModelView.to_host`, called by the tool lanes before the permission gate or a
file tool sees it), and a host path that goes into model-bound text is rendered through
`ModelView.to_model` where that text is built. Evidence bytes (payloads, the alert) are never
rewritten: nothing here scans text.

@owns MODEL_RUN, MODEL_DEFENDER, MODEL_AGENT — the model view's three roots (the box mounts each
tree at its root; nothing else spells them).
"""
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


def _fold_double_slash(p: PurePosixPath) -> PurePosixPath:
    """POSIX lets `//x` mean `/x`; pathlib keeps `//` as its own anchor, so it is folded here."""
    return PurePosixPath("/", *p.parts[1:]) if p.anchor == "//" else p


@dataclasses.dataclass(frozen=True)
class ModelView:
    """One run's mapping between the model's paths and the host's. Built from the run's own
    roots (the role deps carry them), so every tool of the run maps the same way."""

    run_dir: Path
    defender_dir: Path
    tenant_agent: Path | None = None

    def trees(self) -> tuple[tuple[PurePosixPath, Path], ...]:
        """(model root, host root) for each tree this run has. The model roots are disjoint."""
        pairs = [(MODEL_RUN, Path(self.run_dir)), (MODEL_DEFENDER, Path(self.defender_dir))]
        if self.tenant_agent is not None:
            pairs.append((MODEL_AGENT, Path(self.tenant_agent)))
        return tuple(pairs)

    def roots_text(self) -> str:
        """The model roots, for a refusal telling the model where it may name paths."""
        return ", ".join(str(m) for m, _ in self.trees())

    # -- inbound ---------------------------------------------------------------------------
    def to_host(self, operand: str) -> Path | None:
        """The host path a model-supplied operand names, or `None` when it names nothing in the
        view: outside the three trees, or carrying a `..` component (refused as the rooted file
        core refuses it; a climb is never resolved here). A relative operand is anchored on the
        model's working directory, the run folder. The result is lexical: nothing is resolved,
        so a link stays for the gate and the rooted core to refuse."""
        p = _fold_double_slash(PurePosixPath(operand))
        if not p.is_absolute():
            p = MODEL_RUN / p
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


__all__ = ["MODEL_AGENT", "MODEL_DEFENDER", "MODEL_RUN", "ModelView", "runs_base"]
