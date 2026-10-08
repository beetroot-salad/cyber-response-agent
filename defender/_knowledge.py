"""Where a tenant's model-facing agent knowledge lives: the one owner of its layout (#1108).

The agent knowledge is the per-tenant half of what a run's model reads: the lesson corpora,
the per-system skills (`skills/<system>/`), the saved query catalog
(`skills/gather/queries/<system>/`) and what a system keeps in its skill folder (the
tacit-knowledge registry). Every reader and writer
gets those locations from a `KnowledgePaths`; nothing else joins a corpus name onto a root.

Today the knowledge still sits inside the product checkout, at `defender/` itself
(`of_defender_dir`), so its folders coincide with the code tree's. #1108 moves it into each
tenant's own repo (`<data root>/<T>/knowledge/agent/`), keeping the same relative shape under
the agent root; only the construction of a `KnowledgePaths` changes then.

The GENERAL skills (gather's own `SKILL.md` and `defender-sql.md`, invlang, handbook, advisory,
connect) are product code, not knowledge: they stay under `defender_dir / "skills"` and are
never reached through here, even while the two folders coincide.

Pure path arithmetic: nothing here touches disk.
"""
from __future__ import annotations

from pathlib import Path

from defender._model import model

#: The defender's runtime corpus: what the runtime agent loads at PLAN and on its pushes.
LESSONS = "lessons"
#: The questioner's own corpus: findings about a world, never a lesson for the defender.
LESSONS_QUESTIONER = "lessons-questioner"
#: Retired corpora (#922): no run reads them; the lessons posture page still shows them.
LESSONS_ACTOR = "lessons-actor"
LESSONS_ENVIRONMENT = "lessons-environment"

#: Every corpus the author side may touch. Kept separate from `RUNTIME_LESSON_CORPORA` (what
#: the runtime agent loads at PLAN) so an author-only corpus such as `lessons-questioner` is
#: never readable by the runtime.
LESSON_CORPORA = frozenset({LESSONS, LESSONS_QUESTIONER})
RUNTIME_LESSON_CORPORA = frozenset({LESSONS})

#: The per-system skills' parent, under the agent root.
SKILLS = "skills"
#: The saved query catalog, under the agent root.
CATALOG = f"{SKILLS}/gather/queries"

#: Where the agent root sits inside the product checkout until #1108 moves it out.
CHECKOUT_AGENT_REL = "defender"


def checkout_rel(sub: str) -> str:
    """The checkout-relative spelling of a knowledge folder, with a trailing slash
    (`checkout_rel(LESSONS)` is `defender/lessons/`), for a `git` pathspec or a commit gate
    that names the folder before any `KnowledgePaths` exists."""
    return f"{CHECKOUT_AGENT_REL}/{sub}/"


@model(frozen=True)
class KnowledgePaths:
    """One tenant's agent knowledge, rooted at `agent_root`.

    `agent_rel` is `agent_root`'s spelling relative to the git repo that versions it (`defender`
    in the product checkout); the `*_rel` spellings are built from it."""

    agent_root: Path
    agent_rel: str

    @classmethod
    def of_defender_dir(cls, defender_dir: Path) -> KnowledgePaths:
        """The knowledge inside the code tree at `defender_dir` (a checkout's or a worktree's
        `defender/`), where it lives until #1108 moves it into the tenant's repo."""
        return cls(agent_root=Path(defender_dir), agent_rel=CHECKOUT_AGENT_REL)

    def corpus_dir(self, corpus: str) -> Path:
        """A lesson corpus by name (one of `LESSON_CORPORA`, or a retired corpus)."""
        return self.agent_root / corpus

    @property
    def lessons_dir(self) -> Path:
        return self.corpus_dir(LESSONS)

    @property
    def lessons_questioner_dir(self) -> Path:
        return self.corpus_dir(LESSONS_QUESTIONER)

    @property
    def skills_dir(self) -> Path:
        """The per-system skills' parent (`<skills_dir>/<system>/`), which also holds the
        catalog."""
        return self.agent_root / SKILLS

    def system_skill_dir(self, system: str) -> Path:
        """One system's skill folder: its `SKILL.md`, `execution.md` and any data the system
        keeps beside them (the tacit-knowledge registry, #983)."""
        return self.skills_dir / system

    @property
    def catalog_dir(self) -> Path:
        return self.agent_root / CATALOG

    def rel(self, sub: str) -> str:
        """`sub`'s spelling relative to the versioning repo, with a trailing slash."""
        return f"{self.agent_rel}/{sub}/"

    @property
    def skills_rel(self) -> str:
        return self.rel(SKILLS)

    @property
    def catalog_rel(self) -> str:
        return self.rel(CATALOG)
