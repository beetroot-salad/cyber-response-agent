"""Where a tenant's model-facing agent knowledge lives: the one owner of its layout (#1108)."""
from __future__ import annotations

from pathlib import Path

from defender._git import REPO_ROOT
from defender._model import model

#: The defender's runtime corpus: what the runtime agent loads at PLAN and on its pushes.
LESSONS = "lessons"
#: The questioner's own corpus: findings about a world, never a lesson for the defender.
LESSONS_QUESTIONER = "lessons-questioner"
#: Every corpus the author side may touch. Kept separate from `RUNTIME_LESSON_CORPORA` (what
#: the runtime agent loads at PLAN) so an author-only corpus such as `lessons-questioner` is
#: never readable by the runtime.
LESSON_CORPORA = frozenset({LESSONS, LESSONS_QUESTIONER})
RUNTIME_LESSON_CORPORA = frozenset({LESSONS})

#: The per-system skills' parent, under the agent root.
SKILLS = "skills"
#: The saved query catalog, under the agent root.
CATALOG = f"{SKILLS}/gather/queries"
#: The tenant's pitfalls add-on to the product's `defender-sql` reducer page, under the agent
#: root: the pitfalls curator's one write target beyond a system's `execution.md`, and the page
#: a gather dispatch names beside the product page (#1108 P4 O1: the product page is never
#: written). The tenant template ships it, so the curator only ever edits it.
REDUCER_PITFALLS = f"{SKILLS}/gather/defender-sql.pitfalls.md"
#: A name no catalog file may take: the catalog's schema once lay beside its templates under
#: this name, and the lead lane's gates still refuse it (the format is the product's
#: `skills/gather/query-schema.md` now).
CATALOG_SCHEMA_NAME = "SCHEMA.md"

#: The agent root's spelling inside the tenant repo that versions it (`<repo>/agent/`): the
#: prefix of every repo-relative knowledge path a commit, ChangeSet or handoff names (OD6).
AGENT_REL = "agent"


@model(frozen=True)
class KnowledgePaths:
    """One tenant's agent knowledge, rooted at `agent_root`: a run copy's `stage/agent/`, a
    draft's `agent/` or an export's `agent/` (#1108 P4). Nothing else roots it, so a run's paths
    never reach another tenant's knowledge or the product tree."""

    agent_root: Path

    def corpus_dir(self, corpus: str) -> Path:
        """A lesson corpus by name (one of `LESSON_CORPORA`)."""
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

    @property
    def reducer_pitfalls(self) -> Path:
        return self.agent_root / REDUCER_PITFALLS

    def rel(self, sub: str) -> str:
        """`sub`'s spelling relative to the tenant repo (`agent/<sub>/`), with a trailing slash."""
        return f"{AGENT_REL}/{sub}/"

@model(frozen=True)
class _CheckoutKnowledge(KnowledgePaths):
    """The knowledge a product checkout carried before #1108 P4 moved it into the tenant repo:
    rooted at the checkout's `defender/`, spelled `defender/<sub>/` relative to the product repo.

    Kept for the judge's pre-move branch only (O6: a run whose code commit's tree has
    `defender/lessons/<name>.md` is read from the product repo at that commit); the census
    (`tenant_1108_p4/test_census.py`) holds every other module to an agent root."""

    @property
    def agent_rel(self) -> str:
        return "defender"

    def rel(self, sub: str) -> str:
        return f"{self.agent_rel}/{sub}/"


#: The knowledge the running checkout carried before #1108 P4 (`_CheckoutKnowledge`): the judge's
#: pre-move branch is its one design-sanctioned reader.
CHECKOUT_KNOWLEDGE = _CheckoutKnowledge(agent_root=REPO_ROOT / "defender")
