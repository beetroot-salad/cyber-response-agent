"""#936's fixture documents, lesson selectors and record reader, shared by the two test
modules that pin the issue: `test_936_fold_lessons_push.py` (the e2e half — drives the real
driver, needs the runtime extra, marked `e2e`) and `test_936_lessons_loaded_rows.py` (the
unit half — the record's columns, `render`'s lead, `trace_lesson`'s vocabulary, the SKILL.md
prose; no driver, runs everywhere). A private helper rather than one importing the other,
because importing a collected test module loads it twice in one session (`_lessons_corpus`
explains).
"""
from __future__ import annotations

import json
from pathlib import Path

from defender.tests._session_store_705 import CLOSED_LOOP_INVLANG

# documents

#: `_session_store_705.CLOSED_LOOP_INVLANG`, the one closed-loop document both fold suites
#: fold on. Loop 1 is CLOSED with a resolved lead and loop 2 is open, so
#: `compaction.fold_boundary` reads 1 and `driver._fold_decision` authorizes a fold on the
#: first render.
CLOSED_LOOP = CLOSED_LOOP_INVLANG

#: A `process` vertex whose class is the bare open marker — the slot `CLASS_LESSON` keys on.
#: Appended AFTER the loop-2 lead, so it lies past the record cut (see the module docstring).
OPEN_CLASS_BLOCK = """
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-006|process|??|nc[pid=4242]|image=/usr/bin/nc
```
"""

#: A second `process` vertex with an open `attrs.loginuid` — the append that MOVES the top
#: three after the fold (a new slot, a new lesson).
OPEN_LOGINUID_BLOCK = """
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-007|process|nc|nc[pid=4243]|loginuid=??;image=/usr/bin/nc
```
"""

#: A fenced block that moves NOTHING on the frontier: a lead row opens no slot and no
#: contract. Fenced on purpose — prose never reaches the frontier-equality limb of the gate,
#: a fence does, so this is the non-moving write C19 is actually about.
LEAD_ONLY_BLOCK = """
```invlang
:L findings [id|loop|name|target|tests|system|window]
l-006|2|cmdb-host|v-001||cmdb|w
```
"""

FOLDING_DOC = CLOSED_LOOP + OPEN_CLASS_BLOCK

#: ONE append that resolves loop 2's lead, closes loop 2, opens loop 3 and opens
#: `attrs.loginuid` — so the render after it folds through loop 2 (`fold_boundary == 2`,
#: checked in the test) on a document that now matches a second lesson. One append rather
#: than four so no intermediate state trips `flagged_diagnostics`.
SECOND_LOOP = """
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-007|process|nc|nc[pid=4243]|loginuid=??;image=/usr/bin/nc

:E l-005.observations.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-002|spawned|v-006|v-007|2026-05-01T10:12:00Z|siem-event:wazuh|outcome=success
```

```invlang
:T close
loop 2
```

```invlang
:L findings [id|loop|name|target|tests|system|window]
l-009|3|proc-tree|v-007||edr|w
```
"""

CLASS_LESSON = "class-open-936"
LOGINUID_LESSON = "loginuid-open-936"
CLASS_SELECTOR = ("type: process, slot: class",)
LOGINUID_SELECTOR = ("type: process, slot: attrs.loginuid",)
#: A selector NO document in this file opens — the "matches nothing" corpus.
IDENT_SELECTOR = ("type: identity, slot: ident",)

#: The write-return header, verbatim from `lessons_frontier.render`'s default lead — the one
#: the fold row must NOT carry (O3).
WRITE_RETURN_HEADER = "pushed because this write moved it"
#: A substring of the fold lead (design M4). Chosen so it is ABSENT from the record head
#: (`RESUME_RESTART_SHAPED` already says "no longer in the history"); the first test checks
#: that discrimination rather than assuming it.
FOLD_HEADER = "as it stands"

EVIDENCE_VOCABULARY = frozenset({"read", "push", "indirect", "unknown"})



def _rows(run_dir: Path) -> list[dict]:
    p = run_dir / "lessons_loaded.jsonl"
    if not p.is_file():
        return []
    return [json.loads(ln) for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]
