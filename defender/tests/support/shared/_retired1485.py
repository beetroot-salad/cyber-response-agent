"""#1485 O5: the one named ban list of the retired #1278 import and cutover surfaces. Every retirement test takes its
retired names from here, so the product-and-tests census (`test_cutover_retired_census_1485`) skips this module's ban
lists by their constant names and finds the same names anywhere else a test spells them."""
from __future__ import annotations

#: Names whose use as code (a name, attribute, import, definition or string) is a retired import or cutover surface.
RETIRED_NAMES = frozenset({
    "cut_over_learning_state", "import_learning_state", "read_learning_state", "write_learning_state", "LearningImport",
    "ImportRefused", "delivery_for_cutover", "LearningRoot", "unwrap_learning_root", "request_learning_cutover",
})
#: The tenant pending action, the audit-action tail and the database CHECK value the cutover used.
RETIRED_ACTION = "learning_cutover"
#: The operator command that queued it.
RETIRED_COMMAND = "request-learning-cutover"
#: The tenant repositories' request method (`request_` + the action).
RETIRED_REQUEST = f"request_{RETIRED_ACTION}"

#: Module-level constants that are named ban lists: the census skips an assignment to any of these.
BAN_LIST_CONSTANTS = frozenset({"RETIRED_NAMES", "RETIRED_ACTION", "RETIRED_COMMAND", "RETIRED_REQUEST", "REACH_NAMES"})
