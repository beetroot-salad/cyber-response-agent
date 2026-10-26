"""The isolation the defender suite gives every test, borrowed for these: no test here may see the
launching shell's real data root or its `dev` deployment. Re-exported from the defender suite's own
conftest, not restated, so the two cannot drift."""
from defender.tests.conftest import data_root, deployment_unset, session_data_root  # noqa: F401
