"""The per-job host helper (#1170 H7): all privileged work for one job of one tenant, the job's container its child.

The worker spawns one helper per claim (`python -m defender.job_host --kind ... --tenant ... --parent-pid ...`). The
helper holds the tenant's lock, admits the tenant, publishes, signs the job's passes, makes its run folder and copies,
starts the job's one container (labelled with its tenant, its claim and `JOB_LABEL`), answers the job socket by job
kind, starts and relays the job's boxes, and removes what it made when the container exits.

Split into:
  * `_main`          — the flow, the signals, the end (step 8).
  * `_session`       — the job's state, the registry of requests and kinds, the pass mint.
  * `_container`     — the container's socket, environment, `docker run`, and who its processes are.
  * `_server`        — the job socket's server and its peer check.
  * `_common`        — `launch` and the box requests every kind shares.
  * `_investigation` — the investigation kind: the host half of run setup, its pass and its run box.
  * `_learning`      — the learning kinds (the learning slice's).
  * `_paths`         — paths taken from the tenant's folder, judged with no link followed (H10).

The client side (`ask`, `Refused`, `SOCKET_ENV`, `JOB_LABEL`, `IMAGE_ENV`) lives in `defender.job_socket`, low in the
import order so every in-container caller can use it; this door re-exports it. `main` is served lazily, so importing
this package for the client does not load the helper's stack."""
from __future__ import annotations

from typing import TYPE_CHECKING

from defender.job_socket import IMAGE_ENV, JOB_LABEL, SOCKET_ENV, Refused, ask
from defender.lazy_door import lazy_door

if TYPE_CHECKING:
    from defender.job_host._main import main as main

__all__ = ["IMAGE_ENV", "JOB_LABEL", "SOCKET_ENV", "Refused", "ask", "main"]

#: Each name this door serves lazily, and the submodule that defines it.
_HOMES: dict[str, str] = {"main": "_main"}

__getattr__ = lazy_door(globals(), _HOMES)
