"""The per-job host helper (#1170 H7): all privileged work for one job of one tenant, the job's container its child.

The worker spawns one helper per claim (`python -m defender.job_host --kind ... --tenant ... --parent-pid ...`). The
helper holds the tenant's lock, admits the tenant, publishes, signs the job's passes, makes the claim's own root,
inputs and spool and places the job's copies there, starts the job's one container (labelled with its tenant, its claim and `JOB_LABEL`), answers the job socket by job
kind (staging each record the job sends as a fact of its claim), starts and relays the job's boxes, uploads the
objects the job pushed once the container exits, and removes what it made.

Split into:
  * `_main`          — the flow, the signals, the end (step 8).
  * `_session`       — the job's state, the registry of requests and kinds, the pass mint.
  * `_container`     — the container's socket, environment, runtime and `docker run`.
  * `_server`        — the job socket's server (the filesystem alone decides who may use it, #1469 S4).
  * `_common`        — `launch` and the box requests every kind shares.
  * `_investigation` — the investigation kind: the host half of run setup, its pass and its run box.
  * `_learning`      — the learning kinds (the learning slice's), the drain request's included (#1546 D7).
  * `_paths`         — paths taken from the tenant's folder, judged with no link followed (H10).
  * `_rows`          — the job store's writes under the claim, and the claim's own reads (#1546).
  * `_records`       — the records a job sends, held to their shapes on receipt (#1546 PR2).
  * `_evidence`      — the record verbs, the object pushes and pulls, the uploads (#1546 PR8, A-O6).
  * `_folders`       — the claim's root, inputs and spool (#1546 A-O1, A-O9).

The client side (`ask`, `Refused`, `SOCKET_ENV`, `JOB_LABEL`, `IMAGE_ENV`) lives in `defender.job_socket`, low in the
import order so every in-container caller can use it; this door re-exports it. `main` is served lazily, so importing
this package for the client does not load the helper's stack.

A post-step's helper that served its job to its end answers whether work still waits by its exit status (#1487
Amendment r5.2): `NOTHING_WAITS` or `WORK_WAITS`, asked of the learning store it bound once the container exited.
Any other status, 0 included (a stopped post-step, a question that failed, one ended before its container), says
nothing about it: the worker never reads it as "nothing waits"."""
from __future__ import annotations

from typing import TYPE_CHECKING

from defender.job_socket import IMAGE_ENV, JOB_LABEL, SOCKET_ENV, Refused, ask
from defender.lazy_door import lazy_door

if TYPE_CHECKING:
    from defender.job_host._container import STOP_GRACE as STOP_GRACE
    from defender.job_host._main import main as main

__all__ = ["IMAGE_ENV", "JOB_LABEL", "NOTHING_WAITS", "SOCKET_ENV", "STOP_GRACE", "WORK_WAITS", "Refused", "ask", "main"]

#: A served post-step's exit status when the learning store answered that no work waits for a post-step of its tenant.
NOTHING_WAITS = 10
#: A served post-step's exit status when the learning store answered that work still waits.
WORK_WAITS = 11

#: Each name this door serves lazily, and the submodule that defines it.
_HOMES: dict[str, str] = {"main": "_main", "STOP_GRACE": "_container"}

__getattr__ = lazy_door(globals(), _HOMES)
