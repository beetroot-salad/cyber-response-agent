# #1205 — bounded box responses

Current design: R1, implemented over base `27a5d1fc4b2726907202471f9e30434269d784f3`.

## Principles

Inherit [the engineering principles](../../../docs/principles.md): attacker-influenced
box data must not exhaust the host; refuse closed, loud, and fast. The owner selected
64 MiB and stopping the entire box/ending the run on overflow. The budget is a
conservative default, not a measured typical response size.

## Intent

- **O1:** Each Docker-backed call buffers at most a constant multiple of 64 MiB on the
  host, regardless of the response's eventual size. This is a per-call bound, not a
  global bound over concurrent calls or a bound on the Python process's total RSS.
- **O2:** The first byte past the aggregate budget causes a clear fatal refusal. Stop
  the entire box, prove it stopped, and refuse further calls on that executor. No
  partial output is a successful result; no model retry or fresh box recovers this run.
- **O3:** Responses at or below the budget retain the existing protocol, raw bytes,
  command exit status, and model-facing formatting.

Non-obligations: change in-box materialization, streaming/filtering algorithms,
unsandboxed execution, model display caps, or output retention in HTML reports.

## Design

The host-only output module owns a fixed `BOX_OUTPUT_LIMIT` and the bounded exchange.
The budget counts actual bytes on Docker stdout plus Docker stderr, including the
response header and its embedded command stdout/stderr, across the entire call.
It does not trust lengths declared inside the response.

A nonblocking selector loop writes request stdin and drains both outputs concurrently.
Reads request at most the remaining budget plus one sentinel byte, in chunks no larger
than 64 KiB. Successful output is decoded only after EOF and process completion. One
monotonic deadline covers request writing, reading, and waiting. Decoder copies mean
the memory promise is a constant multiple of the budget, not literally 64 MiB.

On overflow, close pipes, kill/reap the local Docker client without collecting residual
output, and raise `BoxOutputLimitExceeded`, a `BoxFault` subtype. Local reaping has a
five-second timeout; failure preserves the original exception with a cleanup note.
`BoxExecutor` marks itself unusable before calling the existing `BoxRuns.stop()` through
its carried daemon. Stop/inspection verify `exited` or `dead`; their existing individual
120-second Docker timeouts allow approximately 240 seconds of remote cleanup. Failure
to prove shutdown remains fatal and is chained to the overflow. Existing outer cleanup
retains its fatal-error precedence.

Tool, correlation, learning-stage, and grouped driver catches propagate overflow rather
than translating it into a recoverable result. Oracle Python bypasses its ordinary
lost-box/replacement path; the existing terminal world-fault path preserves the cause.
Review roles have no tools, so their stage-error handling is unaffected. No protocol,
configuration, image, or run-status schema migration is needed.

## Review and verification

Independent design review accepted R1 after correcting fatal propagation through broad
exception handlers and mixed exception groups. Tests cover aggregate boundaries,
concurrent pipe I/O, memory-constrained reading, deadlines, local cleanup, permanent
executor refusal, failed remote-stop proof, and end-run propagation. The live e2e test
uses a finite 64 MiB-plus-one-byte command and verifies stopped-container status, with
an under-limit control. Run both registered runtimes; unavailable runtimes are explicitly
skipped, not counted as verified.

```yaml
claims:
  - id: C1
    kind: referential
    claim: The base Docker transport captures both streams without a byte bound.
    probe: Read defender/box/_spec.py::_DockerTransport at the grounding base.
    probe_kind: read
    observed: subprocess.run uses capture_output=True.
    verdict: holds
  - id: C2
    kind: behavior
    claim: A bounded selector reader can detect overflow without reading to EOF.
    probe: Local Python child emitting 128 KiB per stream; reader budget 65536 bytes.
    probe_kind: executed
    observed: Refused at 65537 bytes; child killed and reaped.
    verdict: holds
  - id: C3
    kind: behavior
    claim: The installed agent framework propagates an ordinary fatal tool exception.
    probe: pydantic-ai 2.43.0 Agent with TestModel and a tool raising ProbeFault.
    probe_kind: executed
    observed: ProbeFault escaped unchanged.
    verdict: holds
  - id: C4
    kind: behavior
    claim: An oversized response under runc is refused and the container is stopped.
    probe: tests/e2e/test_1205_box_output.py::test_live_box_printing_past_limit_is_refused_and_stopped[runc], executed in the focused locked pytest run.
    probe_kind: executed
    observed: Passed, including an under-limit command and stopped-container inspection.
    verdict: holds
  - id: C5
    kind: behavior
    claim: The same live overflow contract holds under runsc.
    probe: The parametrized live test's runsc case; Docker info runtime inventory.
    probe_kind: executed
    observed: Skipped because runsc is not registered with this daemon.
    verdict: unprobed
```
