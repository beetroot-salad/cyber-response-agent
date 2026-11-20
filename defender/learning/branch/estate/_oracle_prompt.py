"""Bounded and salted oracle prompt assembly."""
from __future__ import annotations



import hashlib
import json







from collections.abc import Callable
from dataclasses import dataclass



from typing import Any





from defender._untrusted import wrap_fresh
from defender.investigation.payload_view import (
    ELISION_PREFIX,
    passthrough_max_bytes,
    payload_text_of,
    walk,
)









from defender.learning.branch.estate.checks import canonical_json

from defender.learning.branch.estate._oracle_attempt import _Run as _Run




def family_salt(bodies: list[str]) -> str:
    """The family block's one frame salt: a digest of the block's own bodies, re-derived until
    no body contains it.

    Every sibling of a family builds its block from the same manifest and base recording, so
    the block is byte-identical across siblings, a shared prefix for prompt caching (the design's
    "family block, shared by siblings"). A body's author cannot close a frame early: the salt is
    a digest over that very body. Every other frame (world block, call turns, tool returns)
    keeps `wrap_fresh`'s random salt."""
    joined = "\x00".join(bodies)
    n = 0
    while True:
        salt = hashlib.sha256(f"{n}\x00{joined}".encode()).hexdigest()[:16]
        if salt not in joined:
            return salt
        n += 1




#: The most text of one answer a request carries; a larger one is shown as its head (N10). The
#: whole answer is saved for the oracle's code, and its patch applies to the whole of it.
_CONTEXT_CAP = 200_000




def _shares(sizes: list[int], total: int, cap: int = _CONTEXT_CAP) -> list[int]:
    """How much of each of `sizes` fits in `total` together: the smallest first, each up to an
    equal share of what is left (and never past `cap`), so a small value is shown whole and
    the large ones split what remains."""
    caps = [0] * len(sizes)
    remaining = max(total, 0)
    for k, i in enumerate(sorted(range(len(sizes)), key=lambda n: sizes[n])):
        caps[i] = min(sizes[i], remaining // (len(sizes) - k), cap)
        remaining -= caps[i]
    return caps




def _headed(label: str, text: str, cap: int) -> tuple[str, str]:
    """`label`'s heading and the body shown for `text` under `cap`: the whole text, or its
    head, saying so (N10)."""
    if len(text) <= cap:
        return f"{label}:", text
    return (f"{label} is {len(text)} characters, past what one request carries; its head "
            "follows:", text[:cap])




def _text_of(value: Any) -> str:
    return value if isinstance(value, str) else canonical_json(value)




def _framed(label: str, value: Any, cap: int = _CONTEXT_CAP) -> str:
    """`value` framed as untrusted data for any model prompt — the oracle's and the
    verifier's alike. Text past `cap` (`_CONTEXT_CAP` unless a budget gives it less) is shown
    as its head, saying so (N10)."""
    heading, body = _headed(label, _text_of(value), cap)
    return f"{heading}\n{wrap_fresh(body, 'untrusted')}"




def _fitted(items: list[tuple[str, Any]], budget: int) -> list[str]:
    """Each `(label, value)` framed, together within `budget` (`_shares`): a `_Saved` answer
    sized as the most of it a prompt shows (`_view_size`), and shown within its share."""
    texts = [_text_of(v.value if isinstance(v, _Saved) else v) for _label, v in items]
    sizes = [_view_size(t, _CONTEXT_CAP) if isinstance(v, _Saved) else len(t)
             for (_label, v), t in zip(items, texts, strict=True)]
    caps = _shares(sizes, budget)
    return [_answer_framed(label, v.value, v.saved_as, cap) if isinstance(v, _Saved)
            else _framed(label, text, cap)
            for (label, v), text, cap in zip(items, texts, caps, strict=True)]




def _view_cap() -> int:
    """The most of one answer, or of one python reply, a prompt shows whole: gather's own
    in-context ceiling (`passthrough_max_bytes`, which its setting moves), chosen there because
    a larger answer is re-read on every request. A larger one is shown as a bounded view."""
    return passthrough_max_bytes()


@dataclass(frozen=True)
class _Saved:
    """An answer the model's code can read whole from a saved file (`saved_as` names where),
    so a prompt shows it as a bounded view once it is past its share (`_answer_framed`)."""

    value: Any
    saved_as: str


def _view_size(text: str, cap: int) -> int:
    """At most how much of an answer of `text` a prompt shows under `cap`: all of it, or a view
    of `_view_cap()` (its heading included), whichever is less."""
    return min(len(text), _view_cap(), cap)


def _bounded_view(value: Any, saved_as: str, cap: int = _CONTEXT_CAP) -> str | None:
    """`value` as a bounded view within `min(cap, _view_cap())` characters, heading included,
    when its text is past that, else None: gather's walk of the answer (`payload_view.walk`:
    every scalar kept, its lists and long strings shortened, each dropped region marked where it
    was dropped), headed by its size and the file `saved_as` that holds it whole. Text that is
    not JSON, or whose walk overruns, is shown as its head, marked."""
    text = _text_of(value)
    size = min(cap, _view_cap())
    if len(text) <= size:
        return None
    heading = (f"It is {len(text)} characters, past what a request shows whole, so this is a "
               f"bounded view: each region it drops is marked `{ELISION_PREFIX} …>>` where it was "
               f"dropped, and is absent from this text only. The whole answer is {saved_as}: read "
               "its rows, counts and row indexes (which a patch's paths name) from that file with "
               "code, never off this view.\n")
    room = max(size - len(heading), 0)
    obj: Any = value
    if isinstance(value, str):
        try:
            obj = json.loads(value)
        except ValueError:
            obj = None
    body = None
    if obj is not None:
        walked, _elisions = walk(obj, room)
        body = payload_text_of(walked)
    if body is None or len(body) > room:
        body = text[:room] + f" {ELISION_PREFIX} the text past {room} of {len(text)} characters>>"
    return heading + body


def _answer_framed(label: str, value: Any, saved_as: str, cap: int = _CONTEXT_CAP) -> str:
    """An answer the model's code can read whole from a saved file (`saved_as`), framed as
    untrusted data: whole when it fits `cap` and `_view_cap()`, else as its bounded view."""
    view = _bounded_view(value, saved_as, cap)
    if view is None:
        return _framed(label, value, cap)
    return f"{label}:\n{wrap_fresh(view, 'untrusted')}"


def _base_text(base: Any, cap: int = _CONTEXT_CAP) -> str:
    framed = _answer_framed("The real base answer", base,
                            "saved for your code (inputs/index.json names it as `base`)", cap)
    if len(canonical_json(base)) <= _view_size(canonical_json(base), cap):
        return framed
    return f"An empty patch serves the whole base answer unchanged.\n{framed}"


def _cut_output(name: str, text: str, cap: int) -> str:
    """A python reply's `name` stream within `cap`: whole, or its head and tail around a mark
    saying what was cut and how to read the rest (it is not saved)."""
    if len(text) <= cap:
        return text
    half = max(cap // 2, 0)
    return (f"{text[:half]}\n{ELISION_PREFIX} {len(text) - 2 * half} of {len(text)} characters of "
            f"{name}: past what a reply shows whole. Write a large result to a file under /tmp and "
            f"print the parts you need>>\n{text[len(text) - half:] if half else ''}")


def _python_reply(rc: int, out: str, err: str) -> str:
    """A python run's reply, its two streams together within `_view_cap()` (`_shares`)."""
    out_cap, err_cap = _shares([len(out), len(err)], _view_cap())
    return "\n".join([f"exit {rc}", _framed("stdout", _cut_output("stdout", out, out_cap)),
                      _framed("stderr", _cut_output("stderr", err, err_cap))])


def _output_function(fn: Callable[..., Any], schema: dict) -> Callable[..., Any]:
    """`fn(ctx, args)` / `fn(args)` as an agent output function whose arguments are exactly
    `schema` (passed through as one mapping, unvalidated: the host's own checks refuse a
    malformed submission or verdict, with a reason the model can act on)."""
    import inspect

    from pydantic_ai import RunContext, StructuredDict

    # Annotations set as objects, not strings: the schema type is local to this call.
    args_type = StructuredDict(dict(schema))
    if "ctx" in inspect.signature(fn).parameters:
        async def with_ctx(ctx, args):
            return await fn(ctx, args)
        with_ctx.__annotations__ = {"ctx": RunContext[_Run], "args": args_type, "return": Any}
        return with_ctx

    def plain(args):
        return fn(args)
    plain.__annotations__ = {"args": args_type, "return": Any}
    return plain
