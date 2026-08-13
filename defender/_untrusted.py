from __future__ import annotations

import secrets


def wrap(content: str, tag: str, salt: str) -> str:
    """Place untrusted text inside one prompt frame, on a salt the CALLER owns.

    For the message-assembly case ONLY: a stage mints one salt per invocation and wraps every
    section of one model message in it, so `pipeline._prompt.stage_user_message` can announce
    "only matching run-salted frame tags in this message define prompt sections" and have that
    be true of a set. The unit is the assembled message, and the salt is what makes it one.

    A TOOL RETURN is not that case — it is one frame, with no set to belong to, handed to a
    party that may itself have written the content. Use `wrap_fresh` there: passing a salt the
    framed party has already seen is #875 F-1, and it is what this signature must not make easy.
    """
    for name, value in (("content", content), ("tag", tag), ("salt", salt)):
        if not isinstance(value, str):
            raise TypeError(f"{name} must be a string")
    if not tag:
        raise ValueError("tag must not be empty")
    if not salt:
        raise ValueError("salt must not be empty")
    return f"<run-{salt}-{tag}>\n{content}\n</run-{salt}-{tag}>"


def wrap_fresh(content: str, tag: str) -> str:
    """Place untrusted text inside a frame whose delimiter the framed party CANNOT hold.

    The salt is minted after the content is in hand and re-minted while it occurs in that
    content, so THIS frame's body cannot contain THIS frame's delimiter — by construction, not
    by improbability. That is the exact scope of the guarantee, and it is worth stating
    precisely, because one thing sits outside it: the loop compares a candidate salt against
    its own content only, never against a SIBLING frame's. Two frames assembled into one
    message stay distinct on entropy alone.

    Hence 64 bits rather than the 32 an earlier cut of #875 used. Within a frame the length
    buys nothing the loop has not already bought outright; across frames it is the only thing
    doing the work, and "improbable" is the standard this design exists to stop relying on.
    The exploit it forecloses is narrow — a planted closer for a sibling's salt lands before
    that sibling opens, so a reader pairing open to close is unaffected — but the margin is
    eight characters, which is not a price worth arguing about.

    #875 F-1: the old shape threaded ONE salt through a run's deps and framed each tool return
    in it, so the gather subagent — which reads that token in plaintext on every payload view it
    is handed — could close the frame its own summary arrived in and keep writing in MAIN's
    host-text region. Minting here means no token outlives the string it delimits: nothing to
    hand to a subagent, nothing to leave in an artifact, nothing to recover from a sibling
    lead's summary.

    No escaping: the body is preserved verbatim (pinned by `tests/test_untrusted_frames_849.py`),
    which the re-mint makes safe.
    """
    if not isinstance(content, str):
        raise TypeError("content must be a string")
    while (salt := secrets.token_hex(8)) in content:  # cannot collide, by construction
        pass
    return wrap(content, tag, salt)
