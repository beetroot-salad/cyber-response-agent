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
    content, so the body cannot contain the delimiter — by construction, not by improbability.
    That is the whole of the guarantee, and it is why the token can be short: length was only
    ever buying collision resistance, and the loop below buys it outright.

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
    while (salt := secrets.token_hex(4)) in content:  # cannot collide, by construction
        pass
    return wrap(content, tag, salt)
