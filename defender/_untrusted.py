from __future__ import annotations

import secrets


def wrap(content: str, tag: str, salt: str) -> str:
    """Place untrusted text inside one prompt frame, on a salt the caller owns.

    Only for assembling one model message whose sections share a salt (see `message_salt`).
    For a tool return use `wrap_fresh`: reusing a salt the framed party has already seen lets
    it close the frame and write outside it.
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
    """Place untrusted text inside a frame whose delimiter the framed party cannot hold.

    The salt is minted after the content is known and re-minted while the content contains it,
    so the body cannot contain its own delimiter; the body is kept verbatim, unescaped. Sibling
    frames in one message are kept distinct only by the salt's 64 bits of entropy. Minting per
    frame means no token outlives the string it delimits, so a subagent that saw one salt cannot
    close a later frame.
    """
    if not isinstance(content, str):
        raise TypeError("content must be a string")
    return wrap(content, tag, message_salt(content))


def message_salt(*bodies: str) -> str:
    """A salt for one assembled message that none of that message's bodies contains.

    A stage that frames several sections in a shared salt (so `learning._prompt.stage_user_message`
    can say "only matching run-salted frame tags define prompt sections") needs the guarantee
    over all bodies at once; per-frame salts would let one section close a sibling's frame.
    """
    for body in bodies:
        if not isinstance(body, str):
            raise TypeError("every body must be a string")
    joined = "".join(bodies)
    while (salt := secrets.token_hex(8)) in joined:  # cannot collide, by construction
        pass
    return salt
