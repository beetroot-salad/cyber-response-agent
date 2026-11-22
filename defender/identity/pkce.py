"""The browser sign-in's one-use values: state, nonce and PKCE verifier, and the S256 challenge of a verifier.

One owner, so the API's start check (#1620) sends the sign-in request with values of exactly the shape a browser's
carries, and so is answered as a browser's would be."""
from __future__ import annotations

import base64
import hashlib
import secrets


def new_secret() -> str:
    """A fresh state, nonce, verifier or token: `token_urlsafe(32)`."""
    return secrets.token_urlsafe(32)


def challenge(verifier: str) -> str:
    """The verifier's S256 challenge (RFC 7636): unpadded base64url of its SHA-256, 43 characters."""
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode()
