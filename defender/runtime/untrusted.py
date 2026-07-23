"""Compatibility import for callers outside the production tree."""

from defender._untrusted import wrap

__all__ = ["wrap"]
