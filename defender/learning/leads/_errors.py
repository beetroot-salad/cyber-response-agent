"""The lead-author lane's refusal class, in a module that imports nothing.

`lead_extraction` re-exports it and stays its public spelling. It lives here so a reader that
only needs to catch or subclass it — `declared_systems`, and through it `tenant.py check`'s
grant census — does not import the extraction stack (`lead_repository` and the rest) to do so.
"""

from __future__ import annotations


class LeadAuthorError(Exception):
    # The public spelling, so a traceback names the class where its readers import it from.
    __module__ = "defender.learning.leads.lead_extraction"
