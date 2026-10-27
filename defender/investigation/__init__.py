"""Every writer and closer of `investigation.md` lives in this package, so loading it hands the
records write gate its invlang validator: no process can reach the gate without it."""
import defender.skills.invlang.validate  # noqa: F401 — registers the validator on load
