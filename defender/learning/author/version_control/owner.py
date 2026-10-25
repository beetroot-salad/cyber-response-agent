"""The owner record of a per-owner scratch folder (a draft or a run copy). Its one owner is
`defender.tenancy._owner`, outside this package, so a run process (which never imports tenant
delivery, #1108 P4 P-3) records its run copy's owner with the same code a publish sweeps by."""
from defender.tenancy._owner import OWNER_FILE, owner_alive, process_start, write_owner

__all__ = ["OWNER_FILE", "owner_alive", "process_start", "write_owner"]
