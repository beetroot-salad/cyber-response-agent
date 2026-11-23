"""#1546: evidence leaves the host. The blob store (an S3 bucket, SSE-C) and the tenant evidence key (OpenBao transit) with
its login policy. The bundle packer is `defender.evidence.bundle`, imported on its own (it reaches the box's scrub)."""
from __future__ import annotations

from ._blob import BlobNotFound, BlobStore, BlobStoreError
from ._keys import (
    KEY_PREFIX,
    TEMPLATED_POLICY,
    DataKey,
    EvidenceKeyError,
    EvidenceKeyMissing,
    EvidenceKeys,
    approle_policy,
    key_name,
)



def object_key(tenant_id: str, owner_kind: str, owner: str, claim: str, obj: str) -> str:
    """The store key of an owner's object (#1546): `t/<tenant>/<owner kind>/<owner id>/<claim token>/<object>`, the one
    layout the helper writes and pulls and the lifecycle's sweeps delete by."""
    return f"t/{tenant_id}/{owner_kind}/{owner}/{claim}/{obj}"


__all__ = ["KEY_PREFIX", "TEMPLATED_POLICY", "BlobNotFound", "BlobStore", "BlobStoreError", "DataKey", "EvidenceKeyError",
           "EvidenceKeyMissing", "EvidenceKeys", "approle_policy", "key_name", "object_key"]
