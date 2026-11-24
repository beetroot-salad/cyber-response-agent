"""Every investigation names its tenant's retention row (#1546 A-O7, r9 D16): a foreign key from `jobs.investigations` to
`tenancy.evidence_retention`, added `NOT VALID`, so the investigations an offboarded tenant (which may have no row) already
has stay, and every new one needs the row.

The upgrade stops, changing nothing, while any tenant that is not offboarded (`creating` included) has no retention row,
naming each. The table is new in this upgrade, so in practice every such tenant lacks one: recreate the development
database, or offboard those tenants first (`defender/CLAUDE.md`, "Upgrade from before #1546").

Revision ID: 0030_retention_required
Revises: 0029_evidence_retention

There is no downgrade.
"""
import sqlalchemy as sa
from alembic import op

revision = "0030_retention_required"
down_revision = "0029_evidence_retention"


def upgrade() -> None:
    found = op.get_bind().execute(sa.text(
        "SELECT t.id FROM tenancy.tenants t WHERE t.state <> 'offboarded' "
        "AND NOT EXISTS (SELECT 1 FROM tenancy.evidence_retention r WHERE r.tenant_id = t.id) ORDER BY t.id"))
    missing = [str(row[0]) for row in found]
    if missing:
        raise RuntimeError(
            f"{len(missing)} tenant(s) not offboarded have no evidence retention row: {', '.join(missing)}. Every "
            "investigation now names its tenant's retention (#1546) and there is no default; nothing was changed. "
            "Recreate the development database, or offboard those tenants, before upgrading")
    op.execute("ALTER TABLE jobs.investigations ADD CONSTRAINT fk_investigations_tenant_id_evidence_retention "
               "FOREIGN KEY (tenant_id) REFERENCES tenancy.evidence_retention (tenant_id) NOT VALID")
