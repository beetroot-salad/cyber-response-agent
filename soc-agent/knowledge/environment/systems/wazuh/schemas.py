"""Wazuh alert envelope declaration consumed by the ANALYZE handler's flat-summary loader."""

from scripts.handlers._alert_schema import AlertSchema

SCHEMAS = (
    AlertSchema(
        name="wazuh-rule-alert",
        matches=lambda a: "rule" in a and "id" in a.get("rule", {}),
        fields=(
            "rule.id",
            "rule.description",
            "rule.level",
            "agent.name",
            "timestamp",
            "@timestamp",
            "data.srcip",
            "data.srcuser",
            "data.dstuser",
            "data.output_fields.evt.type",
            "data.output_fields.proc.name",
            "data.output_fields.proc.pname",
            "data.output_fields.proc.cmdline",
            "data.output_fields.proc.exepath",
            "data.output_fields.proc.aname",
            "data.output_fields.container.name",
            "data.output_fields.container.image.repository",
            "data.output_fields.user.name",
        ),
    ),
)
