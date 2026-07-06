"""AWS logging adapters → normalized LoggingSink (SPEC §5).

CloudTrail is the primary audit-log construct; CloudWatch log groups carry
retention. Extra CloudTrail attributes (multi-region, management events) are
read from the attached resource by the logging KSIs.
"""

from __future__ import annotations

from ...model import LoggingSink, Resource
from ...model.graph import ResourceGraph
from ..registry import adapter


@adapter("aws_cloudtrail")
def adapt_cloudtrail(res: Resource, graph: ResourceGraph) -> None:
    enable_logging = res.get("enable_logging")
    graph.logging_sinks.append(
        LoggingSink(
            resource=res,
            enabled=bool(enable_logging) if enable_logging is not None else True,
            kms_key=res.get("kms_key_id"),
            immutable=bool(res.get("enable_log_file_validation")),
        )
    )


@adapter("aws_cloudwatch_log_group")
def adapt_log_group(res: Resource, graph: ResourceGraph) -> None:
    retention = res.get("retention_in_days")
    graph.logging_sinks.append(
        LoggingSink(
            resource=res,
            enabled=True,
            kms_key=res.get("kms_key_id"),
            retention_days=retention if isinstance(retention, int) else None,
        )
    )
