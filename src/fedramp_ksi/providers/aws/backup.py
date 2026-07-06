"""AWS backup adapters → normalized BackupConfig (SPEC §5)."""

from __future__ import annotations

from ...model import BackupConfig, Resource
from ...model.graph import ResourceGraph
from ..registry import adapter


@adapter("aws_db_instance", "aws_rds_cluster")
def adapt_rds_backup(res: Resource, graph: ResourceGraph) -> None:
    retention = res.get("backup_retention_period")
    if res.is_unknown("backup_retention_period"):
        retention = None
    graph.backups.append(
        BackupConfig(
            resource=res,
            enabled=(retention or 0) > 0 if retention is not None else None,
            retention_days=retention if isinstance(retention, int) else None,
        )
    )


@adapter("aws_backup_plan")
def adapt_backup_plan(res: Resource, graph: ResourceGraph) -> None:
    # Retention lives in rule[].lifecycle[].delete_after; presence of a plan
    # rule is the declarative backup control.
    rules = res.get("rule") or []
    retention = None
    for rule in rules if isinstance(rules, list) else [rules]:
        lifecycle = rule.get("lifecycle") if isinstance(rule, dict) else None
        block = lifecycle[0] if isinstance(lifecycle, list) and lifecycle else lifecycle
        if isinstance(block, dict) and block.get("delete_after"):
            retention = int(block["delete_after"])
            break
    graph.backups.append(BackupConfig(resource=res, enabled=True, retention_days=retention))


@adapter("aws_dynamodb_table")
def adapt_dynamodb_pitr(res: Resource, graph: ResourceGraph) -> None:
    pitr = res.get("point_in_time_recovery")
    enabled = None
    if isinstance(pitr, list) and pitr:
        enabled = bool(pitr[0].get("enabled"))
    elif isinstance(pitr, dict):
        enabled = bool(pitr.get("enabled"))
    graph.backups.append(BackupConfig(resource=res, enabled=enabled))
