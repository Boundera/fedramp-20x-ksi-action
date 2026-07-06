"""AWS encryption adapters → normalized EncryptionSetting (SPEC §5).

Maps data-bearing resources with an at-rest-encryption signal (EBS volumes, RDS
instances/clusters, S3 SSE configuration) into EncryptionSetting. Unknown-after-
apply encryption flags are surfaced via the resource's ``unknown_keys`` so the
evaluator can avoid a false PASS/FAIL.
"""

from __future__ import annotations

from ...model import EncryptionSetting, Resource
from ...model.graph import ResourceGraph
from ..registry import adapter


def _bool_or_none(res: Resource, key: str) -> bool | None:
    if res.is_unknown(key):
        return None
    val = res.get(key)
    return bool(val) if val is not None else None


@adapter("aws_ebs_volume")
def adapt_ebs_volume(res: Resource, graph: ResourceGraph) -> None:
    graph.encryption_settings.append(
        EncryptionSetting(
            resource=res,
            at_rest_enabled=_bool_or_none(res, "encrypted"),
            kms_key=res.get("kms_key_id"),
        )
    )


@adapter("aws_db_instance", "aws_rds_cluster", "aws_rds_global_cluster")
def adapt_rds(res: Resource, graph: ResourceGraph) -> None:
    graph.encryption_settings.append(
        EncryptionSetting(
            resource=res,
            at_rest_enabled=_bool_or_none(res, "storage_encrypted"),
            kms_key=res.get("kms_key_id"),
        )
    )


@adapter("aws_s3_bucket_server_side_encryption_configuration")
def adapt_s3_sse(res: Resource, graph: ResourceGraph) -> None:
    # Presence of an SSE configuration resource means the bucket enforces SSE.
    graph.encryption_settings.append(EncryptionSetting(resource=res, at_rest_enabled=True))


@adapter("aws_efs_file_system")
def adapt_efs(res: Resource, graph: ResourceGraph) -> None:
    graph.encryption_settings.append(
        EncryptionSetting(
            resource=res,
            at_rest_enabled=_bool_or_none(res, "encrypted"),
            kms_key=res.get("kms_key_id"),
        )
    )
