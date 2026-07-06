"""GCP encryption adapters → normalized EncryptionSetting (SPEC §5).

GCP encrypts at rest by default; the IaC-provable signal is whether a
customer-managed encryption key (CMEK) is set where required. We model the
at-rest flag as True (Google-managed) and record the CMEK when present.
"""

from __future__ import annotations

from ...model import EncryptionSetting, Resource
from ...model.graph import ResourceGraph
from ..registry import adapter


def _cmek(res: Resource) -> str | None:
    ek = res.get("encryption") or res.get("disk_encryption_key")
    if isinstance(ek, list) and ek:
        return ek[0].get("kms_key_name") or ek[0].get("kms_key_self_link")
    if isinstance(ek, dict):
        return ek.get("kms_key_name") or ek.get("kms_key_self_link")
    return res.get("kms_key_name")


@adapter("google_compute_disk", "google_storage_bucket", "google_sql_database_instance")
def adapt_gcp_encryption(res: Resource, graph: ResourceGraph) -> None:
    graph.encryption_settings.append(
        EncryptionSetting(resource=res, at_rest_enabled=True, kms_key=_cmek(res))
    )
