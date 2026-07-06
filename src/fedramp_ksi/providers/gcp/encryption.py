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
    key: object
    if isinstance(ek, list) and ek:
        key = ek[0].get("kms_key_name") or ek[0].get("kms_key_self_link")
    elif isinstance(ek, dict):
        key = ek.get("kms_key_name") or ek.get("kms_key_self_link")
    else:
        key = res.get("kms_key_name")
    return str(key) if key else None


@adapter("google_compute_disk", "google_storage_bucket", "google_sql_database_instance")
def adapt_gcp_encryption(res: Resource, graph: ResourceGraph) -> None:
    graph.encryption_settings.append(
        EncryptionSetting(resource=res, at_rest_enabled=True, kms_key=_cmek(res))
    )
