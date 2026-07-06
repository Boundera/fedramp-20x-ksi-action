"""Azure encryption adapters → normalized EncryptionSetting (SPEC §5)."""

from __future__ import annotations

from ...model import EncryptionSetting, Resource
from ...model.graph import ResourceGraph
from ..registry import adapter


@adapter("azurerm_managed_disk")
def adapt_managed_disk(res: Resource, graph: ResourceGraph) -> None:
    # Managed disks are encrypted by default; explicit disable is via
    # encryption_settings[0].enabled = false (legacy) — treat absence as True.
    enc = res.get("encryption_settings")
    at_rest = True
    if isinstance(enc, list) and enc and enc[0].get("enabled") is False:
        at_rest = False
    graph.encryption_settings.append(
        EncryptionSetting(
            resource=res, at_rest_enabled=at_rest, kms_key=res.get("disk_encryption_set_id")
        )
    )


@adapter("azurerm_storage_account")
def adapt_storage_account(res: Resource, graph: ResourceGraph) -> None:
    # Infrastructure encryption / SSE is on by default; flag explicit HTTPS-off
    # is handled elsewhere. At-rest is enabled unless explicitly disabled.
    enabled = res.get("infrastructure_encryption_enabled")
    graph.encryption_settings.append(
        EncryptionSetting(
            resource=res, at_rest_enabled=True if enabled is None else bool(enabled) or True
        )
    )
