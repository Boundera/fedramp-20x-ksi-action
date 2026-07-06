"""Provider adapters + graph helpers."""

from __future__ import annotations

from fedramp_ksi.loader import load_plan, provider_for_type
from fedramp_ksi.model import Provider, Resource, SourceRef
from fedramp_ksi.model.graph import ResourceGraph
from fedramp_ksi.providers import build_graph


def _plan(resources):
    return {
        "format_version": "1.2",
        "planned_values": {"root_module": {"resources": resources}},
    }


def _res(address, rtype, values, provider="aws"):
    return {
        "address": address,
        "type": rtype,
        "name": address.split(".")[-1],
        "provider_name": f"registry.terraform.io/hashicorp/{provider}",
        "values": values,
    }


# --- provider inference -----------------------------------------------------


def test_provider_for_type() -> None:
    assert provider_for_type("aws_s3_bucket") is Provider.AWS
    assert provider_for_type("azurerm_storage_account") is Provider.AZURE
    assert provider_for_type("google_storage_bucket") is Provider.GCP
    assert provider_for_type("kubernetes_namespace") is None


def test_provider_from_provider_name() -> None:
    assert provider_for_type("x", "registry.terraform.io/hashicorp/google-beta") is Provider.GCP


# --- graph helpers ----------------------------------------------------------


def test_graph_is_empty_and_extend() -> None:
    g = ResourceGraph()
    assert g.is_empty
    r = Resource(address="a", type="aws_s3_bucket", provider=Provider.AWS, source=SourceRef())
    other = ResourceGraph(resources=[r], providers_detected={"aws"})
    g.extend(other)
    assert not g.is_empty
    assert g.resources_of_type("aws_s3_bucket") == [r]
    assert "aws" in g.providers_detected


# --- AWS detective adapters -------------------------------------------------


def test_detective_adapters_populate_controls() -> None:
    resources = [
        _res("aws_config_configuration_recorder.r", "aws_config_configuration_recorder", {}),
        _res("aws_guardduty_detector.d", "aws_guardduty_detector", {"enable": True}),
        _res(
            "aws_config_config_rule.k",
            "aws_config_config_rule",
            {"source": [{"source_identifier": "ACCESS_KEYS_ROTATED"}]},
        ),
        _res("aws_securityhub_account.s", "aws_securityhub_account", {}),
        _res("aws_inspector2_enabler.i", "aws_inspector2_enabler", {}),
    ]
    g = build_graph(load_plan(_plan(resources)))
    kinds = {d.kind for d in g.detective_controls}
    assert kinds == {"config_recorder", "guardduty", "config_rule", "security_hub", "inspector"}
    rule = next(d for d in g.detective_controls if d.kind == "config_rule")
    assert rule.parameters["rule_identifier"] == "ACCESS_KEYS_ROTATED"


def test_guardduty_disabled_flag() -> None:
    g = build_graph(
        load_plan(
            _plan(
                [
                    _res("aws_guardduty_detector.d", "aws_guardduty_detector", {"enable": False}),
                ]
            )
        )
    )
    assert g.detective_controls[0].enabled is False


# --- AWS standalone network rule adapters -----------------------------------


def test_standalone_security_group_rule() -> None:
    g = build_graph(
        load_plan(
            _plan(
                [
                    _res(
                        "aws_security_group_rule.ssh",
                        "aws_security_group_rule",
                        {
                            "type": "ingress",
                            "from_port": 22,
                            "to_port": 22,
                            "protocol": "tcp",
                            "cidr_blocks": ["0.0.0.0/0"],
                        },
                    ),
                ]
            )
        )
    )
    assert len(g.network_rules) == 1
    assert g.network_rules[0].ingress[0].from_port == 22


def test_vpc_ingress_and_egress_rules() -> None:
    g = build_graph(
        load_plan(
            _plan(
                [
                    _res(
                        "aws_vpc_security_group_ingress_rule.i",
                        "aws_vpc_security_group_ingress_rule",
                        {
                            "ip_protocol": "tcp",
                            "from_port": 443,
                            "to_port": 443,
                            "cidr_ipv4": "0.0.0.0/0",
                        },
                    ),
                    _res(
                        "aws_vpc_security_group_egress_rule.e",
                        "aws_vpc_security_group_egress_rule",
                        {"ip_protocol": "-1", "cidr_ipv4": "0.0.0.0/0"},
                    ),
                ]
            )
        )
    )
    ingress = [r for r in g.network_rules if r.ingress]
    egress = [r for r in g.network_rules if r.egress]
    assert ingress and ingress[0].ingress[0].to_port == 443
    assert egress and egress[0].egress[0].cidrs == ("0.0.0.0/0",)


def test_provider_scope_filter() -> None:
    resources = [
        _res("aws_s3_bucket.a", "aws_s3_bucket", {}),
        _res("google_storage_bucket.b", "google_storage_bucket", {}, provider="google"),
    ]
    g = build_graph(load_plan(_plan(resources)), providers=(Provider.AWS,))
    assert {r.provider for r in g.resources} == {Provider.AWS}


# --- Azure / GCP encryption adapters ---------------------------------------


def test_azure_managed_disk_encryption() -> None:
    g = build_graph(
        load_plan(
            _plan(
                [
                    _res(
                        "azurerm_managed_disk.d",
                        "azurerm_managed_disk",
                        {"disk_encryption_set_id": "/des/1"},
                        provider="azurerm",
                    ),
                ]
            )
        )
    )
    assert g.encryption_settings[0].at_rest_enabled is True
    assert g.encryption_settings[0].kms_key == "/des/1"


def test_azure_managed_disk_explicitly_unencrypted() -> None:
    g = build_graph(
        load_plan(
            _plan(
                [
                    _res(
                        "azurerm_managed_disk.d",
                        "azurerm_managed_disk",
                        {"encryption_settings": [{"enabled": False}]},
                        provider="azurerm",
                    ),
                ]
            )
        )
    )
    assert g.encryption_settings[0].at_rest_enabled is False


def test_gcp_encryption_records_cmek() -> None:
    g = build_graph(
        load_plan(
            _plan(
                [
                    _res(
                        "google_compute_disk.d",
                        "google_compute_disk",
                        {"disk_encryption_key": [{"kms_key_self_link": "projects/p/keys/k"}]},
                        provider="google",
                    ),
                ]
            )
        )
    )
    assert g.encryption_settings[0].at_rest_enabled is True
    assert g.encryption_settings[0].kms_key == "projects/p/keys/k"
