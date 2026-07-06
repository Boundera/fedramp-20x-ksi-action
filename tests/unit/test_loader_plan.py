"""SPEC §4 / §11 — plan-JSON ingestion resolves modules & unknown-after-apply."""

from __future__ import annotations

import pytest

from fedramp_ksi.loader import PlanLoadError, load_plan, load_plan_file
from fedramp_ksi.model import Provider

from .conftest import fixture


def test_loads_root_module_resources() -> None:
    resources = load_plan_file(fixture("aws", "cna-rnt", "compliant.json"))
    assert len(resources) == 1
    r = resources[0]
    assert r.address == "aws_security_group.web"
    assert r.type == "aws_security_group"
    assert r.provider is Provider.AWS


def test_resolves_nested_module_resources() -> None:
    # The violation lives two modules deep with a for_each key — raw HCL would
    # miss it; the resolved plan catches it (SPEC §11).
    resources = load_plan_file(fixture("aws", "cna-rnt", "module_nested_violation.json"))
    assert len(resources) == 1
    assert resources[0].address == 'module.network.module.sg["prod"].aws_security_group.db'
    assert resources[0].get("ingress")[0]["from_port"] == 3389


def test_destroy_only_resources_excluded() -> None:
    plan = {
        "format_version": "1.2",
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_s3_bucket.gone",
                        "type": "aws_s3_bucket",
                        "name": "gone",
                        "provider_name": "registry.terraform.io/hashicorp/aws",
                        "values": {},
                    },
                ]
            }
        },
        "resource_changes": [
            {
                "address": "aws_s3_bucket.gone",
                "change": {"actions": ["delete"], "after_unknown": {}},
            },
        ],
    }
    assert load_plan(plan) == []


def test_unknown_after_apply_recorded() -> None:
    plan = {
        "format_version": "1.2",
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_db_instance.db",
                        "type": "aws_db_instance",
                        "name": "db",
                        "provider_name": "registry.terraform.io/hashicorp/aws",
                        "values": {"storage_encrypted": True},
                    },
                ]
            }
        },
        "resource_changes": [
            {
                "address": "aws_db_instance.db",
                "change": {"actions": ["create"], "after_unknown": {"kms_key_id": True}},
            },
        ],
    }
    r = load_plan(plan)[0]
    assert r.is_unknown("kms_key_id")
    assert not r.is_unknown("storage_encrypted")


def test_empty_plan_is_not_an_error() -> None:
    assert load_plan({"format_version": "1.2", "planned_values": {}}) == []


def test_unsupported_provider_skipped() -> None:
    plan = {
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "address": "kubernetes_namespace.x",
                        "type": "kubernetes_namespace",
                        "name": "x",
                        "provider_name": "registry.terraform.io/hashicorp/kubernetes",
                        "values": {},
                    },
                ]
            }
        },
        "format_version": "1.2",
    }
    assert load_plan(plan) == []


def test_malformed_plan_raises() -> None:
    with pytest.raises(PlanLoadError):
        load_plan([])  # type: ignore[arg-type]


def test_state_json_values_key_supported() -> None:
    plan = {
        "format_version": "1.0",
        "values": {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_security_group.s",
                        "type": "aws_security_group",
                        "name": "s",
                        "provider_name": "registry.terraform.io/hashicorp/aws",
                        "values": {"ingress": []},
                    },
                ]
            }
        },
    }
    assert len(load_plan(plan)) == 1
