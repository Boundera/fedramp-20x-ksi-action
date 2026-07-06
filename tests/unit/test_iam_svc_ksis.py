"""Golden fixtures for IAM-ELP, IAM-SNU, SVC-SIN enforce KSIs."""

from __future__ import annotations

import pytest

from fedramp_ksi.engine import Engine
from fedramp_ksi.loader import load_plan, load_plan_file
from fedramp_ksi.model import AuthClass, Status
from fedramp_ksi.providers import build_graph

from .conftest import fixture


def _status(ksi_id, provider_dir, name):
    resources = load_plan_file(fixture("aws", provider_dir, name))
    er = Engine().evaluate(build_graph(resources), ksi_ids=[ksi_id], target_class=AuthClass.C)
    return er.results[0]


@pytest.mark.parametrize(
    "ksi_id,fixdir",
    [("KSI-IAM-ELP", "iam-elp"), ("KSI-IAM-SNU", "iam-snu"), ("KSI-SVC-SIN", "svc-sin")],
)
def test_compliant_passes(ksi_id, fixdir) -> None:
    assert _status(ksi_id, fixdir, "compliant.json").status == Status.PASS


@pytest.mark.parametrize(
    "ksi_id,fixdir",
    [("KSI-IAM-ELP", "iam-elp"), ("KSI-IAM-SNU", "iam-snu"), ("KSI-SVC-SIN", "svc-sin")],
)
def test_violating_fails(ksi_id, fixdir) -> None:
    assert _status(ksi_id, fixdir, "violating.json").status == Status.FAIL


def test_iam_elp_na_without_policies() -> None:
    plan = {"format_version": "1.2", "planned_values": {"root_module": {"resources": []}}}
    er = Engine().evaluate(
        build_graph(load_plan(plan)), ksi_ids=["KSI-IAM-ELP"], target_class=AuthClass.C
    )
    assert er.results[0].status == Status.NA


def test_svc_sin_unknown_encryption_is_not_false_pass() -> None:
    # storage_encrypted unknown-after-apply ⇒ that resource is skipped ⇒ N/A,
    # never a false PASS or FAIL.
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
                        "values": {},
                    },
                ]
            }
        },
        "resource_changes": [
            {
                "address": "aws_db_instance.db",
                "change": {"actions": ["create"], "after_unknown": {"storage_encrypted": True}},
            },
        ],
    }
    er = Engine().evaluate(
        build_graph(load_plan(plan)), ksi_ids=["KSI-SVC-SIN"], target_class=AuthClass.C
    )
    assert er.results[0].status == Status.NA


def test_iam_snu_wildcard_action_variant() -> None:
    # "*:*" action form is also admin wildcard.
    plan = {
        "format_version": "1.2",
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_iam_policy.a",
                        "type": "aws_iam_policy",
                        "name": "a",
                        "provider_name": "registry.terraform.io/hashicorp/aws",
                        "values": {
                            "policy": '{"Statement":[{"Effect":"Allow","Action":"*:*","Resource":"*"}]}'
                        },
                    },
                ]
            }
        },
    }
    er = Engine().evaluate(
        build_graph(load_plan(plan)), ksi_ids=["KSI-IAM-ELP"], target_class=AuthClass.C
    )
    assert er.results[0].status == Status.FAIL
