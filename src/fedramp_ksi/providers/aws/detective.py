"""AWS detective-control adapters → normalized DetectiveControl (SPEC §5).

Governing detective controls used by control_declared KSIs: AWS Config
(configuration recorder + rules), GuardDuty, Security Hub, Inspector.
"""

from __future__ import annotations

from ...model import DetectiveControl, Resource
from ...model.graph import ResourceGraph
from ..registry import adapter


@adapter("aws_config_configuration_recorder")
def adapt_config_recorder(res: Resource, graph: ResourceGraph) -> None:
    # A recorder is "on" unless recording is explicitly disabled. The companion
    # aws_config_configuration_recorder_status controls start/stop; presence of a
    # recorder resource is the declarative control.
    graph.detective_controls.append(
        DetectiveControl(
            resource=res,
            kind="config_recorder",
            enabled=True,
            parameters={"recording_group": res.get("recording_group")},
        )
    )


@adapter("aws_config_config_rule", "aws_config_organization_managed_rule")
def adapt_config_rule(res: Resource, graph: ResourceGraph) -> None:
    source = res.get("source") or {}
    identifier = ""
    if isinstance(source, list) and source:
        identifier = source[0].get("source_identifier", "")
    elif isinstance(source, dict):
        identifier = source.get("source_identifier", "")
    graph.detective_controls.append(
        DetectiveControl(
            resource=res,
            kind="config_rule",
            enabled=True,
            parameters={
                "rule_identifier": identifier or res.get("rule_identifier", ""),
                "input_parameters": res.get("input_parameters"),
            },
        )
    )


@adapter("aws_guardduty_detector")
def adapt_guardduty(res: Resource, graph: ResourceGraph) -> None:
    enable = res.get("enable")
    graph.detective_controls.append(
        DetectiveControl(
            resource=res,
            kind="guardduty",
            enabled=bool(enable) if enable is not None else True,
        )
    )


@adapter("aws_securityhub_account")
def adapt_securityhub(res: Resource, graph: ResourceGraph) -> None:
    graph.detective_controls.append(
        DetectiveControl(resource=res, kind="security_hub", enabled=True)
    )


@adapter("aws_inspector2_enabler")
def adapt_inspector(res: Resource, graph: ResourceGraph) -> None:
    graph.detective_controls.append(DetectiveControl(resource=res, kind="inspector", enabled=True))
