"""KSI registry — the data-driven disposition map for all 46 KSIs (SPEC §7).

Each KSI is a self-describing entry: disposition (with per-class overrides),
the check classes it uses, intended provider coverage, and a default severity.
Evaluators register themselves against a KSI id via :func:`register_evaluator`,
so adding a KSI is a registry entry + an evaluator module + fixtures — no edits
to the orchestrator (SPEC §1.8).

The disposition totals are asserted by the completeness test (SPEC §15.1):

    base (Class A/B view): 22 enforce + 12 advisory + 12 manual = 46
    Class C:               25 enforce +  9 advisory + 12 manual = 46
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .model import AuthClass, CheckClass, Disposition, Provider, Severity

if TYPE_CHECKING:
    from .engine.context import EvalContext
    from .model import Finding

# An evaluator takes the evaluation context and returns its findings.
Evaluator = Callable[["EvalContext"], "list[Finding]"]

ALL_PROVIDERS = (Provider.AWS, Provider.AZURE, Provider.GCP)
NO_PROVIDERS: tuple[Provider, ...] = ()

CC = CheckClass
CONFIG = CheckClass.CONFIGURED_CORRECTLY
CONTROL = CheckClass.CONTROL_DECLARED
ANTI = CheckClass.ANTI_PATTERN_ABSENT


@dataclass(frozen=True)
class RegistryEntry:
    """Disposition + metadata for one KSI."""

    ksi_id: str
    disposition: Disposition
    check_classes: tuple[CheckClass, ...] = ()
    providers: tuple[Provider, ...] = ()
    default_severity: Severity = Severity.MEDIUM
    # Per-class disposition overrides (e.g. {AuthClass.C: ENFORCE}).
    class_overrides: dict[AuthClass, Disposition] = field(default_factory=dict)
    notes: str = ""

    def disposition_for(self, cls: AuthClass) -> Disposition:
        return self.class_overrides.get(cls, self.disposition)


def _e(
    ksi_id: str,
    disp: Disposition,
    classes: tuple[CheckClass, ...] = (),
    providers: tuple[Provider, ...] = ALL_PROVIDERS,
    severity: Severity = Severity.MEDIUM,
    overrides: dict[AuthClass, Disposition] | None = None,
    notes: str = "",
) -> RegistryEntry:
    if disp is Disposition.MANUAL:
        providers = NO_PROVIDERS
    return RegistryEntry(
        ksi_id=ksi_id,
        disposition=disp,
        check_classes=classes,
        providers=providers,
        default_severity=severity,
        class_overrides=overrides or {},
        notes=notes,
    )


# --- The 46. Dispositions transcribed from SPEC §7 (the build target). -------
_C_ENFORCE = {AuthClass.C: Disposition.ENFORCE}

_ENTRIES: tuple[RegistryEntry, ...] = (
    # CNA — Cloud Native Architecture (8)
    _e(
        "KSI-CNA-RNT",
        Disposition.ENFORCE,
        (CONFIG, ANTI),
        severity=Severity.HIGH,
        notes="ingress/egress restriction",
    ),
    _e(
        "KSI-CNA-MAT",
        Disposition.ENFORCE,
        (CONFIG, ANTI),
        severity=Severity.HIGH,
        notes="attack surface, no public mgmt ports",
    ),
    _e("KSI-CNA-ULN", Disposition.ENFORCE, (CONFIG,), notes="VPC/subnet/segmentation"),
    _e("KSI-CNA-DFP", Disposition.ENFORCE, (CONFIG,), notes="least functionality"),
    _e("KSI-CNA-IBP", Disposition.ENFORCE, (CONFIG,), notes="vs CIS/best-practice pack"),
    _e(
        "KSI-CNA-EIS",
        Disposition.ADVISORY,
        (CONTROL,),
        overrides=_C_ENFORCE,
        notes="Config/SSM/Policy enforcement; O on B, R on C",
    ),
    _e("KSI-CNA-OFA", Disposition.ENFORCE, (CONFIG,), notes="multi-AZ/redundancy"),
    _e("KSI-CNA-RVP", Disposition.ADVISORY, (CONTROL,), notes="WAF/Shield/Armor present"),
    # MLA — Monitoring, Logging, Auditing (5)
    _e("KSI-MLA-EVC", Disposition.ENFORCE, (CONTROL,), notes="config recorder / this gate"),
    _e(
        "KSI-MLA-LET",
        Disposition.ENFORCE,
        (CONFIG,),
        severity=Severity.HIGH,
        notes="audit/diag log config",
    ),
    _e(
        "KSI-MLA-OSM",
        Disposition.ENFORCE,
        (CONFIG,),
        severity=Severity.HIGH,
        notes="central + tamper-resistant logging",
    ),
    _e(
        "KSI-MLA-ALA",
        Disposition.ADVISORY,
        (CONFIG,),
        overrides=_C_ENFORCE,
        notes="IAM on logs; O on B, R on C",
    ),
    _e("KSI-MLA-RVL", Disposition.ADVISORY, (CONFIG,), notes="logging enabled (review=manual)"),
    # SVC — Service Configuration (8)
    _e(
        "KSI-SVC-SIN",
        Disposition.ENFORCE,
        (CONFIG,),
        severity=Severity.HIGH,
        notes="encryption at rest + in transit",
    ),
    _e(
        "KSI-SVC-ASM",
        Disposition.ENFORCE,
        (CONTROL, ANTI),
        severity=Severity.HIGH,
        notes="secret store + rotation; no hardcoded secrets",
    ),
    _e("KSI-SVC-ACM", Disposition.ENFORCE, (CONTROL,), notes="IaC present + drift rule"),
    _e("KSI-SVC-VRI", Disposition.ADVISORY, (CONTROL,), notes="signing/integrity config"),
    _e(
        "KSI-SVC-VCM",
        Disposition.ADVISORY,
        (CONFIG,),
        overrides=_C_ENFORCE,
        notes="TLS/mTLS; O on B, R on C",
    ),
    _e("KSI-SVC-EIS", Disposition.MANUAL, notes="continuous improvement"),
    _e("KSI-SVC-PRR", Disposition.MANUAL, notes="residual-risk review (O on B, R on C)"),
    _e("KSI-SVC-RUD", Disposition.MANUAL, notes="data removal ops (O on B, R on C)"),
    # IAM — Identity & Access Management (6)
    _e(
        "KSI-IAM-ELP",
        Disposition.ENFORCE,
        (ANTI,),
        severity=Severity.HIGH,
        notes="no wildcard/admin policies",
    ),
    _e("KSI-IAM-JIT", Disposition.ENFORCE, (ANTI, CONTROL), notes="no standing admin; boundaries"),
    _e(
        "KSI-IAM-AAM",
        Disposition.ENFORCE,
        (ANTI, CONTROL),
        severity=Severity.HIGH,
        notes="IAM-as-code; no root keys (SCP)",
    ),
    _e("KSI-IAM-APM", Disposition.ENFORCE, (CONFIG,), notes="password policy; MFA-required policy"),
    _e(
        "KSI-IAM-SNU",
        Disposition.ENFORCE,
        (ANTI, CONTROL),
        severity=Severity.HIGH,
        notes="no static keys; rotation Config rule",
    ),
    _e(
        "KSI-IAM-SUS",
        Disposition.ADVISORY,
        (CONTROL,),
        notes="GuardDuty/Defender (response=manual)",
    ),
    # INR — Incident Response (3)
    _e("KSI-INR-AAR", Disposition.ADVISORY, (CONTROL,), notes="detection infra present"),
    _e("KSI-INR-RIR", Disposition.ADVISORY, (CONTROL,), notes="SecurityHub/Defender present"),
    _e("KSI-INR-RPI", Disposition.ADVISORY, (CONTROL,), notes="Inspector/findings infra present"),
    # PIY — Policy & Inventory (5)
    _e("KSI-PIY-GIV", Disposition.ENFORCE, (CONTROL,), notes="inventory infra (Config/asset)"),
    _e("KSI-PIY-RES", Disposition.MANUAL, notes="exec support"),
    _e("KSI-PIY-RIS", Disposition.MANUAL, notes="investment review"),
    _e("KSI-PIY-RSD", Disposition.MANUAL, notes="SDLC review"),
    _e("KSI-PIY-RVD", Disposition.MANUAL, notes="VDP review"),
    # CMT — Change Management (4)
    _e("KSI-CMT-LMC", Disposition.ENFORCE, (CONFIG,), notes="change-logging infra"),
    _e("KSI-CMT-VTD", Disposition.ADVISORY, (CONTROL,), notes="patch/validation infra"),
    _e("KSI-CMT-RMV", Disposition.MANUAL, notes="redeploy-vs-modify (process)"),
    _e("KSI-CMT-RVP", Disposition.MANUAL, notes="change-procedure review"),
    # RPL — Recovery Planning (4)
    _e("KSI-RPL-ABO", Disposition.ENFORCE, (CONFIG,), notes="backup config + retention"),
    _e("KSI-RPL-ARP", Disposition.ENFORCE, (CONTROL,), notes="backup plans / DR infra"),
    _e("KSI-RPL-RRO", Disposition.MANUAL, notes="RTO/RPO definitions"),
    _e("KSI-RPL-TRC", Disposition.MANUAL, notes="recovery testing"),
    # SCR — Supply Chain Risk (2)
    _e("KSI-SCR-MIT", Disposition.ENFORCE, (CONFIG,), notes="registry scanning/immutability"),
    _e("KSI-SCR-MON", Disposition.ADVISORY, (CONTROL,), notes="dependency/vuln scanning infra"),
    # CED — Cybersecurity Education (1)
    _e("KSI-CED-RAT", Disposition.MANUAL, notes="training"),
)

REGISTRY: dict[str, RegistryEntry] = {e.ksi_id: e for e in _ENTRIES}

# --- Evaluator registration -------------------------------------------------
_EVALUATORS: dict[str, Evaluator] = {}


def register_evaluator(ksi_id: str) -> Callable[[Evaluator], Evaluator]:
    """Decorator: register an evaluator function for ``ksi_id``."""

    def deco(fn: Evaluator) -> Evaluator:
        if ksi_id not in REGISTRY:
            raise KeyError(f"Cannot register evaluator for unknown KSI {ksi_id}")
        _EVALUATORS[ksi_id] = fn
        return fn

    return deco


def get_evaluator(ksi_id: str) -> Evaluator | None:
    return _EVALUATORS.get(ksi_id)


def has_evaluator(ksi_id: str) -> bool:
    return ksi_id in _EVALUATORS


def all_entries() -> tuple[RegistryEntry, ...]:
    return _ENTRIES


def get_entry(ksi_id: str) -> RegistryEntry:
    return REGISTRY[ksi_id.strip().upper()]


def disposition_counts(cls: AuthClass) -> dict[Disposition, int]:
    """Count KSIs by effective disposition for ``cls`` (SPEC §15.1)."""
    counts = {Disposition.ENFORCE: 0, Disposition.ADVISORY: 0, Disposition.MANUAL: 0}
    for e in _ENTRIES:
        counts[e.disposition_for(cls)] += 1
    return counts
