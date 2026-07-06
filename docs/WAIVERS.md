# Waivers & Baseline

Real systems carry exceptions. Handle them with **expiring waivers**, not code
edits or a weakened gate.

## Waivers

Create `.fedramp-ksi-waivers.yml` at your repo root (or point `waivers_file` at
another path):

```yaml
waivers:
  - ksi: KSI-CNA-RNT
    resource: aws_security_group.legacy_bastion   # exact address or a glob
    reason: "Bastion restricted via VPN; tracked in JIRA SEC-1421"
    approved_by: jane@corp.com
    expires: 2026-09-30          # REQUIRED
```

Behaviour:

- A **matching, unexpired** waiver downgrades a `FAIL` to a recorded, **suppressed**
  finding. It stays in the evidence manifest (`waivers_applied`) with the reason,
  approver, and expiry, and appears in SARIF as a `suppressions` entry — so
  auditors see it, but it no longer blocks the gate.
- An **expired** or **unmatched** waiver does nothing: the finding stays live and
  gate-blocking. Expiry re-activates a finding automatically.
- `resource` matches the Terraform **plan address**. Globs are supported, e.g.
  `module.*.aws_security_group.*`.
- Waiver expiry is evaluated against the run date (override with `KSI_TODAY` for
  reproducible runs).

## Baseline (legacy debt)

For brownfield adoption, snapshot existing failures so only **new** findings block:

```yaml
baseline:
  - "KSI-SVC-SIN|SVC-SIN/encryption-at-rest|aws_ebs_volume.legacy"
```

Point `baseline_file` at this file. Findings whose fingerprint
(`ksi|check|resource`) is in the baseline are suppressed; anything new is drift
and stays live. Generate the current snapshot from a run's findings with
`fedramp_ksi.waivers.build_baseline`.

## Which to use?

- **Waiver** — a specific, approved, time-bound exception for one resource.
- **Baseline** — a bulk snapshot of pre-existing debt while you burn it down.

Both keep the gate honest: nothing is silently ignored, everything is recorded.
