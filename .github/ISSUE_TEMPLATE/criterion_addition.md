---
name: New evaluation criterion
about: Propose a new pass/fail check for KSI-MLA-EVC or KSI-CNA-RNT
title: "[criterion] "
labels: enhancement, criterion
assignees: ''
---

## Target indicator

<!-- KSI-MLA-EVC or KSI-CNA-RNT -->

## Proposed criterion

<!-- e.g., "Block AWS security groups that allow 0.0.0.0/0 on port 22" -->

## Why this satisfies the indicator

<!-- Link the criterion to the indicator's statement and reference. -->

## How would the action evaluate it?

<!-- e.g., "Parse all aws_security_group resources from the inventory; for each, check ingress rules for cidr_blocks containing 0.0.0.0/0 and from_port/to_port covering 22." -->

## Sample PASS Terraform

```hcl
resource "aws_security_group" "..." {
  # ...
}
```

## Sample FAIL Terraform

```hcl
resource "aws_security_group" "..." {
  # ...
}
```

## Anything else

<!-- Caveats, edge cases, related criteria. -->
