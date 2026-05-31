# Security Policy

## Supported Versions

We provide security fixes only for the latest published release on the `main`
branch.

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✓         |
| < 0.1   | ✗         |

## Reporting a Vulnerability

If you discover a security vulnerability in this action (particularly in
`action/src/check_run.py` or any code path that touches GitHub API
credentials), please **do not** open a public issue.

Report it privately via one of:

- **Preferred:** [Private vulnerability reporting](https://github.com/Boundera/fedramp-20x-ksi-action/security/advisories/new)
- **Email:** `security@boundera.io` with subject `[fedramp-20x-ksi-action] Vulnerability report`

Include:

- A description of the issue and potential impact
- Steps to reproduce
- The version or commit hash affected
- Suggested remediation if you have one

## Response timeline

- **Acknowledgment:** within 2 business days
- **Initial assessment:** within 5 business days
- **Fix or mitigation plan:** within 30 days for high-severity issues; longer
  for low-severity
- **Coordinated disclosure:** we'll work with you on timing for public
  disclosure

## Scope

In scope:

- The action's Python code (`action/`, `shared/`)
- The bundled FRMR loader and Check Run posting modules
- CI/CD workflows in `.github/workflows/`
- Documentation that, if exploited, could mislead users into insecure
  configurations

Out of scope:

- Vulnerabilities in dependencies (report upstream; we'll bump versions on
  disclosure)
- The Boundera commercial product
- The FedRAMP program or FRMR specification itself
- The GitHub Actions runtime itself

## A note on tokens

This action uses the workflow's built-in `GITHUB_TOKEN`. The token never
leaves the runner. It is not logged, persisted, or transmitted to any
third-party endpoint. If you believe the action mishandles the token, please
report it.

## Recognition

We acknowledge security researchers in release notes (with permission). We
do not currently offer a bug bounty.
