# Security Policy

Beamhall is a security boundary: it stands between an untrusted AI agent and real
infrastructure. We take vulnerabilities seriously and appreciate responsible
disclosure.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
discussions, or pull requests.**

Instead, use GitHub's private vulnerability reporting:

- Go to the repository's **Security** tab → **Report a vulnerability** (GitHub
  Private Vulnerability Reporting), or
- email **security@beamhall.com** with the details.

Please include:

- a description of the issue and the component affected (e.g. the MCP tool
  surface, the egress reconciler, the secret vault, the audit chain);
- the steps to reproduce, or a proof of concept;
- the impact you believe it has — in particular, whether it lets the agent or a
  workload cross a boundary it should not (read a secret, widen egress, escape its
  workspace, tamper with the audit log, or escalate on the host);
- any suggested remediation.

## What to expect

- We will acknowledge your report within **3 business days**.
- We will work with you to understand and validate the issue, and keep you updated
  on remediation progress.
- We will credit you in the release notes when the fix ships, unless you prefer to
  remain anonymous.

## Scope

The security model and its boundaries are documented in
[`docs/threat-model.md`](docs/threat-model.md). Findings that demonstrate a way
to:

- obtain a raw credential the agent is never meant to see,
- weaken or bypass the immutable hardening baseline,
- escape a workload's isolation tier (`runc` or `runsc`),
- defeat the default-deny egress model,
- forge or tamper with the audit chain undetected, or
- cross from one workspace into another,

are exactly the high-value reports we want.

The threat model also states the **known residual risks** plainly (e.g. a
compromised running workload can read its own injected secrets by design, and the
shared-kernel risk under `runc`). A report that restates a documented residual
risk is still welcome as a discussion, but is not considered a new vulnerability.

## Supported versions

Beamhall is pre-1.0 and under active development. Security fixes are applied to
the `main` branch; until a stable release line exists, please test against `main`.
