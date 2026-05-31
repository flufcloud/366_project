# M5: Add adversarial prompt-injection evaluation suite

## Classification

Acceptable residual risk; security hardening technical debt.

## Context

M3 identifies prompt injection through issue/PR content as a primary risk. Current controls use delimiter-wrapped untrusted data, bounded prompts, and schema validation. These controls reduce risk, but they do not prove model behavior against adversarial payloads.

## Acceptance criteria

- Add mocked tests for at least 5 malicious issue/PR payloads.
- Add one manual/demo checklist for live-model evaluation.
- Update the security report with test evidence and remaining limitations.

## Milestone 5 rationale

This is documented as a non-critical residual risk for the final release. It should be defended during the presentation as future hardening work rather than a release blocker.
