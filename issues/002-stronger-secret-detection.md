# M5: Replace regex-only secret detection with a stronger scanner

## Classification

Acceptable residual risk; privacy/security technical debt.

## Context

The current redactor catches common GitHub, Anthropic, Google, AWS, Slack, Stripe, and private-key patterns. Regex-only detection can miss novel provider keys, high-entropy tokens, and organization-specific secrets.

## Acceptance criteria

- Compare a local secret-scanning library/tool with custom entropy heuristics.
- Add tests for novel key-like strings and false-positive control.
- Keep scan output deterministic and avoid logging raw detected values.

## Milestone 5 rationale

Current detection is useful and tested, but this remains a reasonable roadmap item for deeper security assurance after the final course release.
