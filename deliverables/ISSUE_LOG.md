# Issue Log

Repository tracker: [GitHub Issues](https://github.com/flufcloud/366_project/issues)  
Project board: [GitHub Project](https://github.com/users/flufcloud/projects/2/views/1)

This issue log documents outstanding bugs, acceptable risks, and technical debt for the final release. It combines the current GitHub tracker state with local issue-ticket files under `issues/`.

## Current remote issue

| ID | Status | Title | Classification | Link |
|----|--------|-------|----------------|------|
| #1 | Open | Address Google Model Rate Limiting Issues | Reliability / performance | [GitHub issue #1](https://github.com/flufcloud/366_project/issues/1) |

## Local issue tickets

The GitHub integration available during final hardening could read repository state but returned `403 Resource not accessible by integration` when creating issues. The local `gh` CLI was not installed, and no local `secanalyzer` GitHub token was configured. To keep the final release auditable, the remaining accepted risks are recorded as local issue-ticket files.

| Local ID | Title | Classification | File |
|----------|-------|----------------|------|
| 001 | Add adversarial prompt-injection evaluation suite | Acceptable residual risk; security hardening technical debt | `issues/001-adversarial-prompt-injection-evaluation-suite.md` |
| 002 | Replace regex-only secret detection with a stronger scanner | Acceptable residual risk; privacy/security technical debt | `issues/002-stronger-secret-detection.md` |
| 003 | Add supply-chain provenance checks beyond pip-audit | Acceptable residual risk; supply-chain technical debt | `issues/003-supply-chain-provenance-checks.md` |

## Issue details

### #1 Address Google Model Rate Limiting Issues

**Classification:** Reliability / performance.

**Summary:** Google-family model calls can be rate limited, which affects long LLM-report runs and live demos.

**Current mitigation:**

- retry handling for rate limits and server errors;
- configurable retry counts and delays;
- `--list-google-models` for model availability;
- `--set-google-model` and environment overrides for model selection;
- warning and progress output during LLM runs.

**Remaining work:**

- evaluate provider fallback behavior;
- document recommended free-tier limits;
- consider batching or a stricter demo mode for live presentations.

### 001 Add adversarial prompt-injection evaluation suite

**Classification:** Acceptable residual risk; security hardening technical debt.

**Summary:** Prompt injection through issue/PR content remains a known limitation. Current controls reduce risk but do not prove model behavior against adversarial payloads.

**Current mitigation:**

- delimiter-wrapped untrusted GitHub text;
- explicit system instructions;
- output schema validation for structured flows;
- LLM output treated as advisory text, not executable code.

**Acceptance criteria:**

- add mocked tests for at least 5 malicious issue/PR payloads;
- add one manual/demo checklist for live-model evaluation;
- update the security report with test evidence and remaining limitations.

### 002 Replace regex-only secret detection with a stronger scanner

**Classification:** Acceptable residual risk; privacy/security technical debt.

**Summary:** Regex redaction catches common key formats but may miss novel provider tokens, high-entropy secrets, or organization-specific credentials.

**Current mitigation:**

- redaction for GitHub, Anthropic, Google, AWS, Slack, Stripe, and private-key patterns;
- pre-send LLM abort when credential-shaped patterns remain;
- warnings when scan redactions occur;
- no raw prompt logging.

**Acceptance criteria:**

- compare local scanner integration with custom entropy heuristics;
- add tests for novel key-like strings and false-positive control;
- avoid logging raw detected values.

### 003 Add supply-chain provenance checks beyond pip-audit

**Classification:** Acceptable residual risk; supply-chain technical debt.

**Summary:** Current CI checks known CVEs and static source patterns, but does not generate an SBOM or enforce provenance policy for dependency changes.

**Current mitigation:**

- `uv.lock` pins dependency resolution;
- CI uses `uv sync --frozen --all-groups`;
- CI runs pytest, Bandit, and `pip-audit`;
- documentation flags lockfile changes as security-sensitive.

**Acceptance criteria:**

- generate an SBOM artifact in CI or document why out of scope;
- add a PR checklist item for `pyproject.toml` and `uv.lock` changes;
- document package-source/provenance review steps.
