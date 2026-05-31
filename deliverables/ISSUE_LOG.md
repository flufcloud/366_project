# Issue Log

Repository tracker: [GitHub Issues](https://github.com/flufcloud/366_project/issues)  
Project board: [GitHub Project](https://github.com/users/flufcloud/projects/2/views/1)

This log lists outstanding bugs, acceptable risks, and technical debt for the final release. Issue 1 is the live GitHub issue. Issues 2-4 are local issue tickets because the available GitHub integration could read repository state but did not have permission to create new issues.

## Summary

| # | Status | Title | Type | Tracker |
|---:|--------|-------|------|---------|
| 1 | Open | Address Google Model Rate Limiting Issues | Reliability / performance | [GitHub issue #1](https://github.com/flufcloud/366_project/issues/1) |
| 2 | Logged locally | Add adversarial prompt-injection evaluation suite | Security hardening technical debt | `issues/001-adversarial-prompt-injection-evaluation-suite.md` |
| 3 | Logged locally | Replace regex-only secret detection with a stronger scanner | Privacy/security technical debt | `issues/002-stronger-secret-detection.md` |
| 4 | Logged locally | Add supply-chain provenance checks beyond pip-audit | Supply-chain technical debt | `issues/003-supply-chain-provenance-checks.md` |

---

## Issue 1: Address Google Model Rate Limiting Issues

**Status:** Open  
**Tracker:** [GitHub issue #1](https://github.com/flufcloud/366_project/issues/1)  
**Type:** Reliability / performance

**Problem:** Google-family model calls can hit rate limits. This affects long `--llm-report` runs and can make live demonstrations slower or less predictable.

**Current mitigation:**

- Retry handling for rate limits and server errors.
- Configurable retry counts and delays.
- `--list-google-models` to check model availability.
- `--set-google-model` and environment overrides for model selection.
- Progress and warning output during LLM runs.

**Remaining work:**

- Document recommended free-tier limits.
- Evaluate provider fallback behavior.
- Consider a stricter demo mode for predictable presentations.

---

## Issue 2: Add Adversarial Prompt-Injection Evaluation Suite

**Status:** Logged locally  
**Tracker:** `issues/001-adversarial-prompt-injection-evaluation-suite.md`  
**Type:** Acceptable residual risk; security hardening technical debt

**Problem:** Prompt injection through GitHub issue/PR content remains a known limitation. The current controls reduce risk, but they do not prove model behavior against adversarial payloads.

**Current mitigation:**

- GitHub text is wrapped in untrusted-data delimiters.
- System prompts tell the model to treat delimited text as inert data.
- Structured LLM outputs are schema-validated.
- LLM output is advisory and is never executed as code.

**Acceptance criteria:**

- Add mocked tests for at least 5 malicious issue/PR payloads.
- Add one manual/demo checklist for live-model evaluation.
- Update the security report with test evidence and remaining limitations.

---

## Issue 3: Replace Regex-Only Secret Detection With a Stronger Scanner

**Status:** Logged locally  
**Tracker:** `issues/002-stronger-secret-detection.md`  
**Type:** Acceptable residual risk; privacy/security technical debt

**Problem:** Regex redaction catches common key formats, but it may miss novel provider tokens, high-entropy secrets, or organization-specific credentials.

**Current mitigation:**

- Redaction for GitHub, Anthropic, Google, AWS, Slack, Stripe, and private-key patterns.
- Pre-send LLM abort when credential-shaped patterns remain.
- Warnings when scan redactions occur.
- No raw prompt logging.

**Acceptance criteria:**

- Compare local scanner integration with custom entropy heuristics.
- Add tests for novel key-like strings and false-positive control.
- Avoid logging raw detected values.

---

## Issue 4: Add Supply-Chain Provenance Checks Beyond pip-audit

**Status:** Logged locally  
**Tracker:** `issues/003-supply-chain-provenance-checks.md`  
**Type:** Acceptable residual risk; supply-chain technical debt

**Problem:** Current CI checks known CVEs and static source patterns, but it does not generate an SBOM or enforce provenance policy for dependency changes.

**Current mitigation:**

- `uv.lock` pins dependency resolution.
- CI uses `uv sync --frozen --all-groups`.
- CI runs pytest, Bandit, and `pip-audit`.
- Documentation flags lockfile changes as security-sensitive.

**Acceptance criteria:**

- Generate an SBOM artifact in CI or document why it is out of scope.
- Add a PR checklist item for `pyproject.toml` and `uv.lock` changes.
- Document package-source/provenance review steps.
