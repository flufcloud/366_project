# Issue Log

Repository tracker: [GitHub Issues](https://github.com/flufcloud/366_project/issues)  
Project board: [GitHub Project](https://github.com/users/flufcloud/projects/2/views/1)  

This is the single Markdown issue log for the final release. It lists the live GitHub issue first, then local backlog entries that should be copied into GitHub when issue-write access is available.

| # | Status | Title | Type | Tracker |
|---:|--------|-------|------|---------|
| 1 | Open | Address Google Model Rate Limiting Issues | Reliability / performance | [GitHub issue #1](https://github.com/flufcloud/366_project/issues/1) |
| 2 | Logged locally | Add adversarial prompt-injection evaluation suite | Security hardening technical debt | Local backlog entry |
| 3 | Logged locally | Replace regex-only secret detection with a stronger scanner | Privacy/security technical debt | Local backlog entry |
| 4 | Logged locally | Add supply-chain provenance checks beyond pip-audit | Supply-chain technical debt | Local backlog entry |

## Issue 1: Address Google Model Rate Limiting Issues

Google-family model calls can hit rate limits during long `--llm-report` runs or live demos.

Current mitigation:

- retry handling for rate limits and server errors;
- configurable retry counts and delays;
- `--list-google-models`, `--set-google-model`, and environment overrides;
- progress and warning output during LLM runs.

Remaining work:

- document recommended free-tier limits;
- evaluate provider fallback behavior;
- consider a stricter demo mode for predictable presentations.

## Issue 2: Add Adversarial Prompt-Injection Evaluation Suite

Prompt injection through GitHub issue/PR content remains an accepted residual risk. Current delimiter and schema-validation controls reduce risk but do not prove model behavior against adversarial payloads.

Acceptance criteria:

- add mocked tests for at least 5 malicious issue/PR payloads;
- add one manual/demo checklist for live-model evaluation;
- update the security report with test evidence and remaining limitations.

## Issue 3: Replace Regex-Only Secret Detection With a Stronger Scanner

Regex redaction catches common key formats, but it may miss novel provider tokens, high-entropy secrets, or organization-specific credentials.

Acceptance criteria:

- compare local scanner integration with custom entropy heuristics;
- add tests for novel key-like strings and false-positive control;
- avoid logging raw detected values.

## Issue 4: Add Supply-Chain Provenance Checks Beyond pip-audit

Current CI checks known CVEs and static source patterns, but it does not generate an SBOM or enforce provenance policy for dependency changes.

Acceptance criteria:

- generate an SBOM artifact in CI or document why it is out of scope;
- add a PR checklist item for `pyproject.toml` and `uv.lock` changes;
- document package-source/provenance review steps.
