# Issue Log

Repository tracker: [GitHub Issues](https://github.com/flufcloud/366_project/issues)  
Project board: [GitHub Project](https://github.com/users/flufcloud/projects/2/views/1)
Local copy-paste issue drafts: [`issues/`](../../issues/)

This log documents outstanding bugs, acceptable risks, and technical debt for the Milestone 5 final release. Public vulnerability details should still follow the private reporting process in [SECURITY.md](../guides/SECURITY.md).

## Remote tracker status

| ID | Status | Title | Classification | Link |
|----|--------|-------|----------------|------|
| #1 | Open | Address Google Model Rate Limiting Issues | Reliability / performance | [GitHub issue #1](https://github.com/flufcloud/366_project/issues/1) |

Remote issue creation for the additional Milestone 5 entries was attempted on 2026-05-30 and retried on 2026-05-31. The installed GitHub connector can read repository state but returned `403 Resource not accessible by integration` for issue creation. The local `gh` CLI is installed but is not logged in, Git Credential Manager has no stored GitHub HTTPS credential, and no local `secanalyzer` GitHub token file is configured on this machine. Copy-paste-ready issue drafts are stored in [`issues/`](../../issues/).

## Outstanding issues to create

### M5: Add adversarial prompt-injection evaluation suite

Draft file: [`issues/001-adversarial-prompt-injection-evaluation-suite.md`](../../issues/001-adversarial-prompt-injection-evaluation-suite.md)

**Classification:** Acceptable residual risk; security hardening technical debt.

**Context:** M3 identifies prompt injection through issue/PR content as a primary risk. Current controls use delimiter-wrapped untrusted data, bounded prompts, and schema validation. These reduce risk but do not prove model behavior against adversarial payloads.

**Acceptance criteria:**

- Add mocked tests for at least 5 malicious issue/PR payloads.
- Add one manual/demo checklist for live-model evaluation.
- Update the security report with test evidence and remaining limitations.

### M5: Replace regex-only secret detection with a stronger scanner

Draft file: [`issues/002-stronger-secret-detection.md`](../../issues/002-stronger-secret-detection.md)

**Classification:** Acceptable residual risk; privacy/security technical debt.

**Context:** The current redactor catches common GitHub, Anthropic, Google, AWS, Slack, Stripe, and private-key patterns. Regex-only detection can miss novel provider keys, high-entropy tokens, and organization-specific secrets.

**Acceptance criteria:**

- Compare a local secret-scanning library/tool with custom entropy heuristics.
- Add tests for novel key-like strings and false-positive control.
- Keep scan output deterministic and avoid logging raw detected values.

### M5: Add supply-chain provenance checks beyond pip-audit

Draft file: [`issues/003-supply-chain-provenance-checks.md`](../../issues/003-supply-chain-provenance-checks.md)

**Classification:** Acceptable residual risk; supply-chain technical debt.

**Context:** CI uses `uv sync --frozen`, pytest, Bandit, and `pip-audit`. This catches known CVEs and enforces the lockfile, but it does not provide SBOM generation, package provenance review, or lockfile change policy enforcement.

**Acceptance criteria:**

- Generate an SBOM artifact in CI or document why it is out of scope.
- Add a PR checklist item for `pyproject.toml` and `uv.lock` changes.
- Document package-source/provenance review steps in the deployment guide.
