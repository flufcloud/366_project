# M5: Add supply-chain provenance checks beyond pip-audit

## Classification

Acceptable residual risk; supply-chain technical debt.

## Context

CI uses `uv sync --frozen`, pytest, Bandit, and `pip-audit`. This catches known CVEs and enforces the lockfile, but it does not provide SBOM generation, package provenance review, or lockfile change policy enforcement.

## Acceptance criteria

- Generate an SBOM artifact in CI or document why it is out of scope.
- Add a PR checklist item for `pyproject.toml` and `uv.lock` changes.
- Document package-source/provenance review steps in the deployment guide.

## Milestone 5 rationale

The current pipeline is sufficient for the final release baseline, while provenance and SBOM work is logged as formal future hardening.
