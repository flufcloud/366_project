# Security policy

## Reporting a vulnerability

Please report security issues privately (do not open a public GitHub issue) so they can be addressed before wider disclosure. Contact the repository maintainer via the course or project channel described in the course syllabus, or use GitHub **Security Advisories** if enabled for this repository.

Include: affected version or commit, reproduction steps, and impact assessment when possible.

## Data handling guarantees

This tool is designed so that **credentials are never printed to stdout** and are **not embedded in LLM prompts** by design: before each LLM call the tool runs a **pre-send filter** (pattern scan aligned with `--scan` redaction). If credential-shaped data is detected in the fully assembled prompt, the request is **aborted** (no network send). GitHub and LLM credentials are stored under the OS user config directory (override with `SECANALYZER_CONFIG_DIR` for testing only).

### What may be sent to third-party LLM providers (`--issues` and future LLM-backed `--scan`)

- **GitHub issue and PR metadata** you explicitly select: title, body, and (for PRs) truncated per-file patch summaries from the GitHub API — wrapped in delimiter markers and paired with a fixed system instruction that treats that region as untrusted data.
- **Repository contents** (when LLM-backed scan is enabled) that pass extension allowlisting and path confinement, after **automated redaction** of common secret patterns. Redaction is best-effort and **not a substitute** for removing real secrets from your tree before analysis.

### What must not be sent

- **GitHub personal access tokens** and **LLM API keys** — used only in HTTP headers / query parameters to the respective APIs, not placed inside LLM prompt bodies. The pre-send filter aborts if credential-shaped strings appear anywhere in the outbound prompt text.

### Local filesystem

- **`--scan`** resolves the target path and only reads files **under that root** (with `followlinks=False` during directory walk). Symlink tricks that point outside the repository should not expand into reads of arbitrary paths.

### CI and automated checks

The repository ships a GitHub Actions workflow ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) that, on each push and pull request to `main` or `master`, runs **pytest**, **bandit** on `src/secanalyzer`, and **pip-audit** against the **frozen** `uv.lock` environment. This does not replace manual review of dependency upgrades: treat lockfile changes as security-relevant.

### Supply chain

- Dependencies are managed with **uv** and a **lockfile** in this repository. Prefer `uv sync --frozen` in CI and before releases.

## Limitations

- **Prompt injection** from hostile PR/issue content is an industry-wide open problem; mitigations (delimiter wrapping, schema validation) reduce risk but cannot eliminate it. Use the tool only on repositories you trust for write access, and review model output critically.
- **Secret redaction** uses heuristics; novel secret formats may slip through. Treat any LLM-boundary crossing as potentially sensitive.
