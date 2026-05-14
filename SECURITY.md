# Security policy

## Reporting a vulnerability

Please **do not** open a public GitHub issue for undisclosed security problems. For this course project, contact the maintainers privately (for example, your instructor or the repository owner) with enough detail to reproduce the issue. Include affected versions, steps to reproduce, and impact if known.

## Data handling and third-party services

`secanalyzer` may call **GitHub** (REST API) and **LLM vendors** (Anthropic Claude or Google Gemini) when you use those features. API keys and tokens are stored only under the user config directory and are sent only in HTTP headers or query parameters as required by each API—not embedded in prompts as instructions.

### What may be sent to an LLM

| Feature | Content |
|--------|---------|
| **`--issues`** | PR/issue metadata, titles, bodies, and truncated patch text you choose to include, wrapped in delimiter blocks. Output must match a fixed JSON schema before display. |
| **`--scan` (optional narrative)** | A **bounded** text block: scan root path, counts, extension histogram, up to a capped list of relative paths, and up to a few **short, redacted** code excerpts—**not** the full repository. The model is asked to return Markdown prose only (no JSON). |

Heuristic **redaction** runs on file content used in reports and on the **entire outbound prompt** before send. If credential-shaped patterns remain after redaction, the tool **aborts** the LLM request.

### What must not be sent (design intent)

- API keys, GitHub tokens, or other secrets as literal prompt text (blocked by pre-send checks when patterns match).
- Arbitrary binary or non-allowlisted paths during `--scan` (extension allowlist and path confinement under the scan root).

### Residual risk

Regex-based redaction can **miss** novel secret formats. Vendor **retention and training policies** apply to any text you send. Run the tool only on repositories you are permitted to analyze, and review vendor terms for your organization.

## Supply chain

Dependencies are pinned in `uv.lock`. CI runs `uv sync --frozen`, `bandit`, and `pip-audit`. Treat lockfile changes as security-sensitive in code review.
