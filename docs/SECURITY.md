# Security policy

## Data handling and third-party services

`secanalyzer` may call **GitHub** (REST API) and **LLM vendors** (Anthropic Claude or Google Gemini) when you use those features. API keys and tokens are stored only under the user config directory and are sent only in HTTP headers or query parameters as required by each API—not embedded in prompts as instructions.

### What may be sent to an LLM

| Feature | Content |
|--------|---------|
| **`--issues`** | PR/issue metadata, titles, bodies, and truncated patch text you choose to include, wrapped in delimiter blocks. Output must match a fixed JSON schema before display. |
| **`--scan`** | Static inventory only (paths, counts, redacted metadata). |
| **`--llm-report`** | Per-file source (one file per LLM call), rolling compaction, final Markdown report (architecture + high attack-surface files). |

Heuristic **redaction** runs on file content used in reports and on the **entire outbound prompt** before send. If credential-shaped patterns remain after redaction, the tool **aborts** the LLM request.

### What must not be sent (design intent)

- API keys, GitHub tokens, or other secrets as literal prompt text (blocked by pre-send checks when patterns match).
- Arbitrary binary or non-allowlisted paths during `--scan` (extension allowlist and path confinement under the scan root).

### Residual risk

Regex-based redaction can **miss** novel secret formats. Vendor **retention and training policies** apply to any text you send. Run the tool only on repositories you are permitted to analyze, and review vendor terms for your organization.

## Supply chain

Dependencies are pinned in `uv.lock`. CI runs `uv sync --frozen`, `bandit`, and `pip-audit`. Treat lockfile changes as security-sensitive in code review.

## Operational logging

The CLI writes sanitized JSONL events to `operations.jsonl` in the user log directory by default. Events include command starts/completions, scan metrics, redaction hits, Bandit counts, GitHub/LLM request failures, and LLM retry pressure.

The logger redacts fields whose names imply secrets (`token`, `api_key`, `authorization`, `password`, `secret`, or `credential`) and truncates long strings. It is intended for local troubleshooting and demonstration evidence, not centralized telemetry. Configure it with:

| Variable | Purpose |
|----------|---------|
| `SECANALYZER_LOG_FILE` | Write logs to a specific file. |
| `SECANALYZER_LOG_LEVEL` | `DEBUG`, `INFO`, `WARNING`, or `ERROR`. |
| `SECANALYZER_LOG_DISABLE` | Set to `1`, `true`, or `yes` to disable file logging. |

Do not upload operational logs publicly until you have reviewed them for repository names, paths, issue titles, and other contextual data.
